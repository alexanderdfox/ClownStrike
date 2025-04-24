import os
import time
import threading
import hashlib
import shutil
import requests
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara
from flask import Flask, render_template_string

# Configuration Constants
PHEROMONE_INTENSITY = 1.0
PHEROMONE_DECAY = 0.01
NUM_ANTS = 1000
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'  # Replace with your API key
YARA_RULES_PATH = 'malware_rules.yar'

# Flask UI setup
app = Flask(__name__)
flask_pheromone_map = defaultdict(float)

def update_flask_map(map_data):
	global flask_pheromone_map
	flask_pheromone_map = map_data

@app.route("/")
def index():
	sorted_map = dict(sorted(flask_pheromone_map.items(), key=lambda item: item[1]["pheromone"], reverse=True))
	html = '''
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Pheromone Map</title>
		<script src="https://cdn.tailwindcss.com"></script>
	</head>
	<body class="bg-gray-100 text-gray-800">
		<div class="max-w-6xl mx-auto p-8">
			<h1 class="text-4xl font-bold mb-6 text-center">🐜 Pheromone Activity Map</h1>
			<div class="overflow-x-auto bg-white shadow-lg rounded-lg">
				<table class="min-w-full table-auto">
					<thead>
						<tr class="bg-gray-200 text-gray-700 uppercase text-sm leading-normal">
							<th class="py-3 px-6 text-left">Pheromone Level</th>
							<th class="py-3 px-6 text-left">Last Touched</th>
							<th class="py-3 px-6 text-left">Last Modified</th>
							<th class="py-3 px-6 text-left">File</th>
						</tr>
					</thead>
					<tbody class="text-gray-600 text-sm font-light">
					{% for path, data in map.items() %}
						<tr class="border-b border-gray-200 hover:bg-gray-100">
							<td class="py-3 px-6">
								<div class="flex items-center">
									<div class="w-full bg-gray-200 rounded-full h-4">
										<div class="bg-green-500 h-4 rounded-full" style="width: {{ data.bar_width }}%;"></div>
									</div>
									<span class="ml-2">{{ "%.2f"|format(data.pheromone) }}</span>
								</div>
							</td>
							<td class="py-3 px-6">{{ data.last_touched }}</td>
							<td class="py-3 px-6">{{ data.mod_time }}</td>
							<td class="py-3 px-6 whitespace-nowrap">{{ path }}</td>
						</tr>
					{% endfor %}
					</tbody>
				</table>
			</div>
		</div>
	</body>
	</html>
	'''
	return render_template_string(html, map=sorted_map)

# Compile YARA rules
try:
	yara_rules = yara.compile(filepath=YARA_RULES_PATH)
except:
	yara_rules = None

# Pheromone Map
class PheromoneMap:
	def __init__(self):
		self.map = defaultdict(lambda: {
			"pheromone": 0.0,
			"last_touched": 0.0,
			"mod_time": 0.0
		})
		self.lock = threading.Lock()

	def add_pheromone(self, file_path, intensity):
		try:
			mod_time = os.path.getmtime(file_path)
		except Exception:
			mod_time = 0.0

		with self.lock:
			if self.map[file_path]["mod_time"] and self.map[file_path]["mod_time"] != mod_time:
				print(f"⚠️ ALERT: Modification time changed for {file_path}")
			self.map[file_path]["pheromone"] += intensity
			self.map[file_path]["last_touched"] = time.time()
			self.map[file_path]["mod_time"] = mod_time

	def decay(self):
		with self.lock:
			for file_path in list(self.map.keys()):
				self.map[file_path]["pheromone"] -= PHEROMONE_DECAY
				if self.map[file_path]["pheromone"] <= 0:
					del self.map[file_path]

	def get_map(self):
		with self.lock:
			return {
				path: {
					"pheromone": data["pheromone"],
					"bar_width": min(100, data["pheromone"] * 10),
					"last_touched": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data["last_touched"])),
					"mod_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data["mod_time"])) if data["mod_time"] else "N/A"
				}
				for path, data in self.map.items()
			}

# Ant Agent
class Ant(threading.Thread):
	def __init__(self, pheromone_map, id):
		super().__init__()
		self.pheromone_map = pheromone_map
		self.id = id
		self.daemon = True

	def leave_pheromone(self, file_path):
		print(f"Ant-{self.id} leaving pheromone at: {file_path}")
		self.pheromone_map.add_pheromone(file_path, PHEROMONE_INTENSITY)

	def run(self):
		while True:
			time.sleep(1)
			self.pheromone_map.decay()

# Threat Detection
def hash_file(file_path):
	try:
		with open(file_path, 'rb') as f:
			return hashlib.sha256(f.read()).hexdigest()
	except (PermissionError, FileNotFoundError, IsADirectoryError):
		print(f"⚠️ Skipped (no permission): {file_path}")
		return None

def check_virustotal(hash):
	url = f"https://www.virustotal.com/api/v3/files/{hash}"
	headers = {"x-apikey": VIRUSTOTAL_API_KEY}
	response = requests.get(url, headers=headers)
	if response.status_code == 200:
		data = response.json()
		return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
	return {}

def run_yara(file_path):
	if yara_rules:
		try:
			matches = yara_rules.match(filepath=file_path)
			return matches
		except Exception:
			return []
	return []

def quarantine(file_path):
	quarantine_dir = os.path.expanduser("~/quarantine")
	os.makedirs(quarantine_dir, exist_ok=True)
	try:
		shutil.move(file_path, os.path.join(quarantine_dir, os.path.basename(file_path)))
		print(f"🚧 File moved to quarantine: {file_path}")
	except Exception as e:
		print(f"⚠️ Failed to quarantine {file_path}: {e}")

# File Monitor (monitors all file types)
class FileMonitor(FileSystemEventHandler):
	def __init__(self, ants, pheromone_map):
		self.ants = ants
		self.pheromone_map = pheromone_map

	def handle_event(self, file_path):
		if not os.path.isfile(file_path):
			return

		hash_val = hash_file(file_path)
		if not hash_val:
			return

		virustotal_result = check_virustotal(hash_val)
		yara_matches = run_yara(file_path)

		if virustotal_result.get('malicious', 0) > 0 or yara_matches:
			print(f"⚠️ Threat detected: {file_path}")
			quarantine(file_path)

		for ant in self.ants:
			ant.leave_pheromone(file_path)

	def on_modified(self, event):
		if not event.is_directory:
			self.handle_event(event.src_path)

	def on_created(self, event):
		if not event.is_directory:
			self.handle_event(event.src_path)

# Main with Flask Thread
def start_flask():
	app.run(port=5000, debug=False, use_reloader=False)

def main():
	pheromone_map = PheromoneMap()
	ants = [Ant(pheromone_map, i) for i in range(NUM_ANTS)]
	for ant in ants:
		ant.start()

	observer = Observer()
	event_handler = FileMonitor(ants, pheromone_map)
	path = os.path.expanduser("/")  # Monitor root or customize it
	observer.schedule(event_handler, path, recursive=True)
	observer.start()

	flask_thread = threading.Thread(target=start_flask)
	flask_thread.daemon = True
	flask_thread.start()

	try:
		while True:
			time.sleep(1)
			map_data = pheromone_map.get_map()
			update_flask_map(map_data)
	except KeyboardInterrupt:
		observer.stop()

	observer.join()

if __name__ == '__main__':
	main()
