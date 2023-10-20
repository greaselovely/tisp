import requests
import urllib3
import xmltodict
import cursor
import os
import pathlib
from datetime import datetime
import argparse
import getpass
import sys
import urllib
import dns.resolver
import xml.etree.ElementTree as ET
import csv
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

status_dict = {'PEND': 'Pending', 'ACT': 'Running', 'FIN': 'Finished'}


def clear() -> None:
	os.system("cls" if os.name == "nt" else "clear")

def argue_with_me() -> None:
	global fw_ip, fw_username, fw_password, fw_api_key
	"""
	This is called if there are arguments passed to the script via cli
	"""
	parser = argparse.ArgumentParser(description='Performs a request to download traffic and threat logs, monitors the job, and then downloads the data')
	parser.add_argument('-i', '--ip_addr', type=str, help='IP Address of the firewall', required=True)
	parser.add_argument('-u', '--user', type=str, help='Username on the firewall', required=False)
	parser.add_argument('-p', '--password', type=str, help='Password on the firewall', required=False)
	parser.add_argument('-a', '--api_key', type=str, help='API Key from the firewall', required=False)
	args = parser.parse_args()
	fw_ip = args.ip_addr
	fw_api_key = args.api_key
	fw_username = args.user
	fw_password = args.password
	if fw_api_key is not None and len(fw_api_key) > 100:
		return
	elif fw_username and fw_password:
		return
	elif fw_username and not fw_password:
		fw_password = getpass.getpass("[?]\tEnter your password: ")
	elif fw_password and not fw_username:
		fw_username = input("[?]\tEnter your username: ")
	else:
		fw_username = input("[?]\tEnter your username: ")
		fw_password = getpass.getpass("[?]\tEnter your password: ")
	return

def create_session() -> None:
	"""
	making variables global
	creating a session to the firewall
	adding API key to the header
	we use the header for the API key instead of passing in URL
	"""
	global session, response, headers, fw_api_key
	session = requests.session()
	if fw_api_key is None:
		payload = {"type": "keygen", "user": fw_username, "password": fw_password}
		response = session.post(api_url, verify=False, data=payload)
		key_dict = xmltodict.parse(response.text)
		fw_api_key = key_dict.get('response').get('result').get('key')
		headers = {"X-PAN-KEY": fw_api_key}
	else:
		headers = {"X-PAN-KEY": fw_api_key}
		payload = {"type": "op", "cmd": "<show><system><info></info></system></show>" }
		response = session.get(api_url, headers=headers, data=payload, verify=False)

	if response.status_code == 200:
		return
	else:
		broken = xmltodict.parse(response.text)
		broken = broken.get('response').get('result').get('msg', 'b0rk3n')
		print(f"\n\n[!]\tAuthentication failed with status code {response.status_code} - {broken}\n\n")
		sys.exit()

def get_hostname_and_filename() -> None:
	"""
	Just using this to grab hostname which will 
	be used to name the file with the date.
	If we can't parse the hostname, we give it a 
	generic name using the var below
	"""
	tmp_host_name = 'temp_frwl_name'
	global threat_full_path_xml, traffic_full_path_xml, threat_full_path_csv, traffic_full_path_csv
	today = datetime.now().strftime('%m%d%Y')
	payload = {"type": "op", "cmd": "<show><system><info></info></system></show>"}
	response = session.post(api_url, headers=headers, data=payload, verify=False)
	ssi_dict = xmltodict.parse(response.text)
	hostname = ssi_dict.get('response').get('result').get('system').get('hostname', tmp_host_name)
	
	local_path = pathlib.Path(__file__).parent
	threat_file_name_xml = f"{hostname}.{today}.threat.xml"
	threat_file_name_csv = f"{hostname}.{today}.threat.csv"
	traffic_file_name_xml= f"{hostname}.{today}.traffic.xml"
	traffic_file_name_csv = f"{hostname}.{today}.traffic.csv"
	threat_full_path_xml = pathlib.Path.joinpath(local_path, threat_file_name_xml)
	traffic_full_path_xml = pathlib.Path.joinpath(local_path, traffic_file_name_xml)
	threat_full_path_csv = pathlib.Path.joinpath(local_path, threat_file_name_csv)
	traffic_full_path_csv = pathlib.Path.joinpath(local_path, traffic_file_name_csv)

def check_sinkhole_ip() -> str:
	"""
	resolve the sinkhole address for PANW and 
	return the variable to be used in the traffic filter
	"""
	domain = "sinkhole.paloaltonetworks.com"
	result = dns.resolver.resolve(domain, 'A')
	ip = result[0].address
	return ip

def start_threat_logs() -> str:
	"""
	Start the threat log processing using the query filter
	"""
	filter = "(subtype eq spyware) and ((severity eq medium) or (severity eq high) or (severity eq critical))"
	query_params = {"type": "log", "log-type": "threat", "query": filter}	
	response = session.get(api_url, headers=headers, params=query_params, verify=False)
	if response.status_code == 200:
		r = xmltodict.parse(response.text)
		jobid = r.get('response').get('result').get('job', 'Error')
		return jobid
	else:
		print(f"Failed to retrieve filtered traffic logs. Status code: {response.status_code}")

def start_traffic_logs(sinkhole: str) -> None:
	"""
	Start the traffic log processing using the query filter
	"""
	filter = f"( addr.dst in {sinkhole} )"
	query_params = {"type": "log", "log-type": "traffic", "query": filter}	
	response = session.get(api_url, headers=headers, params=query_params, verify=False)
	if response.status_code == 200:
		r = xmltodict.parse(response.text)
		jobid = r.get('response').get('result').get('job', 'Error')
		return jobid
	else:
		print(f"Failed to retrieve filtered traffic logs. Status code: {response.status_code}")

def download_logs(job_id: str, log_file: str) -> None:
	"""
	Download the log, it comes over in an entire xml response
	This gets converted in another function to a csv for import
	into Cortex for analysis
	"""
	query_params = {"type": "log", "action": "get", "job-id": job_id}
	response = session.get(api_url, headers=headers, params=query_params, verify=False)
	if response.status_code == 200:
		with open(log_file, "wb") as f:
			for chunk in response.iter_content(chunk_size=1024):
				f.write(chunk)
		print(f"[i]  File saved to {log_file}")
	else:
		print("Error creating file")
	return

def sji(job_id: str) -> None:
	"""
	sji = show job id
	We monitor the provided job id and 
	return once the status is FIN.  
	Print out friendly message using the dict above
	"""
	payload = {"type": "op", "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>"}
	while True:
		response = session.post(api_url, headers=headers, data=payload, verify=False)
		job_dict = xmltodict.parse(response.text)
		try:
			if job_dict is not None: 
				status = job_dict.get('response').get('result').get('job').get('status', "Something's Happening")
			else:
				print(job_dict)
			if status == "FIN":
				return
		except AttributeError:
			break
		try:
			progress = job_dict.get('response').get('result').get('job').get('progress', '0')
			progress = 0 if progress == None else progress
		except AttributeError:
			print(job_dict.get('response').get('msg').get('line'))
		print(f"{status_dict.get(status)} - {progress}%\t\t", end='\r')
		sleep(10)

def convert_xml_to_csv(xml_path: str, csv_path: str) -> None:
	"""
	Used to convert xml output to csv
	dynamically generates csv headers
	from xml elements and the iterates
	and saves the csv to the full_path 
	provided
	"""
	with open(xml_path, 'r') as xml_file:
		xml_data = xml_file.read()

	root = ET.fromstring(xml_data)
	csv_data = []
	columns = set()

	for entry in root.findall(".//entry"):
		row = {}
		for element in entry:
			columns.add(element.tag)
			row[element.tag] = element.text
		csv_data.append(row)

	with open(csv_path, 'w', newline='') as csvfile:
		csv_writer = csv.writer(csvfile)

		header = list(columns)
		csv_writer.writerow(header)

		for row in csv_data:
			csv_writer.writerow([row.get(col, '') for col in header])
	print(f"[i]  File saved to {csv_path}")


def main():
	
	global fw_ip, fw_username, fw_password, fw_api_key, api_url
	clear()
	if len(sys.argv) > 2:
		argue_with_me()
	elif len(sys.argv) > 1: # will simply send help to the user
		argue_with_me()
	else:
		fw_ip = input("[?]\tEnter FW IP Address: ")
		fw_username = input("[?]\tEnter your username: ")
		fw_password = getpass.getpass("[?]\tEnter your password: ")
		fw_password = urllib.parse.quote(fw_password)   # do we need to urlencode the password if it's not sent in the url string?
		fw_api_key = None
		
	api_url = f"https://{fw_ip}/api"
	
	cursor.hide()
	clear()
	print("[i]  Hostname And File Names\n")
	create_session()
	get_hostname_and_filename()

	print("[i]  Threat Logs")
	job_id = start_threat_logs()
	sji(job_id)
	download_logs(job_id, threat_full_path_xml)
	
	print("\n[i]  Traffic Logs")
	sinkhole = check_sinkhole_ip()
	job_id = start_traffic_logs(sinkhole)
	sji(job_id)
	download_logs(job_id, traffic_full_path_xml)

	print("\n[i]  CSV Conversion")
	convert_xml_to_csv(threat_full_path_xml, threat_full_path_csv)
	convert_xml_to_csv(traffic_full_path_xml, traffic_full_path_csv)

	cursor.show()


if __name__ == '__main__':
	main()
