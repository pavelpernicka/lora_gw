#!/usr/bin/python
# Google Cloud IoT

import json
import base64
import config as conf
import time
import datetime
import jwt
import requests

def create_jwt(project_id, private_key_file, algorithm):
	token = {
		"iat": datetime.datetime.utcnow(),
		"exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
		"aud": project_id
	}
	try:
		with open(private_key_file, "r") as f:
			private_key = f.read()
			print("Creating JWT using {} from private key file {}".format(algorithm, private_key_file))
			return jwt.encode(token, private_key, algorithm=algorithm).decode('utf-8')
	except IOError:
		print("Error: Could not open private key file!")
		return None

def publish_message(message, message_type, base_url, project_id, cloud_region, registry_id, device_id, jwt_token):
	#print(jwt_token)
	headers = {
		"authorization": "Bearer {}".format(jwt_token),
		"content-type": "application/json",
		"cache-control": "no-cache",
	}
	url_suffix = "publishEvent" if message_type == "event" else "setState"
	publish_url = ("{}/projects/{}/locations/{}/registries/{}/devices/{}:{}").format(base_url, project_id, cloud_region, registry_id, device_id, url_suffix)
	body = None
	msg_bytes = base64.urlsafe_b64encode(message.encode("utf-8"))
	if message_type == "event":
		body = {"binary_data": msg_bytes.decode("ascii")}
	else:
		body = {"state": {"binary_data": msg_bytes.decode("ascii")}}

	#print("Publish URL: {}".format(publish_url))
	#print("Headers: {}".format(headers))

	resp = requests.post(publish_url, data=json.dumps(body), headers=headers)
	if resp.status_code != 200:
		print("Error: {}".format(resp.status_code))
	return resp

def upload(d):
	jwt_token = create_jwt(conf.GCP_project_id, conf.GCP_private_key_file, conf.GCP_algorithm)
	if(jwt_token != None):
		jwt_iat = datetime.datetime.utcnow()
		notUploaded = d.getNotUploaded()
		if notUploaded and len(notUploaded) > 0:
			print("Rows to upload: " + str(len(notUploaded)))
			counter = 0
			for i in notUploaded:
				counter += 1
				if not(conf.check_if_all) or ((i["is_wind"]==1 and i["is_meteo"]==1) or (1 != counter)): # when there is data from both sensors
					seconds_since_issue = (datetime.datetime.utcnow() - jwt_iat).seconds
					if seconds_since_issue > 60:
						print("Refreshing token after {}s").format(seconds_since_issue)
						jwt_token = create_jwt(conf.GCP_project_id, conf.GCP_private_key_file, conf.GCP_algorithm)
						jwt_iat = datetime.datetime.utcnow()
					toUpload = {
						"time": i["time"],
						"temperature": i["temperature"],
						"humidity": i["humidity"],
						"pressure": i["pressure"],
						"irradiation": i["irradiation"],
						"rain":	i["rain"],
						"wind": i["wind_avg"],
						"wind_max10": i["wind_max"],
						"wind_min10": i["wind_min"],
						"direction": i["direction_avg"],
						"dir_max10": i["direction_max"],
						"dir_hi10": i["direction_hi"],
						"dir_lo10": i["direction_lo"]
					}
					payload = json.dumps(toUpload)
					#print("Data to send: {}".format(payload))
					resp = publish_message(payload,"event",conf.GCP_base_url,conf.GCP_project_id,conf.GCP_cloud_region,conf.GCP_registry_id,conf.GCP_device_id,jwt_token)
					print("Response from server: ", resp.text)
					if(resp.status_code == 200):
						print(" response OK, changing publish status in DB")
						d.changePublishStatus(i["id"], 1)
					print("")
				else:
					print("This record is still waiting for data to be appended")
		else:
			print("Nothing to upload")
	else:
		print("Cannot publish data without JWT")
