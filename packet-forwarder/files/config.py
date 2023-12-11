#!/usr/bin/python
import subprocess
#configuration

def getUci(what):
	try:
		return subprocess.check_output(['uci', 'get', what]).decode('utf-8').strip('\n')
	except:
		return ""

#templatePath = "template.db"
#dbLocation = "meteodata.db"
templatePath = "/etc/lora/template.db"
dbLocation = "/tmp/meteodata.db"
allowedRanges = {
#   meteoprvek		min, max
    "Type":		[0, 1],
    "Battery":		[3, 4.5],
    "Battery_wind":	[3, 4.5],
    "Temperature":	[-50, 80],
    "T_min":		[-50, 80] ,
    "T_max":		[-50, 80],
    "Humidity":		[1, 100],
    "Pressure":		[60000, 128000],
    "Irradiation":	[0, 1500],
    "Irr_max":		[0, 1500],
    "Rain":		[0, 255],
    "Rain_min_time":	[0, 255],
    "Wind_ave10":	[0, 51],
    "Wind_max10":	[0, 51],
    "Wind_min10":	[0, 51],
    "Dir_ave10":	[0, 359],
    "Dir_max10":	[0, 359],
    "Dir_hi10":		[0, 179],
    "Dir_lo10":		[0, 179]
}
dataStoreMonths = 3 # how long will be data stored (months)

# settings for Google Cloud IoT
GCP_project_id = getUci('lora-global.gateway_conf.gcp_project_id')
GCP_cloud_region = getUci('lora-global.gateway_conf.gcp_cloud_region')
GCP_registry_id = getUci('lora-global.gateway_conf.gcp_registry_id')
GCP_device_id = getUci('lora-global.gateway_conf.gcp_device_id')
GCP_algorithm = "RS256"
GCP_private_key_file = getUci('lora-global.gateway_conf.gcp_private_key_file')
GCP_base_url = "https://cloudiotdevice.googleapis.com/v1"

# check if all data in  is present before sending to GCP (true = data will not be send when meteohelix/meteowind data is missing in last record in DB)
check_if_all = 1
