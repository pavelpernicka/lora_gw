#!/usr/bin/python
#common functions for decoders
import os
from os import path
import config as conf
from data import Data
import gcp

if(path.isfile(conf.dbLocation)):
	print("Database is located here: " + conf.dbLocation)
else:
	print("Database does not exist, creating new from template.")
	os.popen('cp ' + conf.templatePath + ' ' + conf.dbLocation)

def getbits(data, offsetn, ton):
	bytesnr = len(data)*4
	data = format(int(data, 16), '0' + str(bytesnr) + 'b')
	datastr = data[offsetn:(ton+1)]
	return int(datastr, 2)

def precisionRound(number, precision):
	factor = pow(10, precision)
	return round(number * factor) / factor

def doMore(data):
	d = Data(data)
	d.verifyData()
	print("---Data saving---")
	d.saveData()
	print("---Data uploading---")
	gcp.upload(d)
	print("---Deleting old data---")
	affected = d.deleteOldData()
	if(affected > 0):
		print(str(affected) + " rows deleted")
	else:
		print("Nothing was deleted")
	
