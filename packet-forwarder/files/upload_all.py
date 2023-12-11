#!/usr/bin/python
# script for uploading all data to GCP when internet status changes

from data import Data
import gcp
import config as conf

d = Data("")
d.connInit(conf.dbLocation)
with d.conn:
	gcp.upload(d)
