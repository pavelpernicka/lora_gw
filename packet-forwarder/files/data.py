#!/usr/bin/python
#part for working with data and database
import sqlite3 as db
import config as conf
import time
import sys

class Data:
	def __init__(self, data):
		self.data = data

	def verifyData(self):
		print("Data verification:")
		for key in self.data.keys():
			print(" Checking " + key + "...", end='')
			min, max = conf.allowedRanges[key]
			if((self.data[key] != None) and ((self.data[key] >= min) and (self.data[key] <= max))):
				print("OK", end='')
			else:
				print("INCORRECT", end='')
				self.data[key] = None
			print(" (" + str(self.data[key]) + ")")

		print("Verification DONE")

	def getdata(self):
		return self.data

	def dict_factory(self, cursor, row):
		d = {}
		for idx, col in enumerate(cursor.description):
			d[col[0]] = row[idx]
		return d

	def connInit(self, db_file):
		self.conn = None
		try:
			self.conn = db.connect(db_file)
			self.conn.row_factory = self.dict_factory
		except Error as e:
			sys.exit(e)

	def sqlTask(self, sql, task):
		cur = self.conn.cursor()
		try:
			cur.execute(sql, task)
			self.conn.commit()
		except db.Error as e:
			print("An error occurred:", e.args[0])
		return cur.rowcount

	def sqlGet(self, sql, task):
		cur = self.conn.cursor()
		try:
			cur.execute(sql, task)
			rows = cur.fetchall()
			if(len(rows) > 0):
				return rows
			else:
				return None
		except db.Error as e:
			print("An error occurred:", e.args[0])
			return None

	def insertData(self, task):
		sql = ''' INSERT INTO data(time,temperature,temperature_min,temperature_max,humidity,pressure,irradiation,irradiation_max,rain,rain_min_time,wind_avg,wind_max,wind_min,direction_avg,direction_max,direction_hi,direction_lo,is_meteo,is_wind,uploaded)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '''
		return self.sqlTask(sql, task)

	def updateData(self, task):
		sql = ''' UPDATE data SET time=?,temperature=?,temperature_min=?,temperature_max=?,humidity=?,pressure=?,irradiation=?,irradiation_max=?,rain=?,rain_min_time=?,wind_avg=?,wind_max=?,wind_min=?,direction_avg=?,direction_max=?,direction_hi=?,direction_lo=?,is_meteo=?,is_wind=?,uploaded=? WHERE id=? '''
		return self.sqlTask(sql, task)

	def changePublishStatus(self, id, value):
		sql = ''' UPDATE data SET uploaded=? WHERE id=? '''
		task = (value, id)
		return self.sqlTask(sql, task)

	def deleteOldData(self):
		sql = ''' DELETE FROM data WHERE date(time) <= date('now','-''' + str(conf.dataStoreMonths) + ''' months') '''
		#print(sql)
		task = ()
		return self.sqlTask(sql, task)

	def get_last_record(self):
		sql = "SELECT * FROM data ORDER BY id DESC LIMIT 1"
		return self.sqlGet(sql, ())

	def getNotUploaded(self):
		sql = "SELECT * FROM data WHERE uploaded != 1 ORDER BY id DESC"
		return self.sqlGet(sql, ())

	def newRecord(self):
		data_to_insert = (
			time.time(), 
			self.data["Temperature"], 
			self.data["T_min"], 
			self.data["T_max"], 
			self.data["Humidity"], 
			self.data["Pressure"], 
			self.data["Irradiation"], 
			self.data["Irr_max"], 
			self.data["Rain"], 
			self.data["Rain_min_time"], 
			self.data["Wind_ave10"], 
			self.data["Wind_max10"], 
			self.data["Wind_min10"], 
			self.data["Dir_ave10"], 
			self.data["Dir_max10"], 
			self.data["Dir_hi10"], 
			self.data["Dir_lo10"],
			self.data["Type"],
			not(self.data["Type"]),
			0
		)
		self.insertData(data_to_insert)

	def saveData(self):
		self.connInit(conf.dbLocation)
		with self.conn:
			last = self.get_last_record()
			if(last and (last[0]["time"]+1200 > time.time())): #data is not too old (20 minutes)
				if self.data["Type"] == 1: # if meteohelix
					print("Data is from meteohelix")
					if last[0]["is_meteo"] != 1 and last[0]["is_wind"] == 1: # no meteohelix data present
						print(" appending to last record")
						data_to_insert = (
							last[0]["time"], 
							self.data["Temperature"], 
							self.data["T_min"], 
							self.data["T_max"], 
							self.data["Humidity"], 
							self.data["Pressure"], 
							self.data["Irradiation"], 
							self.data["Irr_max"], 
							self.data["Rain"], 
							self.data["Rain_min_time"], 
							last[0]["wind_avg"], 
							last[0]["wind_max"], 
							last[0]["wind_min"], 
							last[0]["direction_avg"], 
							last[0]["direction_max"], 
							last[0]["direction_hi"], 
							last[0]["direction_lo"],
							1,
							1,
							0,
							last[0]["id"]
						)
						self.updateData(data_to_insert)
					else:
						print(" inserting new record")
						self.newRecord()
				else: # if meteowind
					print("Data is from meteowind")
					if last[0]["is_wind"] != 1 and last[0]["is_meteo"] == 1: # no meteohelix data present
						print(" appending to last record")
						data_to_insert = (
							last[0]["time"], 
							last[0]["temperature"], 
							last[0]["temperature_min"], 
							last[0]["temperature_max"], 
							last[0]["humidity"], 
							last[0]["pressure"], 
							last[0]["irradiation"], 
							last[0]["irradiation_max"], 
							last[0]["rain"], 
							last[0]["rain_min_time"], 
							self.data["Wind_ave10"], 
							self.data["Wind_max10"], 
							self.data["Wind_min10"], 
							self.data["Dir_ave10"], 
							self.data["Dir_max10"], 
							self.data["Dir_hi10"], 
							self.data["Dir_lo10"],
							1,
							1,
							0,
							last[0]["id"]
						)
						self.updateData(data_to_insert)
					else:
						print(" inserting new record")
						self.newRecord()
			else:
				print("Too late to append data")
				print(" inserting new record")
				self.newRecord()

