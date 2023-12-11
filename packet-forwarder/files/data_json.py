#!/usr/bin/python
# cgi script to return json from DB

from data import Data
import config as conf
import json

datarange = "aktualni"
datamode = "AVG"


d = Data("")
d.connInit(conf.dbLocation)
data = {}
with d.conn:
	sql = "SELECT datetime(time, 'unixepoch', 'localtime') as date, time, temperature, temperature_min, temperature_max, humidity, pressure, irradiation, irradiation_max, rain, wind_avg as wind, wind_max as gust, direction_max, direction_avg as direction FROM data WHERE date BETWEEN datetime('now', '-2 days') AND datetime('now', 'localtime')"
	task = ()

#	if datarange == "aktualni":
#		sql = "SELECT datetime(time, 'unixepoch', 'localtime') as date, temperature, humidity, pressure, irradiation, rain, wind_avg as wind, wind_max as gust, direction_avg as direction FROM data WHERE datetime(date) >= now() - INTERVAL(1 DAY) ORDER BY date"
#	elif datarange == "tyden":
#		sql = "SELECT datetime(time, 'unixepoch', 'localtime') as date, " + datamode + "(temperature), " + datamode + "(humidity), " + datamode + "(pressure), " + datamode + "(irradiation), SUM(rain), " + datamode + "(wind_avg) as wind, " + datamode + "(wind_max) as gust, " + datamode + "(direction_avg) as direction FROM data WHERE YEARWEEK(date) = YEARWEEK(NOW()) GROUP BY CAST(date), HOUR(date) ORDER BY date"
#	elif datarange == "mesic":
#		sql = "SELECT datetime(time, 'unixepoch', 'localtime') as date, " + datamode + "(temperature), " + datamode + "(humidity), " + datamode + "(pressure), " + datamode + "(irradiation), SUM(rain), " + datamode + "(wind_avg) as wind, " + datamode + "(wind_max) as gust, " + datamode + "(direction_avg) as direction FROM data WHERE date >= now() - INTERVAL 1 MONTH GROUP BY CAST(date), HOUR(date) ORDER BY date"
#	else:
#		sql = "SELECT datetime(time, 'unixepoch', 'localtime') as date, " + datamode + "(temperature), " + datamode + "(humidity), " + datamode + "(pressure), " + datamode + "(irradiation), SUM(rain), " + datamode + "(wind_avg) as wind, " + datamode + "(wind_max) as gust, " + datamode + "(direction_avg) as direction FROM data WHERE date >= now() - INTERVAL 1 YEAR GROUP BY CAST(date), HOUR(date) ORDER BY date"
#	print(sql)

	data = d.sqlGet(sql, task)
	#print(data)
print(json.dumps(data))
