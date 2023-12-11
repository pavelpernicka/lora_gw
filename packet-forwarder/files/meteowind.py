#!/usr/bin/python
#decoder for meteohelix weather station
import sys
import meteocommon as a

def meteowind(data):
    Type =  a.getbits(data, 0, 1);
    Battery = a.precisionRound(a.getbits(data, 2, 6)*0.05+3, 1);
    Wind_ave10 = a.precisionRound(a.getbits(data, 7, 15)*0.1, 1);
    Wind_max10 = Wind_ave10 + a.precisionRound(a.getbits(data, 16, 24)*0.1, 1);
    Wind_min10 = Wind_ave10 - a.precisionRound(a.getbits(data, 25, 33)*0.1, 1);
    Dir_ave10 = a.precisionRound(a.getbits(data, 34, 42)*1, 1);
    Dir_max10 = a.precisionRound(a.getbits(data, 43, 51)*1, 1);
    Dir_hi10 = a.precisionRound(a.getbits(data, 52, 59)*1, 1);
    Dir_lo10 = a.precisionRound(a.getbits(data, 60, 67)*1, 1);
  
    decoded = {
        "Type": Type,
        "Battery": None,
        "Battery_wind": Battery,
        "Temperature": None,
        "T_min": None ,
        "T_max": None,
        "Humidity": None,
        "Pressure": None,
        "Irradiation": None,
        "Irr_max": None,
        "Rain": None,
        "Rain_min_time": None,
        "Wind_ave10": Wind_ave10,
        "Wind_max10": Wind_max10,
        "Wind_min10": Wind_min10,
        "Dir_ave10": Dir_ave10,
        "Dir_max10": Dir_max10,
        "Dir_hi10": Dir_hi10,
        "Dir_lo10": Dir_lo10,

    };
    return decoded

if(len(sys.argv) > 1 and len(sys.argv[1]) > 16):
    decoded = meteowind(sys.argv[1])
    a.doMore(decoded)
else:
    print("Wrong input data!")
