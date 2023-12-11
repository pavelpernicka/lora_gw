#!/usr/bin/python
#decoder for meteohelix weather station
import sys
import meteocommon as a

def meteohelix(data):
    Type =  a.getbits(data, 0, 1);
    Battery = a.precisionRound(a.getbits(data, 2, 6)*0.05+3, 2);
    Temperature = a.precisionRound(a.getbits(data, 7, 17)*0.1-100, 1);
    T_min = a.precisionRound(Temperature - a.getbits(data, 18, 23)*0.1, 1);
    T_max = a.precisionRound(Temperature + a.getbits(data, 24, 29)*0.1, 1);
    Humidity = a.precisionRound(a.getbits(data, 30, 38)*0.2, 1);
    Pressure = a.getbits(data, 39, 52)*5+50000;
    Irradiation = a.getbits(data, 53, 62)*2;
    Irr_max = Irradiation + a.getbits(data, 63, 71)*2;
    Rain = a.precisionRound(a.getbits(data, 72, 79), 1);
    Rain_min_time = a.precisionRound(a.getbits(data, 80, 87), 1);
    decoded = {
        "Type": Type,
        "Battery": Battery,
        "Battery_wind": None,
        "Temperature": Temperature,
        "T_min": T_min ,
        "T_max": T_max,
        "Humidity": Humidity,
        "Pressure": Pressure,
        "Irradiation": Irradiation,
        "Irr_max": Irr_max,
        "Rain": Rain,
        "Rain_min_time": Rain_min_time,
        "Wind_ave10": None,
        "Wind_max10": None,
        "Wind_min10": None,
        "Dir_ave10": None,
        "Dir_max10": None,
        "Dir_hi10": None,
        "Dir_lo10": None
    }
    return decoded

if(len(sys.argv) > 1 and len(sys.argv[1]) > 20):
    decoded = meteohelix(sys.argv[1])
    a.doMore(decoded)
else:
    print("Wrong input data!")
