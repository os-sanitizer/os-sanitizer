#!/usr/bin/env python3
import os
import sys
import json

# Dump data_speedometer.json
# TODO: `speedometer_result_dir` should point towards results directory generated during browserbench speedometer evaluation.
# --------------------------------------------------------------
assert sys.argv[1:], "USAGE: filter_browserbench.py <RESULTS DIR>"
speedometer_result_dir = sys.argv[1]

all_files = os.listdir(speedometer_result_dir)

speedometer_files = []
speedometer_wall_time = {}

for file in all_files:
    if "speedometer" in file and "json" not in file:
        speedometer_files.append(file)

for file in speedometer_files:
    with open(speedometer_result_dir + "/" + file, "r") as reader:
        for line in reader:
            if "Elapsed (wall clock) time" in line:
                encoded_value = line.split(":")[4:]
                if len(encoded_value) == 2:
                    speedometer_wall_time[file] = float(encoded_value[0]) * 60 + float(encoded_value[1])
                elif len(encoded_value) == 3:
                    speedometer_wall_time[file] = float(encoded_value[0]) * 60 * 60 + float(encoded_value[1]) * 60 + float(encoded_value[2])

with open('./../data/data_speedometer.json', 'w') as fp:
    json.dump(speedometer_wall_time, fp)
