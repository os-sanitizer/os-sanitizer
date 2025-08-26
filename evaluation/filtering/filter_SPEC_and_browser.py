import os
import json

# Dump data_SPEC.json

# TODO: spec_result_dir expects directory structure like:
# ├── FedoraBase00
# │         ├── cpu_intspeed_log_0_all_...
# │         ├── ...
# │         ├── cpu_intspeed_log_9_all_...
# │         └── result
# │             ├── CPU2017.001.intspeed.test.csv
# │             ├── CPU2017.002.intspeed.test.csv
# │             ├── ...
# ├── FedoraBase01
# ├── FedoraBase...

# Where FedoraBase00 contains files from `eval_SPEC_intspeed_00.sh` and so on.
# `result` directory in each FedoraBase.. is created by SPEC
# --------------------------------------------------------------
spec_result_dir = ""

clones = os.listdir(spec_result_dir)

SPEC_wall_time = {}

for machine in clones:
    cpu_intspeed_files = []
    if "FedoraBase" in machine:
        curr_dir = spec_result_dir + "/" + machine
        files = os.listdir(curr_dir)

        for file in files:
            if "cpu_intspeed" in file:
                cpu_intspeed_files.append(file)

        for file in cpu_intspeed_files:
            with open(curr_dir + "/" + file, "r") as reader:
                for line in reader:
                    if "format: CSV" in line:
                        csv_file = line.split("/")[-1].rstrip()
                        with open(curr_dir + "/" + "result/" + csv_file, "r") as csv_reader:
                            for result_line in csv_reader:
                                # Explanation:
                                # # We used to report both times of 1x SPEC run with
                                # # if "iteration #" in line:
                                # # Now, we only take the biggest time of 1x SPEC run with
                                # # if "peak NR" in line:
                                if "peak NR" in result_line:
                                    values = result_line.split(",")
                                    benchmark_name = values[0] + values[-1].rstrip() + file
                                    value = float(values[2])
                                    SPEC_wall_time[benchmark_name] = value


with open('./../data/data_SPEC.json', 'w') as fp:
    json.dump(SPEC_wall_time, fp)

# Dump data_speedometer.json
# TODO: `speedometer_result_dir` should point towards results directory generated during browserbench speedometer evaluation.
# --------------------------------------------------------------
speedometer_result_dir = ""

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