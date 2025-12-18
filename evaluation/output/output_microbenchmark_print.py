# Print microbenchmark tables from data.
# Data is obtained by running eval_microbench.sh and filtering for microbenchmark name and iteration count lines.

from statistics import median, stdev

microbench_stat_file = "./../data/data_microbench.txt"

microbench_name = ""
stat_list = [0] * 20
line_processed = 0

global_time_per_iteration_baseline_list = []
global_time_per_iteration_with_option_list = []
global_ratio_list = []
global_baseline_median_list = []
global_experiment_median_list = []
global_baseline_stdev_list = []
global_experiment_stdev_list = []

# following same options order as eval_microbench.sh
os_san_option = ["access", "gets", "rwx-mem", "memcpy", "strcpy", "strncpy", "security-file-open", "sprintf", "snprintf", "printf-mutability", "system-mutability", "system-absolute", "filep-unlocked", "fixed-mmap", "interceptable-path"]

with open(microbench_stat_file, "r") as reader:
    for line in reader:
        line = line.rstrip()
        if "microbenchmark" in line:
            name = line[line.index(" ")+1:]
            microbench_name = name.rstrip()
            # reset line_processed and stat_list for each new microbench name
            line_processed = 0
            stat_list = [0] * 20
        elif "Iterations" in line:
            iterations = int(line[line.index(":")+2:])
            stat_list[line_processed] = iterations
            line_processed += 1
            # collected all 20 iterations
            # first 10 iterations are with os-san; next 10 iterations are without os-san
            if line_processed == 20:
                print(f"microbench: {microbench_name}")
                no_os_san_median_itr = median(stat_list[10:20])
                global_baseline_median_list.append(round(no_os_san_median_itr, 2))
                global_baseline_stdev_list.append(round(stdev(stat_list[10:20]), 2))
                time_per_itr_no_os_san = (10 * 10**6) / no_os_san_median_itr
                print(f"none time per itr: {round(time_per_itr_no_os_san, 2)}")
                global_time_per_iteration_baseline_list.append(round(time_per_itr_no_os_san, 2))

                with_os_san_median_itr = median(stat_list[0:10])
                global_experiment_median_list.append(round(with_os_san_median_itr, 2))
                global_experiment_stdev_list.append(round(stdev(stat_list[0:10]), 2))
                time_per_itr_with_os_san = (10 * 10**6) / with_os_san_median_itr
                print(f"with os-san time per itr: {round(time_per_itr_with_os_san, 2)}")
                global_time_per_iteration_with_option_list.append(round(time_per_itr_with_os_san, 2))

                print(f"Ratio: {round(time_per_itr_with_os_san/time_per_itr_no_os_san, 2)}")
                global_ratio_list.append(round(time_per_itr_with_os_san/time_per_itr_no_os_san, 2))

                print("--------------------------------------------------")

latex_list = [r"        \accstat{} & ",
              r"        \gets{} & ",
              r"        \rwxmem{} & ",
              r"        \memcpy{} & ",
              r"        \strcpy{} & ",
              r"        \strncpy{} & ",
              r"        \secfileopen{} & ",
              r"        \sprintf{} & ",
              r"        \snprintf{} & ",
              r"        \printfmut{} & ",
              r"        \systemmut{} & ",
              r"        \systemabs{} & ",
              r"        \filepunlocked{} & ",
              r"        \fixedmmap{} & ",
              r"        \pintercept{} & ",]

# Main table
print("Table 2: Results of microbenchmarks.")
print("Rows: Pass, Baseline Iteration Time (µs), OS-San Iteration Time (µs), Ratio")
for i in range(len(os_san_option)):
    d1 = f"{global_time_per_iteration_baseline_list[i]:.2f}"
    d2 = f"{global_time_per_iteration_with_option_list[i]:.2f}"
    d3 = f"{global_ratio_list[i]:.2f}"
    d4 = r"\\"
    print(f"{latex_list[i]}{d1} & {d2} & {d3} {d4}")

print("--------------------------------------------------")

# Additional data
print("Additional Table: Median (m) and standard deviation (σ) of iteration counts for microbenchmarks.")
print("Rows: Pass, Baseline Iterations (m), Baseline Iterations (σ), OS-SANITIZER Iterations (m), OS-SANITIZER Iterations (σ)")
for i in range(len(os_san_option)):
    d1 = f"{global_baseline_median_list[i]:.2f}"
    d2 = f"{global_baseline_stdev_list[i]:.2f}"
    d3 = f"{global_experiment_median_list[i]:.2f}"
    d4 = f"{global_experiment_stdev_list[i]:.2f}"
    d5 = r"\\"
    print(f"{latex_list[i]}{d1} & {d2} & {d3} & {d4} {d5}")
