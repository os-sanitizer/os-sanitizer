from statistics import mean, median, stdev
from scipy import stats
import json

global_median_ratio_list = []
global_mean_ratio_list = []
global_t_test_stat_sig_true_list = []
global_median_none_time_list = []
global_mean_none_time_list = []
global_stdev_none_time_list = []

global_experiment_median_list = []
global_experiment_stdev_list = []

pvalue_threshold = 0.05

# these 2 lists hardcode options and benchmark orders. Do not modify them.
os_san_option = ["gets", "access", "security-file-open", "rwx-mem", "memcpy", "strcpy", "strncpy",  "sprintf", "snprintf", "printf-mutability", "system-mutability", "system-absolute", "filep-unlocked", "fixed-mmap", "interceptable-path", "reference-policy", "all", "none"]
spec_bench_names = ["perlbench", "gcc", "mcf", "omnetpp", "xalancbmk", "x264", "deepsjeng", "leela", "exchange2", "xz_s"]

# Read SPEC data and print results
with open("./../data/data_SPEC.json", "r") as reader:
    SPEC_wall_time = json.load(reader)

for spec_app in spec_bench_names:
    # populate spec_app_none_list (spec_appliaction + no os-san; all readings) first because it is used everywhere
    spec_app_none_list = []
    for key in SPEC_wall_time:
        if "none" in key and spec_app in key:
            spec_app_none_list.append(SPEC_wall_time[key])

    spec_app_none_list_median = median(spec_app_none_list)
    global_median_none_time_list.append(round(spec_app_none_list_median, 2))
    spec_app_none_list_stdev = stdev(spec_app_none_list)
    global_stdev_none_time_list.append(round(spec_app_none_list_stdev, 2))
    spec_app_none_list_mean = mean(spec_app_none_list)
    global_mean_none_time_list.append(round(spec_app_none_list_mean, 2))
    print("----------------------------------------------------")
    print("----------------------------------------------------")
    print(f"{spec_app} stats")
    print(f"{spec_app} none median time: {round(spec_app_none_list_median, 2)}")
    print(f"{spec_app} none mean time: {round(spec_app_none_list_mean, 2)}")
    print("----------------------------------------------------")

    for index, option in enumerate(os_san_option):
        spec_app_with_option = []
        for key in SPEC_wall_time:
            if option in key and spec_app in key:
                spec_app_with_option.append(SPEC_wall_time[key])

        global_experiment_median_list.append(round(median(spec_app_with_option), 2))
        global_experiment_stdev_list.append(round(stdev(spec_app_with_option), 2))
        rounded_spec_app_with_option_list_median_ratio = round(median(spec_app_with_option) / spec_app_none_list_median, 2)
        rounded_spec_app_with_option_list_mean_ratio = round(mean(spec_app_with_option) / spec_app_none_list_mean, 2)
        print(f"{spec_app} {option} median ratio: {rounded_spec_app_with_option_list_median_ratio}")
        global_median_ratio_list.append(rounded_spec_app_with_option_list_median_ratio)
        print(f"{spec_app} {option} mean ratio: {rounded_spec_app_with_option_list_mean_ratio}")
        global_mean_ratio_list.append(rounded_spec_app_with_option_list_mean_ratio)
        local_cv = round(stdev(spec_app_with_option) / mean(spec_app_with_option), 2)
        print(f"{spec_app} {option} CV: {local_cv}")
        t_test = stats.ttest_ind(spec_app_with_option, spec_app_none_list, equal_var=False, alternative="greater")
        print(f"t-test p value: {t_test.pvalue}")
        if t_test.pvalue < pvalue_threshold:
            global_t_test_stat_sig_true_list.append(True)
        else:
            global_t_test_stat_sig_true_list.append(False)

# Read speedometer data and print results
with open('./../data/data_speedometer.json', 'r') as fp:
    speedometer_wall_time = json.load(fp)

speedometer_none_list = []
for key in speedometer_wall_time:
    if "none" in key:
        speedometer_none_list.append(speedometer_wall_time[key])

speedometer_none_list_median = median(speedometer_none_list)
global_median_none_time_list.append(round(speedometer_none_list_median,2))
speedometer_none_list_stdev = stdev(speedometer_none_list)
global_stdev_none_time_list.append(round(speedometer_none_list_stdev,2))
speedometer_none_list_mean = mean(speedometer_none_list)
global_mean_none_time_list.append(round(speedometer_none_list_mean,2))
print("----------------------------------------------------")
print("----------------------------------------------------")
print(f"speedometer stats")
print(f"speedometer none median time: {round(speedometer_none_list_median, 2)}")
print(f"speedometer none mean time: {round(speedometer_none_list_mean, 2)}")
print("----------------------------------------------------")

for index, option in enumerate(os_san_option):
    speedometer_with_option = []
    for key in speedometer_wall_time:
        if option in key:
            speedometer_with_option.append(speedometer_wall_time[key])

    global_experiment_median_list.append(round(median(speedometer_with_option), 2))
    global_experiment_stdev_list.append(round(stdev(speedometer_with_option), 2))
    rounded_speedometer_with_option_list_median_ratio = round(median(speedometer_with_option) / speedometer_none_list_median, 2)
    rounded_speedometer_with_option_list_mean_ratio = round(mean(speedometer_with_option) / speedometer_none_list_mean, 2)
    print(f"speedometer {option} median ratio: {rounded_speedometer_with_option_list_median_ratio}")
    global_median_ratio_list.append(rounded_speedometer_with_option_list_median_ratio)
    print(f"speedometer {option} mean ratio: {rounded_speedometer_with_option_list_mean_ratio}")
    global_mean_ratio_list.append(rounded_speedometer_with_option_list_mean_ratio)
    local_cv = round(stdev(speedometer_with_option) / mean(speedometer_with_option), 2)
    print(f"speedometer {option} CV: {local_cv}")
    t_test = stats.ttest_ind(speedometer_with_option, speedometer_none_list, equal_var=False, alternative="greater")
    print(f"t-test p value: {t_test.pvalue}")
    if t_test.pvalue < pvalue_threshold:
        global_t_test_stat_sig_true_list.append(True)
    else:
        global_t_test_stat_sig_true_list.append(False)

print("----------------------------------------------------")
print("----------------------------------------------------")

latex_list = [r"        &\gets{} & ",
              r"        &\accstat{} & ",
              r"        &\secfileopen{} & ",
              r"        &\rwxmem{} & ",
              r"        &\memcpy{} & ",
              r"        &\strcpy{} & ",
              r"        &\strncpy{} & ",
              r"        &\sprintf{} & ",
              r"        &\snprintf{} & ",
              r"        &\printfmut{} & ",
              r"        &\systemmut{} & ",
              r"        &\systemabs{} & ",
              r"        &\filepunlocked{} & ",
              r"        &\fixedmmap{} & ",
              r"        &\pintercept{} & ",
              r"        \cmidrule{2-13}" + r"        &All Passes (except \memcpy{}, \strcpy{}, \strncpy{}) & ",
              r"        &All Passes Enabled & ",
              r"        \midrule" + r"        \multicolumn{2}{l}{\textit{Baseline Time $[s]$}} & "]

# main table
for i in range(17):
    d1 = (r"\significant{" if (global_t_test_stat_sig_true_list[i] is True) else r"\insignificant{") + f"{global_median_ratio_list[i]:.2f}" + r"}"
    d2 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 1 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 1 + i]:.2f}" + r"}"
    d3 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 2 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 2 + i]:.2f}" + r"}"
    d4 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 3 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 3 + i]:.2f}" + r"}"
    d5 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 4 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 4 + i]:.2f}" + r"}"
    d6 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 5 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 5 + i]:.2f}" + r"}"
    d7 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 6 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 6 + i]:.2f}" + r"}"
    d8 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 7 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 7 + i]:.2f}" + r"}"
    d9 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 8 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 8 + i]:.2f}" + r"}"
    d10 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 9 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 9 + i]:.2f}" + r"}"
    d11 = (r"\significant{" if (global_t_test_stat_sig_true_list[18 * 10 + i] is True) else r"\insignificant{") + f"{global_median_ratio_list[18 * 10 + i]:.2f}" + r"}"
    d12 = r"\\"
    print(f"{latex_list[i]}{d1} & {d2} & {d3} & {d4} & {d5} & {d6} & {d7} & {d8} & {d9} & {d10} & {d11} {d12}")
print(f"{latex_list[17]}{global_median_none_time_list[0]:.2f} & {global_median_none_time_list[1]:.2f} & {global_median_none_time_list[2]:.2f} & {global_median_none_time_list[3]:.2f} & "
      f"{global_median_none_time_list[4]:.2f} & {global_median_none_time_list[5]:.2f} & {global_median_none_time_list[6]:.2f} & {global_median_none_time_list[7]:.2f} & "
      f"{global_median_none_time_list[8]:.2f} & {global_median_none_time_list[9]:.2f} & {global_median_none_time_list[10]:.2f} " + r"\\")

print("----------------------------------------------------")
print("----------------------------------------------------")

# appendix table
for i in range(17):
    d1 = f"{global_experiment_median_list[i]:.2f} & {global_experiment_stdev_list[i]:.2f}"
    d2 = f"{global_experiment_median_list[18 * 1 + i]:.2f} & {global_experiment_stdev_list[18 * 1 + i]:.2f}"
    d3 = f"{global_experiment_median_list[18 * 2 + i]:.2f} & {global_experiment_stdev_list[18 * 2 + i]:.2f}"
    d4 = f"{global_experiment_median_list[18 * 3 + i]:.2f} & {global_experiment_stdev_list[18 * 3 + i]:.2f}"
    d5 = f"{global_experiment_median_list[18 * 4 + i]:.2f} & {global_experiment_stdev_list[18 * 4 + i]:.2f}"
    d6 = f"{global_experiment_median_list[18 * 5 + i]:.2f} & {global_experiment_stdev_list[18 * 5 + i]:.2f}"
    d12 = r"\\"
    print(f"{latex_list[i]}{d1} & {d2} & {d3} & {d4} & {d5} & {d6} {d12}")
print(f"{latex_list[17]}{global_median_none_time_list[0]:.2f} & {global_stdev_none_time_list[0]:.2f} & {global_median_none_time_list[1]:.2f} & {global_stdev_none_time_list[1]:.2f} & "
      f"{global_median_none_time_list[2]:.2f} & {global_stdev_none_time_list[2]:.2f} & {global_median_none_time_list[3]:.2f} & {global_stdev_none_time_list[3]:.2f} & "
      f"{global_median_none_time_list[4]:.2f} & {global_stdev_none_time_list[4]:.2f} & {global_median_none_time_list[5]:.2f} & {global_stdev_none_time_list[5]:.2f}" + r"\\")

print("----------------------------------------------------")
print("----------------------------------------------------")

# appendix table
for i in range(17):
    d1 = f"{global_experiment_median_list[18 * 6 + i]:.2f} & {global_experiment_stdev_list[18 * 6 + i]:.2f}"
    d2 = f"{global_experiment_median_list[18 * 7 + i]:.2f} & {global_experiment_stdev_list[18 * 7 + i]:.2f}"
    d3 = f"{global_experiment_median_list[18 * 8 + i]:.2f} & {global_experiment_stdev_list[18 * 8 + i]:.2f}"
    d4 = f"{global_experiment_median_list[18 * 9 + i]:.2f} & {global_experiment_stdev_list[18 * 9 + i]:.2f}"
    d5 = f"{global_experiment_median_list[18 * 10 + i]:.2f} & {global_experiment_stdev_list[18 * 10 + i]:.2f}"
    d12 = r"\\"
    print(f"{latex_list[i]}{d1} & {d2} & {d3} & {d4} & {d5} {d12}")
print(f"{latex_list[17]}{global_median_none_time_list[6]:.2f} & {global_stdev_none_time_list[6]:.2f} & {global_median_none_time_list[7]:.2f} & {global_stdev_none_time_list[7]:.2f} & "
      f"{global_median_none_time_list[8]:.2f} & {global_stdev_none_time_list[8]:.2f} & {global_median_none_time_list[9]:.2f} & {global_stdev_none_time_list[9]:.2f} & "
      f"{global_median_none_time_list[10]:.2f} & {global_stdev_none_time_list[10]:.2f}" + r"\\")