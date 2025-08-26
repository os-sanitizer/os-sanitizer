#!/bin/bash

#
# Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
#
# See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).
#

# Pre run checklist: 1.) os_san_option list 2.) update info_tag 3.) for loop iterations
# Required directory structure:
# os-sanitizer
# ├── evaluation
# │   ├── microbenchmark
# │   	  ├── eval_microbench.sh
# │       └── results
# ├── examples
# │   ├── 01_access.c
# │   ├── ...
# │   ├── ...

# run in directory microbenchmark
# output in results

# add all options except "all". Also, don't include "none" here.
os_san_option=("access" "gets" "rwx-mem" "memcpy" "strcpy" "strncpy" "security-file-open" "sprintf" "snprintf" "printf-mutability" "system-mutability" "system-absolute" "filep-unlocked" "fixed-mmap" "interceptable-path")
example_name=("01_access" "02_gets" "03_rwx_mem" "04_memcpy" "04_strcpy" "04_strncpy" "05_security_file_open" "06_sprintf" "07_snprintf" "08_printf_mutability" "09_system_mutability" "10_system_abs" "11_filep_unlocked" "12_fixed_mmap" "13_interceptable_path")

example_count=0
info_tag=numer_commit_debug

cd ../../examples
make clean
make all OPTION='-DMICROBENCHMARK'
chmod o+w dir1
chmod 666 05_demo_file.txt

for os_san_type in "${os_san_option[@]}"; 
do
    echo "microbenchmark $os_san_type"
    microbenchmark_executable=${example_name[${example_count}]}

    # 10 benchmark runs with os-san + 10 benchmark runs without os-san
    for i in $(seq 0 19);
    do
	    # Check if os-san is already running -> We should not do evaluation in that case.
	    if pgrep os-sanitizer
	    then
		    echo -e "\tAnother instance of os-sanitizer is already running! Please close it to run evaluations.";
		    exit 1;
	    fi

    	if [[ $i -lt 10 ]]
		then
		    echo -e "\tWith os-sanitizer run $i and type --$os_san_type"
	        sudo env RUST_LOG=debug /usr/bin/time -v os-sanitizer --${os_san_type} > ../evaluation/microbenchmark/results/os_sanitizer_log_${i}_${os_san_type}_${info_tag} 2>&1 &
	        # wait for os-san to be ready
	        sleep 3
        else
        	echo -e "\tWithout os-sanitizer run $i and file ${microbenchmark_executable}"
    	fi

    	if [ "$os_san_type" = "gets" ]
		then
			yes "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ" | /usr/bin/time -v ./${microbenchmark_executable} > ../evaluation/microbenchmark/results/example_log_${i}_${os_san_type}_${info_tag} 2>&1
		else
			/usr/bin/time -v ./${microbenchmark_executable} > ../evaluation/microbenchmark/results/example_log_${i}_${os_san_type}_${info_tag} 2>&1
		fi

    	if [[ $i -lt 10 ]]
		then
	        # unfinished business?
	        sleep 3
		    sudo pkill os-sanitizer
	    fi

	    # sanity check; to use with #define debug_printf(...) printf(__VA_ARGS__)
	    # will be 0 by default since: #define debug_printf(...) (0)
	    echo -e "\t\tSuccess count: $(cat ../evaluation/microbenchmark/results/example_log_${i}_${os_san_type}_${info_tag} | grep "Success" | wc -l)"
	    echo -e "$(cat ../evaluation/microbenchmark/results/example_log_${i}_${os_san_type}_${info_tag} | grep "Iterations: " | sed 's/^/\t\t/')"
	    echo -e "\t\tMicrobenchmark execution time: $(cat ../evaluation/microbenchmark/results/example_log_${i}_${os_san_type}_${info_tag} | grep "Elapsed (wall clock) time")"

    	if [[ $i -lt 10 ]]
		then
		    # os-san only prints 15 chars of executable name
		    echo -e "\t\tos-san hits: $(cat ../evaluation/microbenchmark/results/os_sanitizer_log_${i}_${os_san_type}_${info_tag} | grep "os_sanitizer] ${microbenchmark_executable:0:15}" | wc -l)"
		    echo -e "\t\tStats: $(cat ../evaluation/microbenchmark/results/os_sanitizer_log_${i}_${os_san_type}_${info_tag} | grep -E -A 10 "${microbenchmark_executable:0:15} .* terminated with the following statistics" | sed 's/^/\t\t\t/')"
	    fi
	    sleep 15 
	    echo -e "\tDone with run $i"
	    echo -e "\t----------------------------------------"
    done
    example_count=$(($example_count+1))
    echo "----------------------------------------"
    echo "----------------------------------------"
done