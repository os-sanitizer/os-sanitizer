#!/bin/bash

#
# Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
#
# See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).
#

# Pre run checklist: 1.) os_san_option 2.) update info_tag 3.) for loop iterations

os_san_option=("access" "gets" "rwx-mem" "memcpy" "security-file-open" "strncpy" "strcpy" "sprintf" "snprintf" "printf-mutability" "system-mutability" "system-absolute" "filep-unlocked" "fixed-mmap" "interceptable-path" "reference-policy" "all" "none")
info_tag=numer_commit_debug

for os_san_type in "${os_san_option[@]}"; 
do
    echo "os-san type $os_san_type"
    # 10 benchmark runs with different os-san options (including none)
    for i in $(seq 0 9);
    do
	    echo "Iteration $i"
	    # Check if os-san is already running -> We should not do evaluation in that case.
	    while pgrep os-sanitizer
	    do
		    echo "Another instance of os-sanitizer is already running! Please close it to run evaluations.";
		    sudo pkill os-sanitizer
                    sleep 10
	    done

	    if [[ "$os_san_type" == "none" ]]; then
		    echo "Without os-sanitizer run $i"
		    /usr/bin/time -v node speedometer3_run.js > results/speedometer_log_${i}_${os_san_type}_${info_tag} 2>&1  		
    	else
		    echo "With os-sanitizer run $i and type --$os_san_type"
	        sudo env RUST_LOG=debug /usr/bin/time -v os-sanitizer --${os_san_type} > results/os_sanitizer_log_${i}_${os_san_type}_${info_tag} 2>&1 &
	        sleep 1
		    /usr/bin/time -v node speedometer3_run.js > results/speedometer_log_${i}_${os_san_type}_${info_tag} 2>&1
		    sleep 1
		    sudo pkill os-sanitizer    		
		fi
	    mv speedometer_results.json results/speedometer_results_${i}_${os_san_type}_${info_tag}.json
	    # pkill takes time. If we don't sleep we exit 1 due to pgrep check on the top
	    sleep 15 
	    echo "Done with run $i"
    done
done
