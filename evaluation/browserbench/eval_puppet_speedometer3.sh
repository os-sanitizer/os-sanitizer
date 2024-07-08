#!/bin/bash

# Pre run checklist: 1.) os_san_option 2.) for loop iterations

os_san_option=("access" "gets" "rwx-mem" "memcpy" "security-file-open" "strncpy" "strcpy" "sprintf" "snprintf" "printf-mutability" "system-mutability" "system-absolute" "filep-unlocked" "fixed-mmap" "interceptable-path" "all" "none")
info_tag=02_1765c4d_debug

for os_san_type in "${os_san_option[@]}"; 
do
    echo "os-san type $os_san_type"
    # 5 benchmark run with os-san
    for i in $(seq 0 9);
    do
	    echo "Iteration $i"
	    # Check if os-san is already running -> We should not do evaluation in that case.
	    if pgrep os-sanitizer
	    then
		    echo "Another instance of os-sanitizer is already running! Please close it to run evaluations.";
		    exit 1;
	    fi

	    if [[ "os_san_type" == "none" ]]; then
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
