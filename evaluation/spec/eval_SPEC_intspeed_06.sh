#!/bin/sh

#
# Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
#
# See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).
#

# Pre run checklist: 1.) os_san_type 2.) update info_tag 3.) for loop iterations 4.) in SPEC_cpu2017 directory
# for runcpu
source shrc

os_san_type=strncpy
info_tag=numer_commit_debug

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

	echo "With os-sanitizer run $i and type --$os_san_type"
    sudo env RUST_LOG=debug /usr/bin/time -v os-sanitizer --${os_san_type} > os_sanitizer_log_${i}_${os_san_type}_${info_tag} 2>&1 &
	/usr/bin/time -v runcpu --config=s_Example-gcc-linux-x86 --reportable intspeed > cpu_intspeed_log_${i}_${os_san_type}_${info_tag} 2>&1
	sudo pkill os-sanitizer
	# pkill takes time. If we don't sleep we exit 1 due to pgrep check.
	sleep 15 
	echo "Done with run $i"
done
