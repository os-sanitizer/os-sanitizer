// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use core::ffi::c_void;

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::generated::bpf_get_current_comm;
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf_macros::{map, uprobe};

use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, ProgId, EXECUTABLE_LEN};

use crate::statistics::update_tracking;
use crate::{emit_error, emit_report};

#[map]
static UNLOCKED_USED_FILE_POINTERS: LruHashMap<(u64, u64), u64> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_fclose_unlocked(probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, ProgId::uprobe_fclose_unlocked);
    if let Some(filep) = probe.arg::<u64>(0) {
        // ignore the result; this is only a sanity check
        let _ = UNLOCKED_USED_FILE_POINTERS.remove(&(pid_tgid >> 32, filep));
    }
    0
}

#[inline(always)]
unsafe fn check_filep_usage(probe: &ProbeContext, pid_tgid: u64, filep: u64) {
    update_tracking(pid_tgid, ProgId::check_filep_usage);
    if let Some(&orig_pid_tgid) = UNLOCKED_USED_FILE_POINTERS.get(&(pid_tgid >> 32, filep)) {
        if orig_pid_tgid != pid_tgid {
            #[inline(always)]
            unsafe fn report(probe: &ProbeContext, pid_tgid: u64) -> Result<(), OsSanitizerError> {
                let stack_id = crate::report_stack_id(probe, "filep-unlocked")?;

                let mut executable = [0u8; EXECUTABLE_LEN];

                // we do this manually because the existing implementation is restricted to 16 bytes
                let res = bpf_get_current_comm(
                    executable.as_mut_ptr() as *mut c_void,
                    executable.len() as u32,
                );
                if res < 0 {
                    return Err(CouldntGetComm("filep-unlocked comm", res));
                }

                let report = OsSanitizerReport::FilePointerLocking {
                    executable,
                    pid_tgid,
                    stack_id,
                };

                emit_report(probe, &report)
            }

            if let Err(e) = report(probe, pid_tgid) {
                emit_error(probe, e, "check_filep_usage");
            }
        }
    }
}

macro_rules! define_filep_usage {
    ($index: literal) => {
        ::paste::paste! {
            #[uprobe]
            fn [< uprobe_filep_unlocked_used_arg $index >](probe: ProbeContext) -> u32 {
                let pid_tgid = bpf_get_current_pid_tgid();
                let Some(filep) = probe.arg::<u64>($index) else {
                    return 0;
                };

                unsafe {
                    check_filep_usage(&probe, pid_tgid, filep);
                }

                match UNLOCKED_USED_FILE_POINTERS.insert(&(pid_tgid >> 32, filep), &pid_tgid, 0) {
                    Ok(_) => 0,
                    Err(_) => emit_error(
                        &probe,
                        Unreachable("Couldn't insert into UNLOCKED_USED_FILE_POINTERS"),
                        "filep_unlocked_usage",
                    ),
                }
            }

            #[uprobe]
            fn [< uprobe_filep_locked_used_arg $index >](probe: ProbeContext) -> u32 {
                let pid_tgid = bpf_get_current_pid_tgid();
                let Some(filep) = probe.arg::<u64>($index) else {
                    return 0;
                };

                unsafe {
                    check_filep_usage(&probe, pid_tgid, filep);
                }

                0
            }
        }
    };
}

define_filep_usage!(0);
define_filep_usage!(1);
define_filep_usage!(2);
define_filep_usage!(3);
