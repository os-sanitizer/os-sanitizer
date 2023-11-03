use crate::{emit_error, FUNCTION_REPORT_QUEUE, STACK_MAP};
use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::ProbeContext;
use aya_bpf_macros::{map, uprobe};
use core::ffi::c_void;
use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, CouldntRecoverStack, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN};

#[map]
static UNLOCKED_USED_FILE_POINTERS: LruHashMap<(u64, u64), u64> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[inline(always)]
unsafe fn check_filep_usage(probe: &ProbeContext, pid_tgid: u64, filep: u64) {
    if let Some(&orig_pid_tgid) =
        UNLOCKED_USED_FILE_POINTERS.get(&((pid_tgid as u32) as u64, filep))
    {
        if orig_pid_tgid != pid_tgid {
            #[inline(always)]
            unsafe fn report(probe: &ProbeContext, pid_tgid: u64) -> Result<(), OsSanitizerError> {
                let stack_id = STACK_MAP
                    .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
                    .map_err(|e| CouldntRecoverStack("printf-mutability", e))?
                    as u64;

                let mut executable = [0u8; EXECUTABLE_LEN];

                // we do this manually because the existing implementation is restricted to 16 bytes
                let res = bpf_get_current_comm(
                    executable.as_mut_ptr() as *mut c_void,
                    executable.len() as u32,
                );
                if res < 0 {
                    return Err(CouldntGetComm("sprintf comm", res));
                }

                let report =
                    OsSanitizerReport::zeroed_init(|| OsSanitizerReport::FilePointerLocking {
                        executable,
                        pid_tgid,
                        stack_id,
                    });

                FUNCTION_REPORT_QUEUE.output(probe, &report, 0);
                Ok(())
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

                match UNLOCKED_USED_FILE_POINTERS.insert(&((pid_tgid as u32) as u64, filep), &pid_tgid, 0) {
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
