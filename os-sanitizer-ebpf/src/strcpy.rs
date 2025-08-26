// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use aya_ebpf::cty::{c_void, uintptr_t};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::generated::bpf_get_current_comm;
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf_macros::{map, uprobe, uretprobe};

use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, PassId, EXECUTABLE_LEN};

use crate::statistics::update_tracking;
use crate::{emit_report, IGNORED_PIDS, STRLEN_MAP};

#[map]
static STRCPY_SAFE_WRAPPED: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_strcpy_safe_wrapper(probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uprobe_strcpy_safe_wrapper);

    match STRCPY_SAFE_WRAPPED.insert(&pid_tgid, &0, 0) {
        Ok(_) => 0,
        Err(_) => crate::emit_error(
            &probe,
            Unreachable("Couldn't insert into STRCPY_SAFE_WRAPPED"),
            "uprobe_strcpy_safe_wrapper",
        ),
    }
}

#[uretprobe]
fn uretprobe_strcpy_safe_wrapper(_probe: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uretprobe_strcpy_safe_wrapper);

    let _ = STRCPY_SAFE_WRAPPED.remove(&pid_tgid); // don't care if this fails
    0
}

#[uprobe]
fn uprobe_strcpy(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_strcpy(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_strcpy_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_strcpy(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uprobe_strcpy);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    if STRCPY_SAFE_WRAPPED.get(&pid_tgid).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strcpy has a dest pointer"))?;

    let srcptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strcpy has a src pointer"))?;

    if (0x7ff000000000..0x800000000000).contains(&destptr) {
        let stack_id = crate::report_stack_id(probe, "strcpy")?;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("strcpy comm", res));
        }

        let report = OsSanitizerReport::Strcpy {
            executable,
            pid_tgid,
            stack_id,
            dest: destptr as u64,
            src: srcptr as u64,
            len_checked: STRLEN_MAP.get(&(pid_tgid, srcptr)).is_some(),
        };

        emit_report(probe, &report)?;
    }

    Ok(0)
}
