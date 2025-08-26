// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use aya_ebpf::bindings::__u64;
use aya_ebpf::cty::{c_void, uintptr_t};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::generated::bpf_get_current_comm;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf_macros::uprobe;

use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, PassId, EXECUTABLE_LEN};

use crate::statistics::update_tracking;
use crate::{emit_report, read_str, IGNORED_PIDS};

#[inline(always)]
unsafe fn check_system_absolute(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::check_system_absolute);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let command_param: __u64 = probe
        .arg(0)
        .ok_or(Unreachable("system-like has a template parameter"))?;

    let command = read_str(command_param as uintptr_t, "system command")?;

    if !command.trim_ascii_start().starts_with(b"/") {
        let stack_id = crate::report_stack_id(probe, "system-absolute")?;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("system-absolute comm", res));
        }

        let report = OsSanitizerReport::SystemAbsolute {
            executable,
            pid_tgid,
            stack_id,
            command_param,
            command,
        };

        emit_report(probe, &report)?;
    }

    Ok(0)
}

#[uprobe]
fn uprobe_system_absolute(probe: ProbeContext) -> u32 {
    unsafe { check_system_absolute(&probe) }
        .unwrap_or_else(|e| crate::emit_error(&probe, e, "os_sanitizer_system_absolute_uprobe"))
}
