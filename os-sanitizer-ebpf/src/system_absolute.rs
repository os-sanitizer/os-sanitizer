use aya_bpf::bindings::{__u64, BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::c_void;
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::helpers::gen::{bpf_get_current_comm, bpf_probe_read_user_str};
use aya_bpf::programs::ProbeContext;
use aya_bpf_macros::uprobe;

use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, CouldntRecoverStack, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN, TEMPLATE_LEN};

use crate::{emit_report, IGNORED_PIDS, STACK_MAP};

#[inline(always)]
unsafe fn check_system_absolute(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let command_param: __u64 = probe
        .arg(0)
        .ok_or(Unreachable("system-like has a template parameter"))?;

    let mut command = [0u8; TEMPLATE_LEN];
    bpf_probe_read_user_str(
        command.as_mut_ptr() as *mut c_void,
        TEMPLATE_LEN as u32,
        command_param as _,
    );

    if !command.trim_ascii_start().starts_with(b"/") {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("system-absolute", e))? as u64;

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
