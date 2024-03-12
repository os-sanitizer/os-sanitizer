use core::ffi::c_int;

use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_void, uintptr_t};
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes,
};
use aya_bpf::programs::FEntryContext;
use aya_bpf_macros::fentry;

use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, CouldntRecoverStack, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN};

use crate::{emit_report, read_str, ACCESS_MAP, FLAGGED_FILE_OPEN_PIDS, IGNORED_PIDS, STACK_MAP};

#[fentry(function = "do_sys_openat2")]
fn fentry_do_sys_openat2(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_do_sys_openat2(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_do_sys_openat2_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_do_sys_openat2(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // we are opening another file; clear the last entry (still exists if the last open failed)
    let _ = FLAGGED_FILE_OPEN_PIDS.remove(&pid_tgid);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    if let Some(&variant) = ACCESS_MAP.get(&(pid_tgid, dfd as u64, usermode_ptr as u64)) {
        FLAGGED_FILE_OPEN_PIDS
            .insert(&pid_tgid, &variant, 0)
            .map_err(|_| Unreachable("map insertion failure"))?;
    }

    let mut filename = read_str(usermode_ptr, "openat filename")?;

    let mut executable = [0; EXECUTABLE_LEN];

    // we do this manually because the existing implementation is restricted to 16 bytes
    let res = bpf_get_current_comm(
        executable.as_mut_ptr() as *mut c_void,
        executable.len() as u32,
    );
    if res < 0 {
        return Err(CouldntGetComm("do_sys_openat2", res));
    }

    let stack_id = STACK_MAP
        .get_stackid(ctx, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
        .map_err(|e| CouldntRecoverStack("do_sys_openat2", e))? as u64;

    let uid_gid = bpf_get_current_uid_gid();

    let report = OsSanitizerReport::UncheckedOpen {
        executable,
        pid_tgid,
        uid_gid,
        stack_id,
        dfd: dfd as i64,
        filename,
    };

    emit_report(ctx, &report)?;

    Ok(0)
}
