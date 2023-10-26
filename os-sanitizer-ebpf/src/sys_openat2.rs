use crate::{ACCESS_MAP, FLAGGED_FILE_OPEN_PIDS};
use aya_bpf::cty::uintptr_t;
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::programs::FEntryContext;
use aya_bpf_macros::fentry;
use core::ffi::c_int;
use os_sanitizer_common::OsSanitizerError;
use os_sanitizer_common::OsSanitizerError::Unreachable;

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

    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    if let Some(&variant) = ACCESS_MAP.get(&(pid_tgid, dfd as u64, usermode_ptr as u64)) {
        FLAGGED_FILE_OPEN_PIDS
            .insert(&pid_tgid, &variant, 0)
            .map_err(|_| Unreachable("map insertion failure"))?;
    }

    Ok(0)
}
