use crate::ACCESS_MAP;
use aya_ebpf::cty::uintptr_t;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf_macros::fentry;
use core::ffi::c_int;
use os_sanitizer_common::OsSanitizerError;
use os_sanitizer_common::OsSanitizerError::Unreachable;
use os_sanitizer_common::ToctouVariant::Access;

#[fentry(function = "do_faccessat")]
fn fentry_do_faccessat(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_do_faccessat(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_do_faccessat_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_do_faccessat(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    ACCESS_MAP
        .insert(&(pid_tgid, dfd as u64, usermode_ptr as u64), &Access, 0)
        .map_err(|_| Unreachable("map insertion failure"))?;

    Ok(0)
}
