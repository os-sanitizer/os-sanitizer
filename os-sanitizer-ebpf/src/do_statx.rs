use core::ffi::c_int;
use core::hash::{Hash, Hasher};

use aya_ebpf::cty::uintptr_t;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf_macros::fentry;

use os_sanitizer_common::OsSanitizerError;
use os_sanitizer_common::OsSanitizerError::Unreachable;
use os_sanitizer_common::ToctouVariant::Statx;

use crate::binding::filename;
use crate::{read_str, ACCESS_MAP};

#[fentry(function = "do_statx")]
fn fentry_do_statx(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_do_statx(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_do_statx_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_do_statx(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: c_int = ctx.arg(0);

    let filename_ptr: *const filename = ctx.arg(1);
    if !filename_ptr.is_null() {
        let usermode_ptr = (*filename_ptr).uptr as uintptr_t;

        let filename = read_str(usermode_ptr, "statx-filename")?;
        let mut hasher = crate::Hasher::default();
        filename.hash(&mut hasher);
        let hash = hasher.finish();

        let stack_id = crate::report_stack_id(ctx, "filep-unlocked")?;

        ACCESS_MAP
            .insert(&(pid_tgid, dfd as u64, hash), &(Statx, stack_id), 0)
            .map_err(|_| Unreachable("map insertion failure"))?;
    }

    Ok(0)
}
