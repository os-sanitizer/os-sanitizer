use crate::{read_str, ACCESS_MAP, STACK_MAP};
use aya_ebpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_ebpf::cty::uintptr_t;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf_macros::fentry;
use core::ffi::c_int;
use core::hash::{Hash, Hasher};
use os_sanitizer_common::OsSanitizerError;
use os_sanitizer_common::OsSanitizerError::{CouldntRecoverStack, Unreachable};
use os_sanitizer_common::ToctouVariant::Stat;

#[fentry(function = "vfs_fstatat")]
fn fentry_vfs_fstatat(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_vfs_fstatat(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_vfs_fstatat_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_vfs_fstatat(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    let filename = read_str(usermode_ptr, "faccessat-filename")?;
    let mut hasher = crate::Hasher::default();
    filename.hash(&mut hasher);
    let hash = hasher.finish();

    let stack_id = STACK_MAP
        .get_stackid(ctx, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
        .map_err(|e| CouldntRecoverStack("filep-unlocked", e))? as u64;

    ACCESS_MAP
        .insert(&(pid_tgid, dfd as u64, hash), &(Stat, stack_id), 0)
        .map_err(|_| Unreachable("map insertion failure"))?;

    Ok(0)
}
