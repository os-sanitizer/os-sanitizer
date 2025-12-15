// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use core::ffi::c_int;
use core::hash::{Hash, Hasher};

use aya_ebpf::cty::uintptr_t;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf_macros::fentry;

use os_sanitizer_common::OsSanitizerError::Unreachable;
use os_sanitizer_common::{OsSanitizerError, ProgId};

use crate::statistics::update_tracking;
use crate::{read_str, ACCESS_MAP, FLAGGED_FILE_OPEN_PIDS, IGNORED_PIDS};

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
    update_tracking(pid_tgid, ProgId::fentry_do_sys_openat2);

    // we are opening another file; clear the last entry (still exists if the last open failed)
    let _ = FLAGGED_FILE_OPEN_PIDS.remove(&pid_tgid);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    let filename = read_str(usermode_ptr, "openat-filename")?;
    let mut hasher = crate::Hasher::default();
    filename.hash(&mut hasher);
    let hash = hasher.finish();

    if let Some(&access) = ACCESS_MAP.get(&(pid_tgid, dfd as u64, hash)) {
        FLAGGED_FILE_OPEN_PIDS
            .insert(&pid_tgid, &access, 0)
            .map_err(|_| Unreachable("map insertion failure"))?;
    }

    Ok(0)
}
