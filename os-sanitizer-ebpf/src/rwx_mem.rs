// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use core::ffi::c_void;

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::gen::bpf_get_current_comm;
use aya_ebpf::programs::FEntryContext;
use aya_ebpf_macros::fentry;

use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, UnexpectedNull};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, PassId, EXECUTABLE_LEN};

use crate::binding::vm_area_struct;
use crate::statistics::update_tracking;
use crate::{access_vm_end, access_vm_flags, access_vm_start, emit_report, IGNORED_PIDS};

#[fentry(function = "vma_set_page_prot")]
fn fentry_vma_set_page_prot(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_vma_set_page_prot(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_vma_set_page_prot_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_vma_set_page_prot(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fentry_vma_set_page_prot);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let vma = ctx.arg::<*const vm_area_struct>(0);

    let vma = vma
        .as_ref()
        .ok_or(UnexpectedNull("VMA provided was null"))?;
    let start = access_vm_start(vma);
    let end = access_vm_end(vma);
    let vm_flags = access_vm_flags(vma);

    // if writable and executable
    if (vm_flags & 0x00000002) != 0 && (vm_flags & 0x00000004) != 0 {
        let stack_id = crate::report_stack_id(ctx, "rwx-vma")?;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("rwx-vma comm", res));
        }

        let report = OsSanitizerReport::RwxVma {
            executable,
            pid_tgid,
            stack_id,
            start,
            end,
        };

        emit_report(ctx, &report)?;
    }

    Ok(0)
}
