// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use core::mem::offset_of;

use aya_ebpf::cty::{c_char, c_void, uintptr_t};
use aya_ebpf::helpers::generated::bpf_get_current_comm;
use aya_ebpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid, bpf_get_current_uid_gid};
use aya_ebpf::programs::FEntryContext;
use aya_ebpf_macros::fentry;

use os_sanitizer_common::OpenViolation::{Perms, Toctou};
use os_sanitizer_common::OsSanitizerError::{CouldntAccessBuffer, CouldntGetComm, CouldntGetPath};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, ProgId, EXECUTABLE_LEN};

use crate::binding::file;
use crate::statistics::update_tracking;
use crate::{emit_report, FLAGGED_FILE_OPEN_PIDS, IGNORED_PIDS, STRING_SCRATCH};

#[fentry(function = "security_file_open")]
fn fentry_security_file_open(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_security_file_open(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_security_file_open_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_security_file_open(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, ProgId::fentry_security_file_open);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let data: *const file = ctx.arg(0);

    let inode = (*data).f_inode;
    let i_mode = (*inode).i_mode as u64;

    let variant = if i_mode & 0b010 != 0 && i_mode & 0xF000 != 0xA000 && i_mode & 0x200 == 0 {
        let uid_gid = bpf_get_current_uid_gid();
        let gid = (uid_gid >> 32) as u32;
        let uid = uid_gid as u32;
        if uid == 0x1337 && gid == 0x1337 {
            return Ok(0);
        }
        Perms
    } else if let Some(&(variant, stack_id)) = FLAGGED_FILE_OPEN_PIDS.get(&pid_tgid) {
        let _ = FLAGGED_FILE_OPEN_PIDS.remove(&pid_tgid); // maybe removed by race
        Toctou(variant, stack_id)
    } else {
        return Ok(0);
    };

    let ptr = STRING_SCRATCH
        .get_ptr_mut(1)
        .ok_or(CouldntAccessBuffer("emit-report"))?;
    let filename = &mut *ptr;
    let path = data as uintptr_t + offset_of!(file, f_path);

    let res = bpf_d_path(
        path as *mut aya_ebpf::bindings::path,
        filename.as_mut_ptr() as *mut c_char,
        filename.len() as u32,
    );
    if res < 0 {
        return Err(CouldntGetPath("security_file_open", res));
    }

    if !filename.starts_with(b"/proc")
        && !filename.starts_with(b"/sys")
        && !filename.starts_with(b"/dev")
    {
        let mut executable = [0; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("security_file_open", res));
        }

        let stack_id = crate::report_stack_id(ctx, "security_file_open")?;

        let report = OsSanitizerReport::Open {
            executable,
            pid_tgid,
            stack_id,
            i_mode,
            filename,
            variant,
        };

        emit_report(ctx, &report)?;
    }

    Ok(0)
}
