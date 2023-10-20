use crate::binding::file;
use crate::{FLAGGED_FILE_OPEN_PIDS, FUNCTION_REPORT_QUEUE, IGNORED_PIDS, STACK_MAP};
use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_char, c_void, uintptr_t};
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid};
use aya_bpf::programs::FEntryContext;
use aya_bpf_macros::fentry;
use core::mem::offset_of;
use os_sanitizer_common::OpenViolation::{Perms, Toctou};
use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, CouldntGetPath, CouldntRecoverStack};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN, FILENAME_LEN};

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
    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let data: *const file = ctx.arg(0);

    let inode = (*data).f_inode;
    let i_mode = (*inode).i_mode;

    let (variant, toctou) = if i_mode & 0b010 != 0 && i_mode & 0xF000 != 0xA000 {
        (Perms, None)
    } else if let Some(&variant) = FLAGGED_FILE_OPEN_PIDS.get(&pid_tgid) {
        let _ = FLAGGED_FILE_OPEN_PIDS.remove(&pid_tgid); // maybe removed by race

        (Toctou, Some(variant))
    } else {
        return Ok(0);
    };

    let mut filename = [0; FILENAME_LEN];
    let path = data as uintptr_t + offset_of!(file, f_path);

    let res = bpf_d_path(
        path as *mut aya_bpf::bindings::path,
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

        let stack_id = STACK_MAP
            .get_stackid(ctx, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("security_file_open", e))?
            as u64;

        let report = OsSanitizerReport::Open {
            executable,
            pid_tgid,
            stack_id,
            i_mode,
            filename,
            variant,
            toctou,
        };

        FUNCTION_REPORT_QUEUE.output(ctx, &report, 0);
    }

    Ok(0)
}
