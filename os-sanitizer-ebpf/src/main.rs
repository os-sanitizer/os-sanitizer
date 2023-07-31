#![feature(offset_of)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused)]
mod binding;

use crate::binding::file;
use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_char, c_void, uintptr_t};
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid};
use aya_bpf::macros::map;
use aya_bpf::macros::{fentry, uprobe};
use aya_bpf::maps::{PerfEventArray, StackTrace};
use aya_bpf::programs::{FEntryContext, ProbeContext};
use aya_bpf::BpfContext;
use aya_log_ebpf::error;
use core::hint::unreachable_unchecked;
use core::mem::offset_of;
use os_sanitizer_common::OsSanitizerError::*;
use os_sanitizer_common::{FileAccessReport, FunctionInvocationReport, OsSanitizerError};

#[map(name = "FILE_REPORT_QUEUE")]
pub static FILE_REPORT_QUEUE: PerfEventArray<FileAccessReport> =
    PerfEventArray::with_max_entries(1 << 12, 0);

#[map(name = "FUNCTION_REPORT_QUEUE")]
pub static FUNCTION_REPORT_QUEUE: PerfEventArray<FunctionInvocationReport> =
    PerfEventArray::with_max_entries(1 << 12, 0);

#[map(name = "STACKTRACES")]
pub static STACK_MAP: StackTrace = StackTrace::with_max_entries(1 << 12, 0);

#[inline(always)]
fn emit_error<C: BpfContext>(probe: &C, e: OsSanitizerError, name: &str) -> u32 {
    match e {
        MissingArg(op, idx) => {
            error!(probe, "{}: Missing arg {} while handling {}", op, idx, name);
        }
        CouldntReadKernel(op, ptr, _len) => {
            error!(
                probe,
                "{}: Couldn't read kernel address 0x{:x} ({} bytes) while handling {}",
                op,
                ptr,
                len,
                name
            );
        }
        CouldntReadUser(op, ptr, _len) => {
            error!(
                probe,
                "{}: Couldn't read user address 0x{:x} ({} bytes) while handling {}",
                op,
                ptr,
                len,
                name
            );
        }
        CouldntRecoverStack(op, errno) => {
            error!(probe, "{}: Couldn't recover stacktrace: {}", op, errno);
        }
        CouldntGetComm(op, errno) => {
            error!(probe, "{}: Couldn't recover comm: {}", op, errno);
        }
        CouldntAccessBuffer(op) => {
            error!(
                probe,
                "{}: Couldn't access buffer while handling {}", op, name
            );
        }
        InvalidUtf8(op) => {
            error!(
                probe,
                "{}: Encountered invalid UTF8 while handling {}", op, name
            );
        }
        OutOfSpace(op) => {
            error!(probe, "{}: Ran out of space while handling {}", op, name);
        }
        RacefulAccess(op) => {
            error!(
                probe,
                "{}: Performed a raceful operation while handling {}", op, name
            );
        }
        ImpossibleFile => {
            error!(
                probe,
                "Encountered an impossible file while handling {}", name
            );
        }
        Unreachable => {
            error!(
                probe,
                "Encountered an unreachable code block while handling {}", name
            );
        }
    }
    e.into()
}

#[fentry(name = "security_file_open")]
fn fentry_security_file_open(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_security_file_open(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_security_file_open_kprobe"),
    }
}

#[inline(always)]
unsafe fn try_fentry_security_file_open(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let data: *const file = ctx.arg(0);

    let inode = (*data).f_inode;
    let i_mode = (*inode).i_mode;

    if i_mode & 0b010 != 0 && i_mode & 0xF000 != 0xA000 {
        let pid_tgid = bpf_get_current_pid_tgid();

        let mut report = FileAccessReport {
            pid_tgid,
            i_mode,
            filename: [0; 256],
        };

        let len = report.filename.len() as u32;
        let filename_ptr = report.filename.as_mut_ptr() as *mut c_char;
        let path = data as uintptr_t + offset_of!(file, f_path);

        bpf_d_path(path as *mut aya_bpf::bindings::path, filename_ptr, len);

        if !report.filename.starts_with(b"/proc") && !report.filename.starts_with(b"/sys") {
            FILE_REPORT_QUEUE.output(ctx, &report, 0);
        }
    }

    Ok(0)
}

#[uprobe(name = "strcpy")]
fn uprobe_strcpy(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_strcpy(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_strcpy_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_strcpy(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let stack_id = STACK_MAP
        .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
        .map_err(|e| CouldntRecoverStack("strcpy", e))? as u32;

    let mut executable = [0u8; 128];

    // we do this manually because the existing implementation is restricted to 16 bytes
    let res = bpf_get_current_comm(
        executable.as_mut_ptr() as *mut c_void,
        executable.len() as u32,
    );
    if res < 0 {
        return Err(CouldntGetComm("strcpy comm", res));
    }

    let report = FunctionInvocationReport::Strcpy {
        executable,
        stack_id,
    };

    FUNCTION_REPORT_QUEUE.output(probe, &report, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
