#![feature(offset_of)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused)]
mod binding;

use crate::binding::{file, pid};
use aya_bpf::bindings::bpf_map_type::BPF_MAP_TYPE_LRU_HASH;
use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_char, c_void, size_t, uintptr_t};
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read};
use aya_bpf::macros::map;
use aya_bpf::macros::{fentry, uprobe};
use aya_bpf::maps::{Array, HashMap, LruHashMap, PerfEventArray, StackTrace};
use aya_bpf::programs::{FEntryContext, ProbeContext};
use aya_bpf::BpfContext;
use aya_bpf_macros::uretprobe;
use aya_log_ebpf::{error, info};
use core::hint::unreachable_unchecked;
use core::mem::{offset_of, size_of};
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
        Unreachable(condition) => {
            error!(
                probe,
                "Encountered an unreachable code block while handling {}: {}", name, condition
            );
        }
    }
    e.into()
}

#[fentry(function = "security_file_open")]
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

#[map]
static STRLEN_PTR_MAP: HashMap<u64, uintptr_t> = HashMap::with_max_entries(1 << 16, 0);

#[map]
static STRLEN_MAP: LruHashMap<(uintptr_t, size_t), u8> = LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_strlen(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_strlen(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_strlen_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_strlen(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let strptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strlen didn't have an argument"))?;

    if strptr != 0 {
        let pid_tgid = bpf_get_current_pid_tgid();

        STRLEN_PTR_MAP
            .insert(&pid_tgid, &strptr, 0)
            .map_err(|_| OutOfSpace("strlen map"))?;
    }

    Ok(0)
}

#[uretprobe]
fn uretprobe_strlen(probe: ProbeContext) -> u32 {
    match unsafe { try_uretprobe_strlen(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_strlen_uretprobe"),
    }
}

#[inline(always)]
unsafe fn try_uretprobe_strlen(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let srclen: size_t = probe
        .ret()
        .ok_or(Unreachable("strlen has a return value"))?;

    let pid_tgid = bpf_get_current_pid_tgid();

    let Some(&strptr) = STRLEN_PTR_MAP.get(&pid_tgid) else {
        return Ok(0);
    };
    STRLEN_PTR_MAP
        .remove(&pid_tgid)
        .map_err(|_| Unreachable("the value existed, so we must be able to remove it"))?;

    STRLEN_MAP
        .insert(&(strptr, srclen), &0, 0)
        .map_err(|_| Unreachable("we should always be able to insert"))?;

    Ok(0)
}

#[uprobe]
fn uprobe_strncpy(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_strncpy(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_strncpy_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_strncpy(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let strptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strncpy has a src pointer"))?;
    let maybe_src_len: size_t = probe
        .arg(2)
        .ok_or(Unreachable("strncpy has a copied size"))?;

    let pid_tgid = bpf_get_current_pid_tgid();

    if STRLEN_MAP.get(&(strptr, maybe_src_len)).is_some() {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("strncpy", e))? as u64;

        let mut executable = [0u8; 128];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("strncpy comm", res));
        }

        let report = FunctionInvocationReport::Strncpy {
            executable,
            pid_tgid,
            stack_id,
        };

        FUNCTION_REPORT_QUEUE.output(probe, &report, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
