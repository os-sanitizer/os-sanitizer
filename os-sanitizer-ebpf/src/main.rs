#![feature(offset_of)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused, clippy::all)]
mod binding;

use crate::binding::file;
use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_char, c_void, size_t, uintptr_t};
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid};
use aya_bpf::macros::map;
use aya_bpf::macros::{fentry, uprobe};
use aya_bpf::maps::{HashMap, LruHashMap, PerfEventArray, StackTrace};
use aya_bpf::programs::{FEntryContext, ProbeContext};
use aya_bpf::BpfContext;
use aya_bpf_macros::uretprobe;
use aya_log_ebpf::error;
use core::hint::unreachable_unchecked;
use core::mem::offset_of;
use os_sanitizer_common::CopyViolation::{Malloc, Strlen};
use os_sanitizer_common::OsSanitizerError::*;
use os_sanitizer_common::{
    approximate_range, CopyViolation, FileAccessReport, FunctionInvocationReport, OsSanitizerError,
    EXECUTABLE_LEN,
};

#[map(name = "IGNORED_PIDS")]
pub static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1 << 12, 0);

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

        if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
            return Ok(0);
        }

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
static STRLEN_MAP: LruHashMap<(u64, uintptr_t, size_t), u8> =
    LruHashMap::with_max_entries(1 << 16, 0);

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

        if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
            return Ok(0);
        }

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
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let srclen: size_t = probe
        .ret()
        .ok_or(Unreachable("strlen has a return value"))?;

    let Some(&strptr) = STRLEN_PTR_MAP.get(&pid_tgid) else {
        return Ok(0);
    };
    STRLEN_PTR_MAP
        .remove(&pid_tgid)
        .map_err(|_| Unreachable("the value existed, so we must be able to remove it"))?;

    STRLEN_MAP
        .insert(&(pid_tgid, strptr, srclen), &0, 0)
        .map_err(|_| Unreachable("we should always be able to insert"))?;

    Ok(0)
}

#[map]
static MALLOC_LEN_MAP: HashMap<u64, size_t> = HashMap::with_max_entries(1 << 16, 0);

#[map]
static MALLOC_MAP: LruHashMap<(u64, uintptr_t), size_t> = LruHashMap::with_max_entries(1 << 16, 0);

#[map]
static MALLOC_APPROX_MAP: LruHashMap<(u64, uintptr_t), uintptr_t> =
    LruHashMap::with_max_entries(1 << 20, 0);

#[map]
static REPORTED_POINTERS: LruHashMap<(u64, uintptr_t), u8> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_malloc(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_malloc(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_malloc_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_malloc(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let malloc_len: size_t = probe
        .arg(0)
        .ok_or(Unreachable("malloc didn't have an argument"))?;

    MALLOC_LEN_MAP
        .insert(&pid_tgid, &malloc_len, 0)
        .map_err(|_| OutOfSpace("malloc map"))?;

    Ok(0)
}

#[uprobe]
fn uprobe_realloc(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_realloc(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_realloc_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_realloc(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let realloc_ptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("malloc didn't have a pointer argument"))?;

    if realloc_ptr == 0 {
        return Ok(0);
    }

    // we do not care if the value was not present
    let _ = MALLOC_MAP.remove(&(pid_tgid, realloc_ptr));

    let realloc_len: size_t = probe
        .arg(1)
        .ok_or(Unreachable("realloc didn't have a len argument"))?;

    MALLOC_LEN_MAP
        .insert(&pid_tgid, &realloc_len, 0)
        .map_err(|_| OutOfSpace("realloc map"))?;

    Ok(0)
}

const MAX_ALLOC_DISCOVERABLE: usize = 1 << 30; // we assume we're not dealing with mallocs > 1GB

fn insert_allocation(
    pid_tgid: u64,
    malloc_ptr: uintptr_t,
    malloc_len: size_t,
) -> Result<(), OsSanitizerError> {
    MALLOC_MAP
        .insert(&(pid_tgid, malloc_ptr), &malloc_len, 0)
        .map_err(|_| Unreachable("should always be able to insert new malloc'd pointer"))?;

    if let Some(approximate) = approximate_range(malloc_ptr, malloc_len) {
        MALLOC_APPROX_MAP
            .insert(&(pid_tgid, approximate), &malloc_ptr, 0)
            .map_err(|_| {
                Unreachable("should always be able to insert new approximated malloc'd pointer")
            })?;
    }

    Ok(())
}

unsafe fn find_allocation(
    pid_tgid: u64,
    sought_ptr: uintptr_t,
) -> Result<Option<(uintptr_t, size_t)>, OsSanitizerError> {
    // fast option: do we know this pointer?
    if let Some(&len) = MALLOC_MAP.get(&(pid_tgid, sought_ptr)) {
        return Ok(Some((sought_ptr, len)));
    }

    // find all power-of-two greater or less than the sought pointer ("is this sought pointer in
    // that allocation?")
    let mut mask = !1;
    let mut distinguisher = 1;
    while mask & MAX_ALLOC_DISCOVERABLE != 0 {
        // if the nth-from-last bit is zero, then there is no difference between nth and n+1nth
        if sought_ptr & distinguisher != 0 {
            let lower = sought_ptr & mask;
            if let Some(&ptr) = MALLOC_APPROX_MAP.get(&(pid_tgid, lower)) {
                if let Some(&len) = MALLOC_MAP.get(&(pid_tgid, ptr)) {
                    let range = ptr..(ptr + len);
                    if range.contains(&sought_ptr) {
                        return Ok(Some((ptr, len)));
                    }
                }
            }

            let upper = lower + !mask + 1;
            if let Some(&ptr) = MALLOC_APPROX_MAP.get(&(pid_tgid, upper)) {
                if let Some(&len) = MALLOC_MAP.get(&(pid_tgid, ptr)) {
                    let range = ptr..(ptr + len);
                    if range.contains(&sought_ptr) {
                        return Ok(Some((ptr, len)));
                    }
                }
            }
        }

        mask <<= 1;
        distinguisher <<= 1;
    }

    Ok(None)
}

#[uretprobe]
fn uretprobe_malloc(probe: ProbeContext) -> u32 {
    match unsafe { try_uretprobe_malloc(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_malloc_uretprobe"),
    }
}

#[inline(always)]
unsafe fn try_uretprobe_malloc(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let malloc_ptr: uintptr_t = probe
        .ret()
        .ok_or(Unreachable("malloc has a return value"))?;

    let Some(&malloc_len) = MALLOC_LEN_MAP.get(&pid_tgid) else {
        return Ok(0);
    };
    MALLOC_LEN_MAP
        .remove(&pid_tgid)
        .map_err(|_| Unreachable("the value existed, so we must be able to remove it"))?;

    insert_allocation(pid_tgid, malloc_ptr, malloc_len)?;

    Ok(0)
}

#[uretprobe]
fn uretprobe_realloc(probe: ProbeContext) -> u32 {
    match unsafe { try_uretprobe_realloc(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_realloc_uretprobe"),
    }
}

#[inline(always)]
unsafe fn try_uretprobe_realloc(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let realloc_ptr: uintptr_t = probe
        .ret()
        .ok_or(Unreachable("realloc has a return value"))?;

    let Some(&realloc_len) = MALLOC_LEN_MAP.get(&pid_tgid) else {
        return Ok(0);
    };
    MALLOC_LEN_MAP
        .remove(&pid_tgid)
        .map_err(|_| Unreachable("the value existed, so we must be able to remove it"))?;

    insert_allocation(pid_tgid, realloc_ptr, realloc_len)?;

    Ok(0)
}

#[inline(always)]
unsafe fn try_check_bad_copy(
    _probe: &ProbeContext,
    pid_tgid: u64,
    destptr: uintptr_t,
    srcptr: uintptr_t,
    src_len: size_t,
) -> Result<Option<(CopyViolation, u64, u64)>, OsSanitizerError> {
    let mut report = None;

    if src_len != 0 {
        let end = destptr + src_len;
        if STRLEN_MAP.get(&(pid_tgid, srcptr, src_len)).is_some() {
            // okay, so this is a strlen => copy, but did we allocate for it?
            if let Some((allocation, allocated_len)) = find_allocation(pid_tgid, destptr)? {
                let allocated_end = allocation + allocated_len;
                if end <= allocated_end {
                    return Ok(None);
                } else {
                    // we allocated, but it was too small
                    report = Some((
                        Malloc,
                        (src_len + (destptr - allocation)) as u64,
                        allocated_len as u64,
                    ))
                }
            } else {
                report = Some((Strlen, src_len as u64, 0));
            }
        } else if let Some((allocation, allocated_len)) = find_allocation(pid_tgid, destptr)? {
            let allocated_end = allocation + allocated_len;
            // okay, so we allocated it, but is it big enough?
            if end > allocated_end {
                report = Some((
                    Malloc,
                    (src_len + (destptr - allocation)) as u64,
                    allocated_len as u64,
                ))
            }
        }
    }

    Ok(report)
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
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strncpy has a dest pointer"))?;

    // skip reported pointers
    if REPORTED_POINTERS
        .get(&((pid_tgid >> 32), destptr))
        .is_some()
    {
        return Ok(0);
    }

    let strptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strncpy has a src pointer"))?;
    let maybe_src_len: size_t = probe
        .arg(2)
        .ok_or(Unreachable("strncpy has a copied size"))?;

    if let Some((variant, copied_len, allocated)) =
        try_check_bad_copy(probe, pid_tgid, destptr, strptr, maybe_src_len)?
    {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("strncpy", e))? as u64;

        let mut executable = [0u8; EXECUTABLE_LEN];

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
            len: copied_len,
            allocated,
            dest: destptr,
            src: strptr,
            variant,
        };

        FUNCTION_REPORT_QUEUE.output(probe, &report, 0);
        REPORTED_POINTERS
            .insert(&((pid_tgid >> 32), destptr), &0, 0)
            .map_err(|_| Unreachable("strncpy reported pointer insertion failed"))?;
    }

    Ok(0)
}

#[uprobe]
fn uprobe_memcpy(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_memcpy(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_memcpy_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_memcpy(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strncpy has a dest pointer"))?;

    // skip reported pointers
    if REPORTED_POINTERS
        .get(&((pid_tgid >> 32), destptr))
        .is_some()
    {
        return Ok(0);
    }

    let srcptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strncpy has a src pointer"))?;
    let src_len: size_t = probe
        .arg(2)
        .ok_or(Unreachable("strncpy has a copied size"))?;

    if let Some((variant, len, allocated)) =
        try_check_bad_copy(probe, pid_tgid, destptr, srcptr, src_len)?
    {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("memcpy", e))? as u64;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("memcpy comm", res));
        }

        let report = FunctionInvocationReport::Memcpy {
            executable,
            pid_tgid,
            stack_id,
            len,
            allocated,
            dest: destptr,
            src: srcptr,
            variant,
        };

        FUNCTION_REPORT_QUEUE.output(probe, &report, 0);

        REPORTED_POINTERS
            .insert(&((pid_tgid >> 32), destptr), &0, 0)
            .map_err(|_| Unreachable("memcpy reported pointer insertion failed"))?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
