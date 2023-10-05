#![feature(offset_of)]
#![feature(pointer_byte_offsets)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused, clippy::all)]
mod binding;

use crate::binding::{file, filename};
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
use aya_log_ebpf::{debug, error, info, warn};
use core::ffi::c_int;
use core::hint::unreachable_unchecked;
use core::mem::offset_of;
use os_sanitizer_common::CopyViolation::Strlen;
use os_sanitizer_common::OpenViolation::{Perms, Toctou};
use os_sanitizer_common::OsSanitizerError::*;
use os_sanitizer_common::ToctouVariant::{Access, Stat, Statx};
use os_sanitizer_common::{
    CopyViolation, OsSanitizerError, OsSanitizerReport, ToctouVariant, EXECUTABLE_LEN, FILENAME_LEN,
};

#[map(name = "IGNORED_PIDS")]
pub static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1 << 12, 0);

#[map]
pub static FLAGGED_FILE_OPEN_PIDS: LruHashMap<u64, ToctouVariant> =
    LruHashMap::with_max_entries(1 << 12, 0);

#[map(name = "FUNCTION_REPORT_QUEUE")]
pub static FUNCTION_REPORT_QUEUE: PerfEventArray<OsSanitizerReport> =
    PerfEventArray::with_max_entries(1 << 16, 0);

#[map(name = "STACKTRACES")]
pub static STACK_MAP: StackTrace = StackTrace::with_max_entries(1 << 16, 0);

#[inline(always)]
fn emit_error<C: BpfContext>(probe: &C, e: OsSanitizerError, name: &str) -> u32 {
    match e {
        MissingArg(op, idx) => {
            error!(probe, "{}: Missing arg {} while handling {}", op, idx, name);
        }
        CouldntReadKernel(op, ptr, num_bytes) => {
            error!(
                probe,
                "{}: Couldn't read kernel address 0x{:x} ({} bytes) while handling {}",
                op,
                ptr,
                num_bytes,
                name
            );
        }
        CouldntReadUser(op, ptr, num_bytes) => {
            error!(
                probe,
                "{}: Couldn't read user address 0x{:x} ({} bytes) while handling {}",
                op,
                ptr,
                num_bytes,
                name
            );
        }
        CouldntRecoverStack(op, errno) => {
            info!(probe, "{}: Couldn't recover stacktrace: {}", op, errno);
        }
        CouldntGetPath(op, errno) => {
            debug!(probe, "{}: Couldn't recover path: {}", op, errno);
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
            warn!(
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
        Err(e) => emit_error(&probe, e, "os_sanitizer_security_file_open_fentry"),
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

#[map]
static ACCESS_MAP: LruHashMap<(u64, c_int, uintptr_t), ToctouVariant> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[fentry(function = "do_faccessat")]
fn fentry_do_faccessat(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_do_faccessat(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_do_faccessat_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_do_faccessat(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    ACCESS_MAP
        .insert(&(pid_tgid, dfd, usermode_ptr), &Access, 0)
        .map_err(|_| Unreachable("map insertion failure"))?;

    Ok(0)
}

#[fentry(function = "vfs_fstatat")]
fn fentry_vfs_fstatat(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_vfs_fstatat(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_vfs_fstatat_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_vfs_fstatat(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    ACCESS_MAP
        .insert(&(pid_tgid, dfd, usermode_ptr), &Stat, 0)
        .map_err(|_| Unreachable("map insertion failure"))?;

    Ok(0)
}

#[fentry(function = "do_statx")]
fn fentry_do_statx(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_do_statx(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_do_statx_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_do_statx(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dfd: c_int = ctx.arg(0);

    let filename_ptr: *const filename = ctx.arg(1);
    let usermode_ptr = (*filename_ptr).uptr as uintptr_t;

    ACCESS_MAP
        .insert(&(pid_tgid, dfd, usermode_ptr as uintptr_t), &Statx, 0)
        .map_err(|_| Unreachable("map insertion failure"))?;

    Ok(0)
}

#[fentry(function = "do_sys_openat2")]
fn fentry_do_sys_openat2(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_do_sys_openat2(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_do_sys_openat2_fentry"),
    }
}

#[inline(always)]
unsafe fn try_fentry_do_sys_openat2(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // we are opening another file; clear the last entry (still exists if the last open failed)
    let _ = FLAGGED_FILE_OPEN_PIDS.remove(&pid_tgid);

    let dfd: c_int = ctx.arg(0);
    let usermode_ptr: uintptr_t = ctx.arg(1);

    if let Some(&variant) = ACCESS_MAP.get(&(pid_tgid, dfd, usermode_ptr)) {
        FLAGGED_FILE_OPEN_PIDS
            .insert(&pid_tgid, &variant, 0)
            .map_err(|_| Unreachable("map insertion failure"))?;
    }

    Ok(0)
}

#[map]
static STRLEN_PTR_MAP: HashMap<u64, uintptr_t> = HashMap::with_max_entries(1 << 16, 0);

#[map]
static STRLEN_MAP: LruHashMap<(u64, uintptr_t), size_t> = LruHashMap::with_max_entries(1 << 16, 0);

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
        .insert(&(pid_tgid, strptr), &srclen, 0)
        .map_err(|_| Unreachable("we should always be able to insert"))?;

    Ok(0)
}

#[map]
static STRCPY_SAFE_WRAPPED: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_strcpy_safe_wrapper(probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    match STRCPY_SAFE_WRAPPED.insert(&pid_tgid, &0, 0) {
        Ok(_) => 0,
        Err(_) => emit_error(
            &probe,
            Unreachable("Couldn't insert into STRCPY_SAFE_WRAPPED"),
            "uprobe_strcpy_safe_wrapper",
        ),
    }
}

#[uretprobe]
fn uretprobe_strcpy_safe_wrapper(_probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = STRCPY_SAFE_WRAPPED.remove(&pid_tgid); // don't care if this fails
    0
}

#[uprobe]
fn uprobe_strcpy(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_strcpy(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_strcpy_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_strcpy(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    if STRCPY_SAFE_WRAPPED.get(&pid_tgid).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strcpy has a dest pointer"))?;

    let srcptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strcpy has a src pointer"))?;

    if (0x7ff000000000..0x800000000000).contains(&destptr) {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("strcpy", e))? as u64;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("strcpy comm", res));
        }

        let report = OsSanitizerReport::Strcpy {
            executable,
            pid_tgid,
            stack_id,
            dest: destptr,
            src: srcptr,
            len_checked: STRLEN_MAP.get(&(pid_tgid, srcptr)).is_some(),
        };

        FUNCTION_REPORT_QUEUE.output(probe, &report, 0);
    }

    Ok(0)
}

#[map]
static SPRINTF_SAFE_WRAPPED: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_sprintf_safe_wrapper(probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    match SPRINTF_SAFE_WRAPPED.insert(&pid_tgid, &0, 0) {
        Ok(_) => 0,
        Err(_) => emit_error(
            &probe,
            Unreachable("Couldn't insert into SPRINTF_SAFE_WRAPPED"),
            "uprobe_sprintf_safe_wrapper",
        ),
    }
}

#[uretprobe]
fn uretprobe_sprintf_safe_wrapper(_probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SPRINTF_SAFE_WRAPPED.remove(&pid_tgid); // don't care if this fails
    0
}

#[uprobe]
fn uprobe_sprintf(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_sprintf(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_sprintf_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_sprintf(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    if SPRINTF_SAFE_WRAPPED.get(&pid_tgid).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("sprintf has a dest pointer"))?;

    if (0x7ff000000000..0x800000000000).contains(&destptr) {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("sprintf", e))? as u64;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("sprintf comm", res));
        }

        let report = OsSanitizerReport::Sprintf {
            executable,
            pid_tgid,
            stack_id,
            dest: destptr,
        };

        FUNCTION_REPORT_QUEUE.output(probe, &report, 0);
    }

    Ok(0)
}

#[inline(always)]
unsafe fn try_check_bad_copy(
    _probe: &ProbeContext,
    pid_tgid: u64,
    srcptr: uintptr_t,
    src_len: size_t,
) -> Result<Option<(CopyViolation, u64, u64)>, OsSanitizerError> {
    let mut report = None;

    if src_len != 0 && Some(&src_len) == STRLEN_MAP.get(&(pid_tgid, srcptr)) {
        report = Some((Strlen, src_len as u64, 0));
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

    let strptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strncpy has a src pointer"))?;
    let maybe_src_len: size_t = probe
        .arg(2)
        .ok_or(Unreachable("strncpy has a copied size"))?;

    if let Some((variant, copied_len, allocated)) =
        try_check_bad_copy(probe, pid_tgid, strptr, maybe_src_len)?
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

        let report = OsSanitizerReport::Strncpy {
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

    let srcptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strncpy has a src pointer"))?;
    let src_len: size_t = probe
        .arg(2)
        .ok_or(Unreachable("strncpy has a copied size"))?;

    if let Some((variant, len, allocated)) = try_check_bad_copy(probe, pid_tgid, srcptr, src_len)? {
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

        let report = OsSanitizerReport::Memcpy {
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
    }

    Ok(0)
}

macro_rules! always_bad_call {
    ($name: ident, $variant: ident) => {
        ::paste::paste! {
            #[uprobe]
            fn [< uprobe_ $name >](probe: ProbeContext) -> u32 {
                match unsafe { [< try_uprobe_ $name >](&probe) } {
                    Ok(res) => res,
                    Err(e) => emit_error(&probe, e, concat!(concat!("os_sanitizer_", stringify!($name)), "_uprobe")),
                }
            }

            #[inline(always)]
            unsafe fn [< try_uprobe_ $name >](probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
                let pid_tgid = bpf_get_current_pid_tgid();

                if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
                    return Ok(0);
                }

                let stack_id = STACK_MAP
                    .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
                    .map_err(|e| CouldntRecoverStack(stringify!($name), e))? as u64;

                let mut executable = [0u8; EXECUTABLE_LEN];

                // we do this manually because the existing implementation is restricted to 16 bytes
                let res = bpf_get_current_comm(
                    executable.as_mut_ptr() as *mut c_void,
                    executable.len() as u32,
                );
                if res < 0 {
                    return Err(CouldntGetComm(concat!(stringify!($name), " comm"), res));
                }

                let report = OsSanitizerReport::$variant {
                    executable,
                    pid_tgid,
                    stack_id,
                };

                FUNCTION_REPORT_QUEUE.output(probe, &report, 0);

                Ok(0)
            }
        }
    };
}

always_bad_call!(access, Access);
always_bad_call!(gets, Gets);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
