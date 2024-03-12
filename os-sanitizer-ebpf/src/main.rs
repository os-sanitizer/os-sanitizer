#![feature(byte_slice_trim_ascii)]
#![no_std]
#![no_main]

use core::ffi::c_ulong;
use core::hint::unreachable_unchecked;

use aya_ebpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_ebpf::cty::{c_void, size_t, uintptr_t};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::gen::{bpf_get_current_comm, bpf_probe_read_user_str};
use aya_ebpf::macros::map;
use aya_ebpf::macros::uprobe;
use aya_ebpf::maps::{HashMap, LruHashMap, PerCpuArray, PerfEventArray, StackTrace};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::{memset, EbpfContext};
use aya_log_ebpf::{error, info, log, warn, Level};

use crate::binding::vm_area_struct;
use os_sanitizer_common::CopyViolation::Strlen;
use os_sanitizer_common::OsSanitizerError::*;
use os_sanitizer_common::{
    CopyViolation, MaybeOwnedArray, OsSanitizerError, OsSanitizerReport, ToctouVariant,
    EXECUTABLE_LEN, SERIALIZED_SIZE, USERSTR_LEN,
};

use crate::strlen::STRLEN_MAP;

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused, clippy::all)]
mod binding;
mod do_faccessat;
mod do_statx;
mod filep_unlocked;
mod fixed_mmap;
mod memcpy;
mod printf_mutability;
mod rwx_mem;
mod security_file_open;
mod snprintf;
mod sprintf;
mod strcpy;
mod strlen;
mod strncpy;
mod sys_openat2;
mod system_absolute;
mod system_mutability;
mod vfs_fstatat;

#[map(name = "IGNORED_PIDS")]
pub static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1 << 12, 0);

#[map]
pub static FLAGGED_FILE_OPEN_PIDS: LruHashMap<u64, ToctouVariant> =
    LruHashMap::with_max_entries(1 << 12, 0);

#[map(name = "FUNCTION_REPORT_QUEUE")]
pub static FUNCTION_REPORT_QUEUE: PerfEventArray<[u8; SERIALIZED_SIZE]> =
    PerfEventArray::with_max_entries(1 << 20, 0);

#[map(name = "STACKTRACES")]
pub static STACK_MAP: StackTrace = StackTrace::with_max_entries(1 << 20, 0);

#[inline(always)]
fn emit_error<C: EbpfContext>(probe: &C, e: OsSanitizerError, name: &str) -> u32 {
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
        CouldntReadUser(op, ptr, num_bytes, e) => {
            let level = if e == -14 { Level::Debug } else { Level::Error };
            log!(
                probe,
                level,
                "{}: Couldn't read user address 0x{:x} ({} bytes) while handling {} ({})",
                op,
                ptr,
                num_bytes,
                name,
                e
            );
        }
        CouldntRecoverStack(op, errno) => {
            info!(probe, "{}: Couldn't recover stacktrace: {}", op, errno);
        }
        CouldntGetPath(op, errno) => {
            info!(probe, "{}: Couldn't recover path: {}", op, errno);
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
        CouldntFindVma(op, errno, pid, tgid) => {
            // this is noisy
            info!(
                probe,
                "Failed to find VMA for an address in pid {} (tgid: {}) while handling {}: {} ({})",
                pid,
                tgid,
                name,
                op,
                errno
            );
        }
        UnexpectedNull(op) => {
            error!(
                probe,
                "Unexpected null pointer while handling {}: {}", name, op, errno
            );
        }
        SerialisationError(op) => {
            error!(probe, "Couldn't serialise {}: {}", name, op);
        }
    }
    e.into()
}

#[map]
static ACCESS_MAP: LruHashMap<(u64, u64, u64), ToctouVariant> =
    LruHashMap::with_max_entries(1 << 16, 0);

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

#[map]
pub static REPORT_SCRATCH: PerCpuArray<[u8; SERIALIZED_SIZE]> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub static STRING_SCRATCH: PerCpuArray<[u8; USERSTR_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
pub(crate) unsafe fn read_str(
    usermode_ptr: uintptr_t,
    op: &'static str,
) -> Result<MaybeOwnedArray<u8, USERSTR_LEN>, OsSanitizerError> {
    let ptr = STRING_SCRATCH
        .get_ptr_mut(0)
        .ok_or(CouldntAccessBuffer("emit-report"))?;
    let buf = &mut *ptr;
    memset(buf.as_mut_ptr(), 0, buf.len());
    let mut res = -1;
    for _ in 0..32 {
        res = bpf_probe_read_user_str(
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            usermode_ptr as *const c_void,
        );
        if res >= 0 {
            break;
        }
    }

    if res < 0 {
        Err(CouldntReadUser(op, usermode_ptr as u64, 0, res))
    } else {
        Ok(buf)
    }
}

#[inline(always)]
pub(crate) unsafe fn emit_report<C: EbpfContext>(
    ctx: &C,
    report: &OsSanitizerReport,
) -> Result<(), OsSanitizerError> {
    let ptr = REPORT_SCRATCH
        .get_ptr_mut(0)
        .ok_or(CouldntAccessBuffer("emit-report"))?;
    let buf = &mut *ptr;
    report
        .serialise_into(buf)
        .map_err(|_| SerialisationError("emit-report"))?;
    FUNCTION_REPORT_QUEUE.output(ctx, buf, 0);
    Ok(())
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

                $crate::emit_report(probe, &report)?;

                Ok(0)
            }
        }
    };
}

always_bad_call!(access, Access);
always_bad_call!(gets, Gets);

// helpers for different emitted bindgen results
#[cfg(feature = "anon-struct")]
#[inline(always)]
unsafe fn access_vm_flags(vm_area: &vm_area_struct) -> binding::vm_flags_t {
    vm_area.__bindgen_anon_2.vm_flags
}
#[cfg(not(feature = "anon-struct"))]
#[inline(always)]
fn access_vm_flags(vm_area: &vm_area_struct) -> u64 {
    vm_area.vm_flags
}
#[cfg(feature = "anon-struct")]
#[inline(always)]
unsafe fn access_vm_start(vm_area: &vm_area_struct) -> c_ulong {
    vm_area.__bindgen_anon_1.__bindgen_anon_1.vm_start
}
#[cfg(not(feature = "anon-struct"))]
#[inline(always)]
fn access_vm_start(vm_area: &vm_area_struct) -> c_ulong {
    vm_area.vm_start
}
#[cfg(feature = "anon-struct")]
#[inline(always)]
unsafe fn access_vm_end(vm_area: &vm_area_struct) -> c_ulong {
    vm_area.__bindgen_anon_1.__bindgen_anon_1.vm_end
}
#[cfg(not(feature = "anon-struct"))]
#[inline(always)]
fn access_vm_end(vm_area: &vm_area_struct) -> c_ulong {
    vm_area.vm_end
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
