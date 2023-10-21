#![feature(offset_of)]
#![feature(pointer_byte_offsets)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused, clippy::all)]
mod binding;
mod do_faccessat;
mod do_statx;
mod memcpy;
mod printf_mutability;
mod security_file_open;
mod sprintf;
mod strcpy;
mod strlen;
mod strncpy;
mod sys_openat2;
mod vfs_fstatat;

use crate::strlen::STRLEN_MAP;
use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_void, size_t, uintptr_t};
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::macros::map;
use aya_bpf::macros::uprobe;
use aya_bpf::maps::{HashMap, LruHashMap, PerfEventArray, StackTrace};
use aya_bpf::programs::ProbeContext;
use aya_bpf::BpfContext;
use aya_log_ebpf::{debug, error, info, warn};
use core::ffi::c_int;
use core::hint::unreachable_unchecked;
use os_sanitizer_common::CopyViolation::Strlen;
use os_sanitizer_common::OsSanitizerError::*;
use os_sanitizer_common::{
    CopyViolation, OsSanitizerError, OsSanitizerReport, ToctouVariant, EXECUTABLE_LEN,
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
        CouldntFindVma(op, errno, pid, tgid) => {
            error!(
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
    }
    e.into()
}

#[map]
static ACCESS_MAP: LruHashMap<(u64, c_int, uintptr_t), ToctouVariant> =
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
