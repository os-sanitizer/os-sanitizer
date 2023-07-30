#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused)]
mod binding;

use crate::binding::nameidata;
use aya_bpf::cty::uintptr_t;
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use aya_bpf::macros::kprobe;
use aya_bpf::macros::map;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::error;
use core::hint::unreachable_unchecked;
use core::mem::size_of;
use os_sanitizer_common::{OsSanitizerError, Report};

use os_sanitizer_common::OsSanitizerError::{
    CouldntAccessBuffer, CouldntReadKernel, CouldntReadUser, ImpossibleFile, InvalidUtf8,
    MissingArg, OutOfSpace, RacefulAccess, Unreachable,
};

#[map(name = "REPORT_QUEUE")]
pub static REPORT_QUEUE: PerfEventArray<Report> = PerfEventArray::with_max_entries(1024, 0);

#[inline(always)]
fn emit_error(probe: &ProbeContext, e: OsSanitizerError, name: &str) -> u32 {
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

#[kprobe(name = "os_sanitizer_complete_walk_kprobe")]
fn kprobe_complete_walk_empty(probe: ProbeContext) -> u32 {
    match unsafe { try_kprobe_complete_walk_empty(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_complete_walk_kprobe"),
    }
}

unsafe fn do_read_kernel<T>(name: &'static str, ptr: *const T) -> Result<T, OsSanitizerError> {
    bpf_probe_read_kernel(ptr)
        .map_err(|_| CouldntReadKernel(name, ptr as uintptr_t, size_of::<T>()))
}

unsafe fn do_read_kernel_str_bytes<'a>(
    name: &'static str,
    src: *const u8,
    dest: &'a mut [u8],
) -> Result<&'a [u8], OsSanitizerError> {
    match bpf_probe_read_kernel_str_bytes(src, dest) {
        Ok(arr) => Ok(arr),
        Err(_) => Err(CouldntReadKernel(name, src as uintptr_t, 0)),
    }
}

unsafe fn try_kprobe_complete_walk_empty(ctx: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let data: *const nameidata = ctx.arg(0).ok_or(MissingArg("nameidata", 0))?;

    let inode = do_read_kernel("d_inode", &(*data).inode)?;
    let i_mode = do_read_kernel("i_mode", &(*inode).i_mode)?;

    let filename = do_read_kernel("filename*", &(*data).name)?;
    let filename = do_read_kernel("filename char*", &(*filename).name)? as *const u8;

    let pid_tgid = bpf_get_current_pid_tgid();

    let mut report = Report {
        pid_tgid,
        i_mode,
        filename: [0; 128],
    };

    do_read_kernel_str_bytes("filename", filename, &mut report.filename)?;

    REPORT_QUEUE.output(ctx, &report, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
