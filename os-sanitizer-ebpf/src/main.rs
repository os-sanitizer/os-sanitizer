#![feature(offset_of)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused)]
mod binding;

use crate::binding::nameidata;
use aya_bpf::bindings::BPF_F_NO_PREALLOC;
use aya_bpf::cty::uintptr_t;
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use aya_bpf::macros::kprobe;
use aya_bpf::macros::map;
use aya_bpf::maps::HashMap;
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::{error, info, warn};
use core::hint::unreachable_unchecked;
use core::mem::size_of;
use os_sanitizer_common::OsSanitizerError;

use os_sanitizer_common::OsSanitizerError::{
    CouldntAccessBuffer, CouldntReadKernel, CouldntReadUser, ImpossibleFile, InvalidUtf8,
    MissingArg, OutOfSpace, RacefulAccess, Unreachable,
};

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

#[repr(C)]
pub struct FilenameBuf {
    pub buf: [u8; 1024],
}

static EMPTY_FILENAME_BUF: FilenameBuf = FilenameBuf { buf: [0; 1024] };

#[map]
pub static mut FILENAME_BUF: HashMap<u64, FilenameBuf> =
    HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

unsafe fn do_read_kernel<T>(name: &'static str, ptr: *const T) -> Result<T, OsSanitizerError> {
    bpf_probe_read_kernel(ptr)
        .map_err(|_| CouldntReadKernel(name, ptr as uintptr_t, size_of::<T>()))
}

unsafe fn do_read_kernel_str_bytes(
    name: &'static str,
    src: *const u8,
    dest: &mut [u8],
) -> Result<(), OsSanitizerError> {
    match bpf_probe_read_kernel_str_bytes(src, dest) {
        Ok(_) => Ok(()),
        Err(_) => Err(CouldntReadKernel(name, src as uintptr_t, dest.len())),
    }
}

unsafe fn try_kprobe_complete_walk_empty(ctx: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let data: *const nameidata = ctx.arg(0).ok_or(MissingArg("nameidata", 0))?;

    let inode = do_read_kernel("d_inode", &(*data).inode)?;
    let i_mode = do_read_kernel("i_mode", &(*inode).i_mode)?;

    let filetype = i_mode >> 12;

    let filetype = if filetype == 0x1 {
        "fifo"
    } else if filetype == 0x4 {
        "directory"
    } else if filetype == 0x8 {
        "regular file"
    } else if filetype == 0xC {
        "socket"
    } else {
        return Ok(0);
    };

    let filename = do_read_kernel("filename*", &(*data).name)?;
    let filename = do_read_kernel("filename char*", &(*filename).name)? as *const u8;

    let mut rendered = [0u8; 9];

    let mut ctr = 0;
    for i in (0..3).rev() {
        let base = i_mode >> (i * 3);
        rendered[ctr] = if base & 0b100 != 0 { b'r' } else { b'-' };
        ctr += 1;
        rendered[ctr] = if base & 0b010 != 0 { b'w' } else { b'-' };
        ctr += 1;
        rendered[ctr] = if base & 0b001 != 0 { b'x' } else { b'-' };
        ctr += 1;
    }

    let rendered_ref = core::str::from_utf8_unchecked(&rendered);

    let pid_tgid = bpf_get_current_pid_tgid();

    let FilenameBuf { buf } = {
        FILENAME_BUF
            .insert(&pid_tgid, &EMPTY_FILENAME_BUF, 0)
            .map_err(|_| OutOfSpace("filename buf"))?;
        let ptr = FILENAME_BUF
            .get_ptr_mut(&pid_tgid)
            .ok_or(CouldntAccessBuffer("filename"))?;
        &mut *ptr
    };
    do_read_kernel_str_bytes("name", filename, buf)?;
    let name_ref = core::str::from_utf8_unchecked(buf);
    if i_mode & 0b010 != 0 {
        warn!(
            ctx,
            r#"pid {} requested `{}' which has mode {} and is a {}"#,
            pid_tgid as u32,
            // i_ino,
            name_ref,
            rendered_ref,
            filetype
        );
    } else {
        info!(
            ctx,
            r#"pid {} requested `{}' which has mode {} and is a {}"#,
            pid_tgid as u32,
            // i_ino,
            name_ref,
            rendered_ref,
            filetype
        );
    }
    FILENAME_BUF
        .remove(&pid_tgid)
        .map_err(|_| RacefulAccess("name removal"))?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
