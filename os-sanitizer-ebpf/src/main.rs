#![feature(offset_of)]
#![no_std]
#![no_main]

#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[allow(nonstandard_style, unused)]
mod binding;

use crate::binding::{dentry, inode, path};
use aya_bpf::bindings::{bpf_spin_lock, BPF_F_NO_PREALLOC};
use aya_bpf::cty::uintptr_t;
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes, bpf_spin_lock,
    bpf_spin_unlock,
};
use aya_bpf::macros::{btf_tracepoint, map};
use aya_bpf::macros::{kprobe, kretprobe};
use aya_bpf::maps::{Array, HashMap, PerCpuArray};
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::{error, info};
use core::hint::unreachable_unchecked;
use core::mem::size_of;
use os_sanitizer_common::OsSanitizerError;

use os_sanitizer_common::OsSanitizerError::{
    COULDNT_ACCESS_BUFFER, COULDNT_READ_KERNEL, COULDNT_READ_USER, IMPOSSIBLE_FILE, INVALID_UTF8,
    MISSING_ARG, OUT_OF_SPACE, RACEFUL_ACCESS,
};

#[inline(always)]
fn emit_error(probe: &ProbeContext, e: OsSanitizerError, name: &str) -> u32 {
    match e {
        MISSING_ARG(op, idx) => {
            error!(probe, "{}: Missing arg {} while handling {}", op, idx, name);
        }
        COULDNT_READ_KERNEL(op, ptr, len) => {
            error!(
                probe,
                "{}: Couldn't read kernel address 0x{:x} ({} bytes) while handling {}",
                op,
                ptr,
                len,
                name
            );
        }
        COULDNT_READ_USER(op, ptr, len) => {
            error!(
                probe,
                "{}: Couldn't read user address 0x{:x} ({} bytes) while handling {}",
                op,
                ptr,
                len,
                name
            );
        }
        COULDNT_ACCESS_BUFFER(op) => {
            error!(
                probe,
                "{}: Couldn't access buffer while handling {}", op, name
            );
        }
        INVALID_UTF8(op) => {
            error!(
                probe,
                "{}: Encountered invalid UTF8 while handling {}", op, name
            );
        }
        OUT_OF_SPACE(op) => {
            error!(probe, "{}: Ran out of space while handling {}", op, name);
        }
        RACEFUL_ACCESS(op) => {
            error!(
                probe,
                "{}: Performed a raceful operation while handling {}", op, name
            );
        }
        IMPOSSIBLE_FILE => {
            error!(
                probe,
                "Encountered an impossible file while handling {}", name
            );
        }
    }
    e.into()
}

#[kprobe(name = "os_sanitizer_user_path_at_empty_kprobe")]
fn kprobe_user_path_at_empty(probe: ProbeContext) -> u32 {
    match unsafe { try_kprobe_user_path_at_empty(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_user_path_at_empty_kprobe"),
    }
}

#[kretprobe(name = "os_sanitizer_user_path_at_empty_kretprobe")]
fn kretprobe_user_path_at_empty(probe: ProbeContext) -> u32 {
    match unsafe { try_kretprobe_user_path_at_empty(&probe) } {
        Ok(res) => res,
        Err(e) => emit_error(&probe, e, "os_sanitizer_user_path_at_empty_kretprobe"),
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UserPathAtEmptyArgs {
    path: *const path,
    user_name: *const u8,
}

// cannot conceive of a use case for >1024 simultaneous kprobes...
#[map]
pub static mut UPAE_ARGS: HashMap<u64, UserPathAtEmptyArgs> = HashMap::with_max_entries(1024, 0);

unsafe fn try_kprobe_user_path_at_empty(ctx: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let user_name: *const u8 = ctx.arg(1).ok_or(MISSING_ARG("name", 1))?;
    let path: *const path = ctx.arg(3).ok_or(MISSING_ARG("path", 3))?;

    let pid_tgid = bpf_get_current_pid_tgid();

    UPAE_ARGS
        .insert(&pid_tgid, &UserPathAtEmptyArgs { path, user_name }, 0)
        .map_err(|_| OUT_OF_SPACE("args storage"))?;
    Ok(0)
}

unsafe fn do_read_kernel<T>(name: &'static str, ptr: *const T) -> Result<T, OsSanitizerError> {
    bpf_probe_read_kernel(ptr)
        .map_err(|_| COULDNT_READ_KERNEL(name, ptr as uintptr_t, size_of::<T>()))
}

unsafe fn do_read_user_str_bytes(
    name: &'static str,
    src: *const u8,
    dest: &mut [u8],
) -> Result<(), OsSanitizerError> {
    match bpf_probe_read_user_str_bytes(src, dest) {
        Ok(_) => Ok(()),
        Err(_) => Err(COULDNT_READ_USER(name, src as uintptr_t, dest.len())),
    }
}

unsafe fn try_kretprobe_user_path_at_empty(ctx: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let Some(&UserPathAtEmptyArgs { path, user_name }) = UPAE_ARGS.get(&pid_tgid) else {
        return Ok(0);
    };
    UPAE_ARGS
        .remove(&pid_tgid)
        .map_err(|_| RACEFUL_ACCESS("name removal"))?;
    let dentry = do_read_kernel("dentry", &(*path).dentry)?;
    if dentry.is_null() {
        return Ok(0);
    }
    let inode = do_read_kernel("d_inode", &(*dentry).d_inode)?;
    let i_mode = do_read_kernel("i_mode", &(*inode).i_mode)?;

    let filetype = i_mode >> 12;

    let filetype = if filetype == 8 {
        "file"
    } else if filetype == 0x4 {
        "directory"
    } else {
        return Ok(0);
    };

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

    let FilenameBuf { buf } = {
        FILENAME_BUF
            .insert(&pid_tgid, &EMPTY_FILENAME_BUF, 0)
            .map_err(|_| OUT_OF_SPACE("filename buf"))?;
        let ptr = FILENAME_BUF
            .get_ptr_mut(&pid_tgid)
            .ok_or(COULDNT_ACCESS_BUFFER("filename"))?;
        &mut *ptr
    };
    let name_ptr = user_name as uintptr_t;
    do_read_user_str_bytes("name", user_name, buf)?;
    let name_ref = core::str::from_utf8_unchecked(buf);
    info!(
        ctx,
        r#"pid {} requested `{}' which has mode {} and is a {}"#,
        pid_tgid as u32,
        // i_ino,
        name_ref,
        rendered_ref,
        filetype
    );
    FILENAME_BUF
        .remove(&pid_tgid)
        .map_err(|_| RACEFUL_ACCESS("name removal"))?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { unreachable_unchecked() }
}
