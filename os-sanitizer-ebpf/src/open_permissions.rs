// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use core::mem::offset_of;

use aya_ebpf::cty::{c_char, c_void, uintptr_t};
use aya_ebpf::helpers::generated::bpf_get_current_comm;
use aya_ebpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid};
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{FEntryContext, FExitContext, LsmContext};
use aya_ebpf::EbpfContext;
use aya_ebpf_macros::{fentry, fexit, lsm, map};

use os_sanitizer_common::OsSanitizerError::{
    CouldntAccessBuffer, CouldntGetComm, CouldntGetPath, Unreachable,
};
use os_sanitizer_common::OsSanitizerReport::UnsafeOpen;
use os_sanitizer_common::{OsSanitizerError, PassId, EXECUTABLE_LEN};

use crate::binding::{file, filename, inode};
use crate::statistics::update_tracking;
use crate::{read_str, report_stack_id, IGNORED_PIDS, STRING_SCRATCH};

#[map]
pub static ORIGINAL_NAME: LruHashMap<u64, uintptr_t> = LruHashMap::with_max_entries(65536, 0);
#[map]
pub static PERMISSION_INODE_RECORD: LruHashMap<u64, ([u32; 8], [u32; 8], bool)> =
    LruHashMap::with_max_entries(65536, 0);
#[map]
pub static MAY_OPEN_RECORD: LruHashMap<u64, u32> = LruHashMap::with_max_entries(65536, 0);

#[lsm(hook = "inode_permission")]
fn lsm_open_permissions_inode(ctx: LsmContext) -> i32 {
    if let Err(e) = unsafe { try_open_permissions_inode(&ctx) } {
        crate::emit_error(&ctx, e, "open_permissions_inode_lsm");
    }
    0
}

unsafe fn try_open_permissions_inode(ctx: &LsmContext) -> Result<(), OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::lsm_open_permissions_inode);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(());
    }

    let inode: *const inode = ctx.arg(0);

    let uid = ctx.uid();
    let gid = ctx.gid();

    let i_uid = (*inode).i_uid.val;
    let i_gid = (*inode).i_gid.val;
    let i_mode = (*inode).i_mode;

    if (uid != i_uid && i_uid != 0) || (gid != i_gid && i_gid != 0) || i_mode & 0x2 != 0 {
        // we know this will not race because we are accessing relevant to a particular pid_tgid
        // and we are not sleepable
        // we cannot modify in place as the map may be updated elsewhere, invalidating the entry
        let (mut uids, mut gids, mut everyone) =
            if let Some((existing_uids, existing_gids, everyone)) =
                PERMISSION_INODE_RECORD.get(&pid_tgid).copied()
            {
                (existing_uids, existing_gids, everyone)
            } else {
                ([0; 8], [0; 8], false)
            };

        if uid != i_uid && i_uid != 0 {
            for i in 0..uids.len() {
                if uids[i] == 0 || uids[i] == i_uid {
                    // owners secretly may always write
                    uids[i] = i_uid;
                    break;
                }
            }
        }
        if gid != i_gid && i_gid != 0 {
            for i in 0..gids.len() {
                if gids[i] == 0 || gids[i] == i_gid {
                    if i_mode & 0x10 != 0 {
                        // this gid has write permissions
                        gids[i] = i_gid;
                    }
                    break;
                }
            }
        }

        // globally writable, but sticky bit, means perms are preserved
        if i_mode & 0x2 != 0 && i_mode & 0o1000 == 0 {
            everyone = true;
        }

        PERMISSION_INODE_RECORD
            .insert(&pid_tgid, &(uids, gids, everyone), 0)
            .map_err(|_| OsSanitizerError::OutOfSpace("couldn't insert to inode record"))?;
    }

    Ok(())
}

#[fentry(function = "do_filp_open")]
fn fentry_do_filp_open(ctx: FEntryContext) -> i32 {
    if let Err(e) = unsafe { try_do_filp_open(&ctx) } {
        crate::emit_error(&ctx, e, "do_filp_open_fentry");
    }
    0
}

unsafe fn try_do_filp_open(ctx: &FEntryContext) -> Result<(), OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fentry_do_filp_open);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(());
    }

    let filename: *const filename = ctx.arg(1);
    let uptr = (*filename).uptr as uintptr_t;

    ORIGINAL_NAME
        .insert(&pid_tgid, &uptr, 0)
        .map_err(|_| OsSanitizerError::OutOfSpace("couldn't insert to original name record"))?;

    Ok(())
}

#[fexit(function = "do_filp_open")]
fn fexit_do_filp_open(ctx: FExitContext) -> i32 {
    if let Err(e) = unsafe { try_do_filp_open_cleanup(&ctx) } {
        crate::emit_error(&ctx, e, "do_filp_open_fxit");
    }
    0
}

unsafe fn try_do_filp_open_cleanup(_ctx: &FExitContext) -> Result<(), OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fexit_do_filp_open);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(());
    }

    let _ = ORIGINAL_NAME.remove(&pid_tgid);

    Ok(())
}

#[fentry(function = "may_open")]
fn fentry_may_open(ctx: FEntryContext) -> i32 {
    if let Err(e) = unsafe { try_may_open(&ctx) } {
        crate::emit_error(&ctx, e, "may_open_fentry");
    }
    0
}

unsafe fn try_may_open(ctx: &FEntryContext) -> Result<(), OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fentry_may_open);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(());
    }

    let acc_mode: u32 = ctx.arg(2);

    MAY_OPEN_RECORD
        .insert(&pid_tgid, &acc_mode, 0)
        .map_err(|_| OsSanitizerError::OutOfSpace("couldn't insert to may_open record"))?;

    Ok(())
}

#[fentry(function = "security_file_open")]
fn fentry_open_permissions_file(ctx: FEntryContext) -> i32 {
    if let Err(e) = unsafe { try_open_permissions_file(&ctx) } {
        crate::emit_error(&ctx, e, "open_permissions_file_fentry");
    }
    0
}

unsafe fn try_open_permissions_file(ctx: &FEntryContext) -> Result<(), OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fentry_open_permissions_file);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(());
    }

    let file: *const file = ctx.arg(0);
    let stack_id = report_stack_id(ctx, "stack eq check")?;

    if let Some(original) = ORIGINAL_NAME.get(&pid_tgid).copied() {
        if let Some((uids, gids, everyone)) = PERMISSION_INODE_RECORD.get(&pid_tgid).copied() {
            if let Some(mask) = MAY_OPEN_RECORD.get(&pid_tgid).copied() {
                if uids[0] == 0 && gids[0] == 0 && !everyone {
                    return Ok(()); // nothing to report
                }

                // let inode_type = ((*(*file).f_inode).i_mode >> 8) as u8;
                let ptr = STRING_SCRATCH
                    .get_ptr_mut(1)
                    .ok_or(CouldntAccessBuffer("emit-report"))?;
                if ptr == core::ptr::null_mut() {
                    return Err(Unreachable("unset string scratch pointer"));
                }
                let filename = &mut *ptr;
                let path = file as uintptr_t + offset_of!(file, f_path);

                let res = bpf_d_path(
                    path as *mut aya_ebpf::bindings::path,
                    filename.as_mut_ptr() as *mut c_char,
                    filename.len() as u32,
                );
                if res < 0 {
                    return Err(CouldntGetPath("emit-report", res));
                }

                if filename[0] == 0 {
                    return Ok(()); // nothing to report :(
                }

                if filename.starts_with(b"/dev")
                    || filename.starts_with(b"/proc")
                    || filename.starts_with(b"/sys")
                {
                    return Ok(()); // generally not desireable to report
                }

                let original = read_str(original, "original file requested").ok();

                if let Some(original) = original {
                    if [
                        b"/dev/full".as_slice(),
                        b"/dev/fuse".as_slice(),
                        b"/dev/kvm".as_slice(),
                        b"/dev/null".as_slice(),
                        b"/dev/ptmx".as_slice(),
                        b"/dev/random".as_slice(),
                        b"/dev/tty".as_slice(),
                        b"/dev/urandom".as_slice(),
                        b"/dev/vhost-net".as_slice(),
                        b"/dev/vhost-vsock".as_slice(),
                        b"/dev/zero".as_slice(),
                    ]
                    .into_iter()
                    .any(|d| original.starts_with(d))
                    {
                        return Ok(()); // generally not desireable to report
                    }
                }

                let uid = ctx.uid();
                let gid = ctx.gid();

                let mut executable = [0u8; EXECUTABLE_LEN];

                // we do this manually because the existing implementation is restricted to 16 bytes
                let res = bpf_get_current_comm(
                    executable.as_mut_ptr() as *mut c_void,
                    executable.len() as u32,
                );
                if res < 0 {
                    return Err(CouldntGetComm("open permissions comm", res));
                }

                let report = UnsafeOpen {
                    executable,
                    uid,
                    gid,
                    pid_tgid,
                    stack_id,
                    original,
                    filename,
                    uids,
                    gids,
                    mask,
                    everyone,
                };

                crate::emit_report(ctx, &report)?;
            }
        }
    }

    Ok(())
}

#[fentry(function = "path_openat")]
fn fentry_clear_open_permissions(_ctx: FEntryContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fentry_clear_open_permissions);

    // discard the accumulated perms
    let _ = PERMISSION_INODE_RECORD.remove(&pid_tgid);
    let _ = MAY_OPEN_RECORD.remove(&pid_tgid);
    0
}
