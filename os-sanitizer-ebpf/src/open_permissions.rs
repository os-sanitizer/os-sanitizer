use aya_ebpf::cty::{c_char, uintptr_t};
use aya_ebpf::helpers::{bpf_d_path, bpf_get_current_pid_tgid};
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{FEntryContext, LsmContext};
use aya_ebpf::EbpfContext;
use aya_ebpf_macros::{fentry, lsm, map};
use core::mem::offset_of;

use os_sanitizer_common::OsSanitizerError;
use os_sanitizer_common::OsSanitizerError::{CouldntAccessBuffer, CouldntGetPath, Unreachable};
use os_sanitizer_common::OsSanitizerReport::UnsafeOpen;

use crate::binding::{file, inode};
use crate::{report_stack_id, STRING_SCRATCH};

#[map]
pub static PERMISSION_INODE_RECORD: LruHashMap<(u64, u64), ([u32; 16], [u32; 16], u64)> =
    LruHashMap::with_max_entries(65536, 0);

#[lsm(hook = "inode_permission")]
fn lsm_open_permissions_inode(ctx: LsmContext) -> i32 {
    if let Err(e) = unsafe { try_open_permissions_inode(&ctx) } {
        crate::emit_error(&ctx, e, "open_permissions_inode_lsm");
    }
    0
}

unsafe fn try_open_permissions_inode(ctx: &LsmContext) -> Result<(), OsSanitizerError> {
    let inode: *const inode = ctx.arg(0);

    let uid = ctx.uid();
    let gid = ctx.gid();

    let i_uid = (*inode).i_uid.val;
    let i_gid = (*inode).i_gid.val;

    if (uid != i_uid && i_uid != 0) || (gid != i_gid && i_gid != 0) {
        // we know this will not race because we are accessing relevant to a particular pid_tgid
        // and we are not sleepable
        // we cannot modify in place as the map may be updated elsewhere, invalidating the entry
        let pid_tgid = bpf_get_current_pid_tgid();
        let i_no = (*inode).i_ino;
        let (mut uids, mut gids, stack_id) = if let Some((existing_uids, existing_gids, stack_id)) =
            PERMISSION_INODE_RECORD.get(&(pid_tgid, i_no)).copied()
        {
            (existing_uids, existing_gids, stack_id)
        } else {
            ([0; 16], [0; 16], report_stack_id(ctx, "inode record")?)
        };

        if uid != i_uid && i_uid != 0 {
            for i in 0..uids.len() {
                if uids[i] == 0 || uids[i] == i_uid {
                    uids[i] = i_uid;
                    break;
                }
            }
        }
        if gid != i_gid && i_gid != 0 {
            for i in 0..gids.len() {
                if gids[i] == 0 || gids[i] == i_gid {
                    gids[i] = i_gid;
                    break;
                }
            }
        }

        PERMISSION_INODE_RECORD
            .insert(&(pid_tgid, i_no), &(uids, gids, stack_id), 0)
            .map_err(|_| OsSanitizerError::OutOfSpace("couldn't insert to inode record"))?;
    }

    Ok(())
}

#[fentry(function = "security_file_permission")]
fn fentry_open_permissions_file(ctx: FEntryContext) -> i32 {
    if let Err(e) = unsafe { try_open_permissions_file(&ctx) } {
        crate::emit_error(&ctx, e, "open_permissions_file_fentry");
    }
    0
}

unsafe fn try_open_permissions_file(ctx: &FEntryContext) -> Result<(), OsSanitizerError> {
    let file: *const file = ctx.arg(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let i_no = (*(*file).f_inode).i_ino;

    if let Some((uids, gids, stack_id)) = PERMISSION_INODE_RECORD.get(&(pid_tgid, i_no)).copied() {
        let mask: u32 = ctx.arg(1);
        let inode_type = ((*(*file).f_inode).i_mode >> 8) as u8;
        let ptr = STRING_SCRATCH
            .get_ptr_mut(0)
            .ok_or(CouldntAccessBuffer("emit-report"))?;
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

        let report = UnsafeOpen {
            executable: ctx
                .command()
                .map_err(|_| Unreachable("not in an executable context"))?,
            pid_tgid,
            stack_id,
            filename,
            uids,
            gids,
            mask,
            inode_type,
        };

        crate::emit_report(ctx, &report)?;
    }

    Ok(())
}
