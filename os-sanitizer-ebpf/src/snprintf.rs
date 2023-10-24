use aya_bpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_int, c_void, size_t, uintptr_t};
use aya_bpf::helpers::gen::bpf_get_current_comm;
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes};
use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::{FEntryContext, ProbeContext};
use aya_bpf_macros::{fentry, map, uprobe, uretprobe};
use aya_log_ebpf::info;

use os_sanitizer_common::OsSanitizerError::{
    CouldntGetComm, CouldntReadUser, CouldntRecoverStack, MissingArg, Unreachable,
};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, SnprintfViolation, EXECUTABLE_LEN};

use crate::{FUNCTION_REPORT_QUEUE, IGNORED_PIDS, STACK_MAP};

#[map]
static SNPRINTF_INTERMEDIARY_MAP: LruHashMap<u64, (uintptr_t, size_t)> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[map]
static SNPRINTF_SIZE_MAP: LruHashMap<(u64, uintptr_t), (size_t, size_t)> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_snprintf(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_snprintf(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_snprintf_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_snprintf(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe.arg(0).ok_or(MissingArg("snprintf dest pointer", 0))?;
    let size: size_t = probe.arg(1).ok_or(MissingArg("snprintf size", 1))?;

    SNPRINTF_INTERMEDIARY_MAP
        .insert(&pid_tgid, &(destptr, size), 0)
        .map_err(|_| Unreachable("Couldn't insert into SNPRINTF_INTERMEDIARY_MAP"))?;

    Ok(0)
}

#[uretprobe]
fn uretprobe_snprintf(probe: ProbeContext) -> u32 {
    match unsafe { try_uretprobe_snprintf(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_snprintf_uretprobe"),
    }
}

#[inline(always)]
unsafe fn try_uretprobe_snprintf(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    if let Some(&(destptr, size)) = SNPRINTF_INTERMEDIARY_MAP.get(&pid_tgid) {
        let _ = SNPRINTF_INTERMEDIARY_MAP.remove(&pid_tgid); // don't care if this fails

        let computed: c_int = probe
            .ret()
            .ok_or(Unreachable("no return value for snprintf"))?;

        info!(
            probe,
            "stashed {:x} ({}/{}) for {}",
            destptr,
            computed,
            size,
            pid_tgid >> 32
        );

        SNPRINTF_SIZE_MAP
            .insert(&(pid_tgid >> 32, destptr), &(size, computed as size_t), 0)
            .map_err(|_| Unreachable("Couldn't insert into SNPRINTF_SIZE_MAP"))?;
    }

    Ok(0)
}

#[fentry(function = "vfs_write")]
fn fentry_vfs_write_snprintf(ctx: FEntryContext) -> u32 {
    match unsafe { try_fentry_vfs_write_snprintf(&ctx) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&ctx, e, "os_sanitizer_vfs_write_snprintf_fentry"),
    }
}

unsafe fn try_fentry_vfs_write_snprintf(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    // TODO use pointer approximation

    let srcptr: uintptr_t = ctx.arg(1);
    let count: size_t = ctx.arg(2);

    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    if count == 7 {
        let mut userstring = [0u8; 32];

        let userstring = core::str::from_utf8_unchecked(
            bpf_probe_read_user_str_bytes(srcptr as *const _, &mut userstring)
                .map_err(|_| CouldntReadUser("user string for vfs write", srcptr, 0))?,
        );

        info!(
            ctx,
            "found {} ({:x}) for {}",
            userstring,
            srcptr,
            pid_tgid >> 32
        );
    }

    if let Some(&(size, computed)) = SNPRINTF_SIZE_MAP.get(&(pid_tgid >> 32, srcptr)) {
        if count >= computed {
            let mut executable = [0u8; EXECUTABLE_LEN];

            // we do this manually because the existing implementation is restricted to 16 bytes
            let res = bpf_get_current_comm(
                executable.as_mut_ptr() as *mut c_void,
                executable.len() as u32,
            );
            if res < 0 {
                return Err(CouldntGetComm("vfs_write_snprintf comm", res));
            }

            let stack_id = STACK_MAP
                .get_stackid(ctx, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
                .map_err(|e| CouldntRecoverStack("printf-mutability", e))?
                as u64;

            let mut executable = [0u8; EXECUTABLE_LEN];

            // we do this manually because the existing implementation is restricted to 16 bytes
            let res = bpf_get_current_comm(
                executable.as_mut_ptr() as *mut c_void,
                executable.len() as u32,
            );
            if res < 0 {
                return Err(CouldntGetComm("vfs_write_snprintf comm", res));
            }

            let kind = if count >= size {
                SnprintfViolation::DefiniteLeak
            } else {
                SnprintfViolation::PossibleLeak
            };

            let report = OsSanitizerReport::zeroed_init(|| OsSanitizerReport::Snprintf {
                executable,
                pid_tgid,
                stack_id,
                size,
                computed,
                count,
                kind,
            });

            FUNCTION_REPORT_QUEUE.output(ctx, &report, 0);
        }
    }

    Ok(0)
}
