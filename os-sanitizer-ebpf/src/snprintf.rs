use aya_ebpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_ebpf::cty::{c_int, c_void, size_t, uintptr_t};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::gen::bpf_get_current_comm;
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{FEntryContext, ProbeContext};
use aya_ebpf::EbpfContext;
use aya_ebpf_macros::{fentry, map, uprobe, uretprobe};

use os_sanitizer_common::OsSanitizerError::{
    CouldntGetComm, CouldntRecoverStack, MissingArg, Unreachable,
};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, SnprintfViolation, EXECUTABLE_LEN};

use crate::{emit_report, IGNORED_PIDS, STACK_MAP};

#[map]
static SNPRINTF_SAFE_WRAPPED: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_snprintf_safe_wrapper(probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    match SNPRINTF_SAFE_WRAPPED.insert(&pid_tgid, &0, 0) {
        Ok(_) => 0,
        Err(_) => crate::emit_error(
            &probe,
            Unreachable("Couldn't insert into SNPRINTF_SAFE_WRAPPED"),
            "uprobe_snprintf_safe_wrapper",
        ),
    }
}

#[uretprobe]
fn uretprobe_snprintf_safe_wrapper(_probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SNPRINTF_SAFE_WRAPPED.remove(&pid_tgid); // don't care if this fails
    0
}

#[map]
static SNPRINTF_INTERMEDIARY_MAP: LruHashMap<u64, (uintptr_t, size_t)> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[map]
static SNPRINTF_SIZE_MAP: LruHashMap<(u64, uintptr_t), (size_t, size_t, u64)> =
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

    if SNPRINTF_SAFE_WRAPPED.get(&pid_tgid).is_some() {
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

    if SNPRINTF_SAFE_WRAPPED.get(&pid_tgid).is_some() {
        return Ok(0);
    }

    if let Some(&(destptr, size)) = SNPRINTF_INTERMEDIARY_MAP.get(&pid_tgid) {
        let _ = SNPRINTF_INTERMEDIARY_MAP.remove(&pid_tgid); // don't care if this fails

        let computed: c_int = probe
            .ret()
            .ok_or(Unreachable("no return value for snprintf"))?;

        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("printf-mutability", e))?
            as u64;

        SNPRINTF_SIZE_MAP
            .insert(
                &(pid_tgid >> 32, destptr),
                &(size, computed as size_t, stack_id),
                0,
            )
            .map_err(|_| Unreachable("Couldn't insert into SNPRINTF_SIZE_MAP"))?;
    }

    Ok(0)
}

#[inline(always)]
unsafe fn maybe_report_sprintf<C: EbpfContext>(
    ctx: &C,
    pid_tgid: u64,
    srcptr: uintptr_t,
    count: size_t,
) -> Result<u32, OsSanitizerError> {
    // TODO use pointer approximation

    if let Some(&(size, computed, stack_id)) = SNPRINTF_SIZE_MAP.get(&(pid_tgid >> 32, srcptr)) {
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

            let second_stack_id = STACK_MAP
                .get_stackid(ctx, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
                .map_err(|e| CouldntRecoverStack("printf-mutability", e))?
                as u64;

            let report = OsSanitizerReport::Snprintf {
                executable,
                pid_tgid,
                stack_id,
                second_stack_id,
                srcptr: srcptr as u64,
                size: size as u64,
                computed: computed as u64,
                count: count as u64,
                kind,
            };

            emit_report(ctx, &report)?;
        }
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

#[inline(always)]
unsafe fn try_fentry_vfs_write_snprintf(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let srcptr: uintptr_t = ctx.arg(1);
    let count: size_t = ctx.arg(2);

    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    maybe_report_sprintf(ctx, pid_tgid, srcptr, count)
}

#[uprobe]
fn uprobe_xsputn_sprintf(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_xsputn_sprintf(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_xsputn_snprintf_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_xsputn_sprintf(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let srcptr: uintptr_t = probe.arg(1).ok_or(MissingArg("xsputn data pointer", 1))?;
    let count: size_t = probe.arg(2).ok_or(MissingArg("xsputn count", 2))?;

    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    maybe_report_sprintf(probe, pid_tgid, srcptr, count)
}
