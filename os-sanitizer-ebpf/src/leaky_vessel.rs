use aya_ebpf::cty::c_void;
use aya_ebpf::helpers::gen::bpf_get_current_comm;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid};
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{FEntryContext, LsmContext, TracePointContext};
use aya_ebpf_macros::{fentry, lsm, map, tracepoint};

use os_sanitizer_common::OsSanitizerError::CouldntGetComm;
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN};

#[map]
pub static FORK_CHDIR: LruHashMap<u32, (u32, u32, u64, u64)> =
    LruHashMap::with_max_entries(65536, 0);

#[map]
pub static FORK_OBSERVED: LruHashMap<u32, (u32, u32, u64)> = LruHashMap::with_max_entries(65536, 0);

#[tracepoint]
fn tracepoint_execveat_lv(ctx: TracePointContext) -> u32 {
    match unsafe { try_tracepoint_execveat_lv(&ctx) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&ctx, e, "execveat_lv_tracepoint"),
    }
}

unsafe fn try_tracepoint_execveat_lv(ctx: &TracePointContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(&(orig_pid, orig_uid, chdir_stack, setuid_stack)) =
        FORK_CHDIR.get(&(pid_tgid as u32))
    {
        let stack_id = crate::report_stack_id(ctx, "leaky-vessel execveat")?;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("leaky-vessel comm", res));
        }

        let report = OsSanitizerReport::LeakyVessel {
            executable,
            pid_tgid,
            stack_id,
            orig_pid,
            orig_uid,
            chdir_stack,
            setuid_stack,
        };
        crate::emit_report(ctx, &report)?;
    }
    Ok(0)
}

#[fentry(function = "set_fs_pwd")]
fn fentry_set_fs_pwd_lv(ctx: FEntryContext) -> u32 {
    match unsafe { try_fentry_set_fs_pwd_lv(&ctx) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&ctx, e, "set_fs_pwd_lv_fentry"),
    }
}

unsafe fn try_fentry_set_fs_pwd_lv(ctx: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid = bpf_get_current_pid_tgid() as u32;
    if let Some(&(old_pid, old_uid, setuid)) = FORK_OBSERVED.get(&pid) {
        let stack_id = crate::report_stack_id(ctx, "leaky-vessel fchdir")?;

        FORK_CHDIR
            .insert(&pid, &(old_pid, old_uid, stack_id, setuid), 0)
            .map_err(|_| OsSanitizerError::Unreachable("couldn't insert pid to FORK_SUID"))?;

        let _ = FORK_OBSERVED.remove(&pid);
    }
    Ok(0)
}

#[lsm(hook = "task_fix_setuid")]
fn lsm_setuid_lv(ctx: LsmContext) -> i32 {
    if let Err(e) = unsafe { try_lsm_setuid_lv(&ctx) } {
        crate::emit_error(&ctx, e, "setuid_lv_lsm");
    }
    0
}

unsafe fn try_lsm_setuid_lv(ctx: &LsmContext) -> Result<(), OsSanitizerError> {
    let pid = bpf_get_current_pid_tgid() as u32;
    if let Some(&(orig_pid, uid, setuid)) = FORK_OBSERVED.get(&pid) {
        if setuid == 0 {
            let setuid = crate::report_stack_id(ctx, "leaky-vessel fchdir")?;

            FORK_OBSERVED
                .insert(&pid, &(orig_pid, uid, setuid), 0)
                .map_err(|_| OsSanitizerError::Unreachable("couldn't insert pid to FORK_SUID"))?;
        }
    }
    if let Some(&(orig_pid, uid, chdir, setuid)) = FORK_CHDIR.get(&pid) {
        if setuid == 0 {
            let setuid = crate::report_stack_id(ctx, "leaky-vessel fchdir")?;

            FORK_CHDIR
                .insert(&pid, &(orig_pid, uid, chdir, setuid), 0)
                .map_err(|_| OsSanitizerError::Unreachable("couldn't insert pid to FORK_SUID"))?;
        }
    }

    Ok(())
}

#[tracepoint]
fn tracepoint_fork_lv(probe: TracePointContext) -> u32 {
    match unsafe { try_tracepoint_fork_lv(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "fork_lv_tracepoint"),
    }
}

unsafe fn try_tracepoint_fork_lv(probe: &TracePointContext) -> Result<u32, OsSanitizerError> {
    let uid = bpf_get_current_uid_gid() as u32;

    let orig_pid = probe
        .read_at::<u32>(24)
        .map_err(|_| OsSanitizerError::MissingArg("child_pid of sched_process_fork", 44))?;
    let pid = probe
        .read_at::<u32>(44)
        .map_err(|_| OsSanitizerError::MissingArg("child_pid of sched_process_fork", 44))?;

    FORK_OBSERVED
        .insert(&pid, &(orig_pid, uid, 0), 0)
        .map_err(|_| OsSanitizerError::Unreachable("couldn't insert pid to FORK_OBSERVED"))?;

    Ok(0)
}
