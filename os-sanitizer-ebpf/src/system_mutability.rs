use crate::binding::vm_area_struct;
use crate::{access_vm_flags, emit_report, read_str, IGNORED_PIDS, STACK_MAP};
use aya_bpf::bindings::{__u64, task_struct, BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_bpf::cty::{c_long, c_void, uintptr_t};
use aya_bpf::helpers::gen::{bpf_get_current_comm, bpf_probe_read_user_str};
use aya_bpf::helpers::{bpf_find_vma, bpf_get_current_pid_tgid, bpf_get_current_task_btf};
use aya_bpf::programs::ProbeContext;
use aya_bpf_macros::uprobe;
use os_sanitizer_common::OsSanitizerError::{
    CouldntFindVma, CouldntGetComm, CouldntRecoverStack, UnexpectedNull, Unreachable,
};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN};

#[repr(C)]
struct SystemMutabilityContext {
    pid_tgid: u64,
    command_param: __u64,
    probe: *const ProbeContext,
}

unsafe extern "C" fn system_mutability_callback(
    _task: *mut task_struct,
    vma: *mut vm_area_struct,
    callback_ctx: *mut c_void,
) -> c_long {
    #[inline(always)]
    unsafe fn do_mutability_check(
        vma: *mut vm_area_struct,
        pid_tgid: u64,
        command_param: u64,
        probe: &ProbeContext,
    ) -> Result<(), OsSanitizerError> {
        let vm_flags = access_vm_flags(
            vma.as_ref()
                .ok_or(UnexpectedNull("VMA provided was null"))?,
        );

        // if writable
        if (vm_flags & 0x00000002) != 0 {
            let stack_id = STACK_MAP
                .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
                .map_err(|e| CouldntRecoverStack("system-mutability", e))?
                as u64;

            let mut executable = [0u8; EXECUTABLE_LEN];

            // we do this manually because the existing implementation is restricted to 16 bytes
            let res = bpf_get_current_comm(
                executable.as_mut_ptr() as *mut c_void,
                executable.len() as u32,
            );
            if res < 0 {
                return Err(CouldntGetComm("system-mutability comm", res));
            }

            let mut command = read_str(command_param as uintptr_t, "system command")?;

            let report = OsSanitizerReport::SystemMutability {
                executable,
                pid_tgid,
                stack_id,
                command_param,
                command,
            };

            emit_report(probe, &report)?;
        }

        Ok(())
    }

    if let Some(ctx) = (callback_ctx as *const SystemMutabilityContext).as_ref() {
        if let Some(probe) = ctx.probe.as_ref() {
            if let Err(e) = do_mutability_check(vma, ctx.pid_tgid, ctx.command_param, probe) {
                crate::emit_error(probe, e, "system_mutability_callback");
            }
        }
    }

    0
}

#[inline(always)]
unsafe fn check_system_mutability(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let task_ptr = bpf_get_current_task_btf();

    let command_param: __u64 = probe
        .arg(0)
        .ok_or(Unreachable("system-like has a template parameter"))?;

    let ctx = SystemMutabilityContext {
        pid_tgid,
        command_param,
        probe: probe as *const _,
    };

    match bpf_find_vma(
        task_ptr,
        command_param,
        system_mutability_callback as *mut c_void,
        &ctx as *const SystemMutabilityContext as *mut c_void,
        0,
    ) {
        0 => Ok(0),
        e => Err(CouldntFindVma(
            "couldn't find vma for template parameter",
            e,
            (pid_tgid >> 32) as u32,
            pid_tgid as u32,
        )),
    }
}

#[uprobe]
fn uprobe_system_mutability(probe: ProbeContext) -> u32 {
    unsafe { check_system_mutability(&probe) }
        .unwrap_or_else(|e| crate::emit_error(&probe, e, "os_sanitizer_system_mutability_uprobe"))
}
