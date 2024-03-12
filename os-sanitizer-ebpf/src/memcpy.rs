use crate::{emit_report, IGNORED_PIDS, STACK_MAP};
use aya_ebpf::bindings::{BPF_F_REUSE_STACKID, BPF_F_USER_STACK};
use aya_ebpf::cty::{c_void, size_t, uintptr_t};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::gen::bpf_get_current_comm;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf_macros::uprobe;
use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, CouldntRecoverStack, Unreachable};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, EXECUTABLE_LEN};

#[uprobe]
fn uprobe_memcpy(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_memcpy(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_memcpy_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_memcpy(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let destptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strncpy has a dest pointer"))?;

    let srcptr: uintptr_t = probe
        .arg(1)
        .ok_or(Unreachable("strncpy has a src pointer"))?;
    let src_len: size_t = probe
        .arg(2)
        .ok_or(Unreachable("strncpy has a copied size"))?;

    if let Some((variant, len, allocated)) =
        crate::try_check_bad_copy(probe, pid_tgid, srcptr, src_len)?
    {
        let stack_id = STACK_MAP
            .get_stackid(probe, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64)
            .map_err(|e| CouldntRecoverStack("memcpy", e))? as u64;

        let mut executable = [0u8; EXECUTABLE_LEN];

        // we do this manually because the existing implementation is restricted to 16 bytes
        let res = bpf_get_current_comm(
            executable.as_mut_ptr() as *mut c_void,
            executable.len() as u32,
        );
        if res < 0 {
            return Err(CouldntGetComm("memcpy comm", res));
        }

        let report = OsSanitizerReport::Memcpy {
            executable,
            pid_tgid,
            stack_id,
            len,
            allocated,
            dest: destptr as u64,
            src: srcptr as u64,
            variant,
        };

        emit_report(probe, &report)?;
    }

    Ok(0)
}
