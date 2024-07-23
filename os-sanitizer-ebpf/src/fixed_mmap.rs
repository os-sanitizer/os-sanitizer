// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use core::ffi::c_ulong;

use aya_ebpf::bindings::task_struct;
use aya_ebpf::cty::{c_long, c_void};
use aya_ebpf::helpers::gen::bpf_get_current_comm;
use aya_ebpf::helpers::{bpf_find_vma, bpf_get_current_pid_tgid, bpf_get_current_task_btf};
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{FEntryContext, ProbeContext, RetProbeContext};
use aya_ebpf_macros::{fentry, map, uprobe, uretprobe};

use os_sanitizer_common::OsSanitizerError::{
    CouldntFindVma, CouldntGetComm, UnexpectedNull, Unreachable,
};
use os_sanitizer_common::{
    FixedMmapViolation, OsSanitizerError, OsSanitizerReport, PassId, EXECUTABLE_LEN,
};

use crate::binding::vm_area_struct;
use crate::statistics::update_tracking;
use crate::{access_vm_flags, emit_report, IGNORED_PIDS};

const MAP_FIXED: c_ulong = 16; // manually determined

#[repr(C)]
struct MmapFixedContext {
    pid_tgid: u64,
    protection: u64,
    probe: *const FEntryContext,
}

unsafe fn emit_fixed_mmap_report(
    probe: &FEntryContext,
    pid_tgid: u64,
    protection: u64,
    variant: FixedMmapViolation,
) -> Result<(), OsSanitizerError> {
    let stack_id = crate::report_stack_id(probe, "fixed-mmap")?;

    let mut executable = [0u8; EXECUTABLE_LEN];

    // we do this manually because the existing implementation is restricted to 16 bytes
    let res = bpf_get_current_comm(
        executable.as_mut_ptr() as *mut c_void,
        executable.len() as u32,
    );
    if res < 0 {
        return Err(CouldntGetComm("fixed-mmap comm", res));
    }

    let report = OsSanitizerReport::FixedMmap {
        executable,
        pid_tgid,
        stack_id,
        protection,
        variant,
    };
    emit_report(probe, &report)
}

unsafe extern "C" fn mmap_fixed_callback(
    _task: *mut task_struct,
    vma: *mut vm_area_struct,
    callback_ctx: *mut c_void,
) -> c_long {
    #[inline(always)]
    unsafe fn do_fixed_address_check(
        vma: *mut vm_area_struct,
        pid_tgid: u64,
        protection: u64,
        probe: &FEntryContext,
    ) -> Result<(), OsSanitizerError> {
        let vm_flags = access_vm_flags(
            vma.as_ref()
                .ok_or(UnexpectedNull("VMA provided was null"))?,
        );

        // if readable, writable, or executable
        if (vm_flags & 0x00000007) != 0 {
            emit_fixed_mmap_report(
                probe,
                pid_tgid,
                protection,
                FixedMmapViolation::FixedMmapBadProt,
            )?;
        }

        Ok(())
    }

    if let Some(ctx) = (callback_ctx as *const MmapFixedContext).as_ref() {
        if let Some(probe) = ctx.probe.as_ref() {
            if let Err(e) = do_fixed_address_check(vma, ctx.pid_tgid, ctx.protection, probe) {
                crate::emit_error(probe, e, "fixed_mmap_callback");
            }
        }
    }

    0
}

#[map]
static FIXED_MMAP_SAFE_WRAPPED: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_fixed_mmap_safe_function(probe: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uprobe_fixed_mmap_safe_function);
    match FIXED_MMAP_SAFE_WRAPPED.insert(&pid_tgid, &0, 0) {
        Ok(_) => 0,
        Err(_) => crate::emit_error(
            &probe,
            Unreachable("Couldn't insert into FIXED_MMAP_SAFE_WRAPPED"),
            "uprobe_fixed_mmap_safe_function",
        ),
    }
}

#[uretprobe]
fn uretprobe_fixed_mmap_safe_function(_probe: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uretprobe_fixed_mmap_safe_function);
    let _ = FIXED_MMAP_SAFE_WRAPPED.remove(&pid_tgid); // don't care if this fails
    0
}

#[fentry(function = "ksys_mmap_pgoff")]
fn fentry_fixed_mmap(probe: FEntryContext) -> u32 {
    match unsafe { try_fentry_fixed_mmap(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_fixed_mmap_fentry"),
    }
}

unsafe fn try_fentry_fixed_mmap(probe: &FEntryContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::fentry_fixed_mmap);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }
    if FIXED_MMAP_SAFE_WRAPPED.get(&pid_tgid).is_some() {
        return Ok(0);
    }

    let addr: u64 = probe.arg(0);
    let protection: u64 = probe.arg(2);
    let flags: u64 = probe.arg(3);

    let task_ptr = bpf_get_current_task_btf();

    let ctx = MmapFixedContext {
        pid_tgid,
        protection,
        probe: probe as *const _,
    };

    if addr != 0 {
        if flags & MAP_FIXED != 0 {
            match bpf_find_vma(
                task_ptr,
                addr,
                mmap_fixed_callback as *mut c_void,
                &ctx as *const MmapFixedContext as *mut c_void,
                0,
            ) {
                0 => {
                    return Ok(0); // we found the VMA and handled it appropriately
                }
                -2 => {
                    // no entry => MAP_FIXED was used without a preallocated region
                    // this is explicitly warned against in the man page
                    emit_fixed_mmap_report(
                        probe,
                        pid_tgid,
                        protection,
                        FixedMmapViolation::FixedMmapUnmapped,
                    )?;
                }
                e => {
                    return Err(CouldntFindVma(
                        "couldn't find vma for fixed address",
                        e,
                        (pid_tgid >> 32) as u32,
                        pid_tgid as u32,
                    ))
                }
            }
        } else {
            emit_fixed_mmap_report(probe, pid_tgid, protection, FixedMmapViolation::HintUsed)?;
        }
    }

    Ok(0)
}
