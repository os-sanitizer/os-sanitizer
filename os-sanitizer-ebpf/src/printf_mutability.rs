// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use aya_ebpf::bindings::{__u64, task_struct};
use aya_ebpf::cty::{c_long, c_void, uintptr_t};
use aya_ebpf::helpers::generated::bpf_get_current_comm;
use aya_ebpf::helpers::{bpf_find_vma, bpf_get_current_pid_tgid, bpf_get_current_task_btf};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf_macros::uprobe;

use os_sanitizer_common::OsSanitizerError::{
    CouldntFindVma, CouldntGetComm, UnexpectedNull, Unreachable,
};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, ProgId, EXECUTABLE_LEN};

use crate::binding::vm_area_struct;
use crate::statistics::update_tracking;
use crate::{access_vm_flags, emit_report, read_str, IGNORED_PIDS};

#[repr(C)]
pub struct PrintfMutabilityContext {
    pid_tgid: u64,
    template_param: __u64,
    probe: *const ProbeContext,
}

unsafe extern "C" fn printf_mutability_callback(
    _task: *mut task_struct,
    vma: *mut vm_area_struct,
    callback_ctx: *mut c_void,
) -> c_long {
    #[inline(always)]
    unsafe fn do_mutability_check(
        vma: *mut vm_area_struct,
        pid_tgid: u64,
        template_param: u64,
        probe: &ProbeContext,
    ) -> Result<(), OsSanitizerError> {
        let vm_flags = access_vm_flags(
            vma.as_ref()
                .ok_or(UnexpectedNull("VMA provided was null"))?,
        );

        // if writable
        if (vm_flags & 0x00000002) != 0 {
            let stack_id = crate::report_stack_id(probe, "printf-mutability")?;

            let mut executable = [0u8; EXECUTABLE_LEN];

            // we do this manually because the existing implementation is restricted to 16 bytes
            let res = bpf_get_current_comm(
                executable.as_mut_ptr() as *mut c_void,
                executable.len() as u32,
            );
            if res < 0 {
                return Err(CouldntGetComm("printf-mutability comm", res));
            }

            let template = read_str(template_param as uintptr_t, "printf template")?;

            let report = OsSanitizerReport::PrintfMutability {
                executable,
                pid_tgid,
                stack_id,
                template_param,
                template,
            };

            emit_report(probe, &report)?;
        }

        Ok(())
    }

    if let Some(ctx) = (callback_ctx as *const PrintfMutabilityContext).as_ref() {
        if let Some(probe) = ctx.probe.as_ref() {
            if let Err(e) = do_mutability_check(vma, ctx.pid_tgid, ctx.template_param, probe) {
                crate::emit_error(probe, e, "printf_mutability_callback");
            }
        }
    }

    0
}

#[inline(always)]
unsafe fn check_printf_mutability<const TEMPLATE_PARAM: usize>(
    probe: &ProbeContext,
) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, ProgId::check_printf_mutability);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let task_ptr = bpf_get_current_task_btf();

    let template_param: __u64 = probe
        .arg(TEMPLATE_PARAM)
        .ok_or(Unreachable("printf-like has a template parameter"))?;

    let ctx = PrintfMutabilityContext {
        pid_tgid,
        template_param,
        probe: probe as *const _,
    };

    match bpf_find_vma(
        task_ptr,
        template_param,
        printf_mutability_callback as *mut c_void,
        &ctx as *const PrintfMutabilityContext as *mut c_void,
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

macro_rules! define_printf_mutability {
    ($name: ident, $variant: literal) => {
        ::paste::paste! {
            #[uprobe]
            fn [< uprobe_ $name _mutability >](probe: ProbeContext) -> u32 {
                match unsafe { check_printf_mutability::<$variant>(&probe) } {
                    Ok(res) => res,
                    Err(e) => crate::emit_error(&probe, e, concat!(concat!("os_sanitizer_", stringify!($name)), "_mutability_uprobe")),
                }
            }
        }
    }
}

define_printf_mutability!(printf, 0);
define_printf_mutability!(vprintf, 0);

define_printf_mutability!(fprintf, 1);
define_printf_mutability!(dprintf, 1);
define_printf_mutability!(sprintf, 1);
define_printf_mutability!(vfprintf, 1);
define_printf_mutability!(vdprintf, 1);
define_printf_mutability!(vsprintf, 1);

define_printf_mutability!(snprintf, 2);
define_printf_mutability!(vsnprintf, 2);
