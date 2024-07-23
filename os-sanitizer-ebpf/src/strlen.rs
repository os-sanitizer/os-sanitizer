// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use aya_ebpf::cty::{size_t, uintptr_t};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::maps::{HashMap, LruHashMap};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf_macros::{map, uprobe, uretprobe};

use os_sanitizer_common::OsSanitizerError::{OutOfSpace, Unreachable};
use os_sanitizer_common::{OsSanitizerError, PassId};

use crate::statistics::update_tracking;
use crate::IGNORED_PIDS;

#[map]
static STRLEN_PTR_MAP: HashMap<u64, uintptr_t> = HashMap::with_max_entries(1 << 16, 0);

#[map]
pub(crate) static STRLEN_MAP: LruHashMap<(u64, uintptr_t), size_t> =
    LruHashMap::with_max_entries(1 << 16, 0);

#[uprobe]
fn uprobe_strlen(probe: ProbeContext) -> u32 {
    match unsafe { try_uprobe_strlen(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_strlen_uprobe"),
    }
}

#[inline(always)]
unsafe fn try_uprobe_strlen(probe: &ProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uprobe_strlen);

    let strptr: uintptr_t = probe
        .arg(0)
        .ok_or(Unreachable("strlen didn't have an argument"))?;

    if strptr != 0 {
        if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
            return Ok(0);
        }

        STRLEN_PTR_MAP
            .insert(&pid_tgid, &strptr, 0)
            .map_err(|_| OutOfSpace("strlen map"))?;
    }

    Ok(0)
}

#[uretprobe]
fn uretprobe_strlen(probe: RetProbeContext) -> u32 {
    match unsafe { try_uretprobe_strlen(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "os_sanitizer_strlen_uretprobe"),
    }
}

#[inline(always)]
unsafe fn try_uretprobe_strlen(probe: &RetProbeContext) -> Result<u32, OsSanitizerError> {
    let pid_tgid = bpf_get_current_pid_tgid();
    update_tracking(pid_tgid, PassId::uretprobe_strlen);

    if IGNORED_PIDS.get(&((pid_tgid >> 32) as u32)).is_some() {
        return Ok(0);
    }

    let srclen: size_t = probe
        .ret()
        .ok_or(Unreachable("strlen has a return value"))?;

    let Some(&strptr) = STRLEN_PTR_MAP.get(&pid_tgid) else {
        return Ok(0);
    };
    STRLEN_PTR_MAP
        .remove(&pid_tgid)
        .map_err(|_| Unreachable("the value existed, so we must be able to remove it"))?;

    STRLEN_MAP
        .insert(&(pid_tgid, strptr), &srclen, 0)
        .map_err(|_| Unreachable("we should always be able to insert"))?;

    Ok(0)
}
