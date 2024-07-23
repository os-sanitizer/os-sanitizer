// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use crate::{REPORT_SCRATCH, STATS_QUEUE};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf_macros::{map, tracepoint};
use core::mem::variant_count;
use os_sanitizer_common::OsSanitizerError::{CouldntAccessBuffer, SerialisationError};
use os_sanitizer_common::{OsSanitizerError, OsSanitizerReport, PassId};

#[map]
static STATISTICS: LruHashMap<u64, [u64; variant_count::<PassId>()]> =
    LruHashMap::with_max_entries(1 << 16, 0);

// relieve some stack pressure
#[cfg(feature = "tracking")]
static DEFAULT_STATISTICS: [u64; variant_count::<PassId>()] = [0; variant_count::<PassId>()];

#[tracepoint]
fn tracepoint_sched_exit_stats(probe: TracePointContext) -> u32 {
    match unsafe { try_tracepoint_sched_exit_stats(&probe) } {
        Ok(res) => res,
        Err(e) => crate::emit_error(&probe, e, "sched_exit_stats_tracepoint"),
    }
}

unsafe fn try_tracepoint_sched_exit_stats(
    probe: &TracePointContext,
) -> Result<u32, OsSanitizerError> {
    if cfg!(feature = "tracking") {
        let executable: [u8; 16] = probe.read_at(8).map_err(|e| {
            OsSanitizerError::CouldntGetComm("tracepoint_sched_exit_stats comm from trace", e)
        })?;

        // comm only gives pid, but we want tgid too
        let pid_tgid = bpf_get_current_pid_tgid();

        if let Some(stats) = STATISTICS.get(&pid_tgid) {
            let report = OsSanitizerReport::Statistics {
                executable,
                pid_tgid,
                stats,
            };
            if stats.iter().all(|&e| e == 0) {
                return Ok(0); // no point in reporting this
            }

            let ptr = REPORT_SCRATCH
                .get_ptr_mut(0)
                .ok_or(CouldntAccessBuffer("emit-report"))?;
            let buf = &mut *ptr;
            report
                .serialise_into(buf)
                .map_err(|_| SerialisationError("emit-report"))?;
            STATS_QUEUE.output(probe, buf, 0);
        }

        let _ = STATISTICS.remove(&pid_tgid);
    }
    Ok(0)
}

#[cfg(feature = "tracking")]
#[inline(always)]
pub fn update_tracking(pid_tgid: u64, id: PassId) {
    unsafe {
        let statistics = if let Some(existing) = STATISTICS.get_ptr_mut(&pid_tgid) {
            &mut *existing
        } else {
            if STATISTICS
                .insert(&pid_tgid, &DEFAULT_STATISTICS, 0)
                .is_err()
            {
                return; // don't propagate errors
            }
            let Some(existing) = STATISTICS.get_ptr_mut(&pid_tgid) else {
                return;
            };
            &mut *existing
        };
        // this will not race on this entry as each pid_tgid can only be in one bpf program
        statistics[id as usize] += 1;
    }
}
#[cfg(not(feature = "tracking"))]
#[inline(always)]
pub fn update_tracking(_pid_tgid: u64, _id: PassId) {}
