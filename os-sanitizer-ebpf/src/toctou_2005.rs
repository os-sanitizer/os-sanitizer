use core::hash::{Hash, Hasher};

use aya_ebpf::cty::c_void;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf_macros::{map, tracepoint};

use os_sanitizer_common::OsSanitizerError;
use os_sanitizer_common::OsSanitizerError::{CouldntGetComm, Unreachable};
use os_sanitizer_common::OsSanitizerReport::Toctou2005;

use crate::read_str;

#[map]
static CREATION_SET: LruHashMap<(u64, u64), u64> = LruHashMap::with_max_entries(1 << 16, 0);
#[map]
static REMOVE_SET: LruHashMap<(u64, u64), u64> = LruHashMap::with_max_entries(1 << 16, 0);
#[map]
static NORMAL_USE_SET: LruHashMap<(u64, u64), u64> = LruHashMap::with_max_entries(1 << 16, 0);
#[map]
static CHECK_SET: LruHashMap<(u64, u64), u64> = LruHashMap::with_max_entries(1 << 16, 0);

// we explicitly chose not to distinguish between File, Dir, and Link variants, since this is
// a) non-trivial to extract, and
// b) not important for the actual detection of these issues what flavor of file is used
#[derive(Copy, Clone)]
enum ToctouVariant {
    Creation,
    Remove,
    NormalUse,
    Check,
}

impl ToctouVariant {
    #[inline]
    fn as_map(&self) -> &'static LruHashMap<(u64, u64), u64> {
        match self {
            ToctouVariant::Creation => &CREATION_SET,
            ToctouVariant::Remove => &REMOVE_SET,
            ToctouVariant::Check => &CHECK_SET,
            ToctouVariant::NormalUse => &NORMAL_USE_SET,
        }
    }
}

// we macro this out to force unrolling because the verifier cannot work out how to access the maps
// if they are stored in an array
macro_rules! report_toctou {
    ($probe: ident, $key: ident, $pid_tgid: ident, $executable: ident, $stack_id: ident, $existing_stack: ident, $filename: ident, $map: ident) => {
        if let Some(&$existing_stack) = $map.get(&$key) {
            let report = Toctou2005 {
                executable: $executable,
                pid_tgid: $pid_tgid,
                stack_id: $stack_id,
                second_stack_id: $existing_stack,
                filename: $filename,
            };
            crate::emit_report($probe, &report)?;
        }
    };

    ($probe: ident, $key: ident, $pid_tgid: ident, $executable: ident, $stack_id: ident, $existing_stack: ident, $filename: ident, $map: ident, $($maps: ident),+) => {
        report_toctou!($probe, $key, $pid_tgid, $executable, $stack_id, $existing_stack, $filename, $map);
        report_toctou!($probe, $key, $pid_tgid, $executable, $stack_id, $existing_stack, $filename, $($maps),+);
    };
}

macro_rules! define_toctou_tracepoint {
    ($name: ident, $variant: expr, $offset: literal) => {
        ::paste::paste! {
            #[tracepoint]
            fn [< tracepoint_sched_enter_ $name >](probe: TracePointContext) -> u32 {
                match unsafe { [< try_tracepoint_sched_enter_ $name >](&probe) } {
                    Ok(res) => res,
                    Err(e) => crate::emit_error(&probe, e, concat!(concat!("os_sanitizer_sched_enter_", stringify!($name)), "_tracepoint")),
                }
            }

            unsafe fn [< try_tracepoint_sched_enter_ $name >](probe: &TracePointContext) -> Result<u32, OsSanitizerError> {
                let pid_tgid = bpf_get_current_pid_tgid();
                if let Ok(uptr) = probe.read_at($offset) {
                    let filename = read_str(uptr, "toctou filename")?;
                    let mut hasher = crate::Hasher::default();
                    filename.hash(&mut hasher);
                    let hash = hasher.finish();

                    let mut executable = [0; 16];
                    let stack_id = crate::report_stack_id(probe, "toctou stack ID")?;
                    let res = aya_ebpf::helpers::generated::bpf_get_current_comm(
                        executable.as_mut_ptr() as *mut c_void,
                        executable.len() as u32,
                    );
                    if res < 0 {
                        return Err(CouldntGetComm("toctou comm", res));
                    }

                    let key = (pid_tgid, hash);

                    match $variant {
                        ToctouVariant::Creation => {
                            report_toctou!(
                                probe,
                                key,
                                pid_tgid,
                                executable,
                                stack_id,
                                existing_stack,
                                filename,
                                CHECK_SET,
                                REMOVE_SET
                            );
                        }
                        ToctouVariant::NormalUse => {
                            report_toctou!(
                                probe,
                                key,
                                pid_tgid,
                                executable,
                                stack_id,
                                existing_stack,
                                filename,
                                CHECK_SET,
                                CREATION_SET,
                                NORMAL_USE_SET
                            );
                        }
                        ToctouVariant::Remove | ToctouVariant::Check => {
                            // do nothing; these have no previous
                        }
                    }

                    $variant
                        .as_map()
                        .insert(&key, &stack_id, 0)
                        .map_err(|_| Unreachable("Couldn't insert into corresponding set"))?;
                }
                Ok(0)
            }
        }
    };
}

define_toctou_tracepoint!(creation_arg0, ToctouVariant::Creation, 16);
define_toctou_tracepoint!(creation_arg1, ToctouVariant::Creation, 24);
define_toctou_tracepoint!(remove_arg0, ToctouVariant::Remove, 16);
define_toctou_tracepoint!(normal_use_arg0, ToctouVariant::NormalUse, 16);
define_toctou_tracepoint!(normal_use_arg1, ToctouVariant::NormalUse, 24);
define_toctou_tracepoint!(check_arg0, ToctouVariant::Check, 16);
define_toctou_tracepoint!(check_arg1, ToctouVariant::Check, 24);
