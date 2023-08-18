mod resolver;

use crate::resolver::{ProcMap, ProcMapOffsetResolver};
use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, HashMap as AyaHashMap, StackTraceMap},
    programs::FEntry,
    util::online_cpus,
    Bpf, Btf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::{CommandFactory, Parser};
use either::Either;
use libc::pid_t;
use log::{debug, log, warn, Level};
use os_sanitizer_common::{CopyViolation, OpenViolation, OsSanitizerReport};
use std::collections::HashMap;

use std::time::Duration;
use std::{
    collections::HashSet,
    ffi::{c_char, CStr},
    process::exit,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;
use tokio::{signal, task};

const STACK_DEDUPLICATION_DEPTH: usize = 3;
const STACK_MAX_DISPLAYED: usize = 7;
const PROCMAP_CACHE_TIME: u64 = 30;

macro_rules! attach_fentry {
    ($bpf: expr, $btf: expr, $name: literal) => {
        let program: &mut FEntry = $bpf
            .program_mut(concat!("fentry_", $name))
            .unwrap()
            .try_into()?;
        program.load($name, &$btf)?;
        program.attach()?;
    };
}

macro_rules! attach_uprobe {
    ($bpf: expr, $name: literal, $function: literal, $library: literal) => {
        let program: &mut ::aya::programs::UProbe = $bpf
            .program_mut(concat!("uprobe_", $name))
            .unwrap()
            .try_into()?;
        program.load()?;
        program.attach(Some($function), 0, $library, None)?;
    };

    ($bpf: expr, $name: literal, $function: literal) => {
        attach_uprobe!($bpf, $name, $function, "libc")
    };

    ($bpf: expr, $name: literal) => {
        attach_uprobe!($bpf, $name, $name, "libc")
    };
}

macro_rules! attach_uretprobe {
    ($bpf: expr, $name: literal, $function: literal, $library: literal) => {
        let program: &mut ::aya::programs::UProbe = $bpf
            .program_mut(concat!("uretprobe_", $name))
            .unwrap()
            .try_into()?;
        program.load()?;
        program.attach(Some($function), 0, $library, None)?;
    };

    ($bpf: expr, $name: literal, $function: literal) => {
        attach_uretprobe!($bpf, $name, $function, "libc")
    };

    ($bpf: expr, $name: literal) => {
        attach_uretprobe!($bpf, $name, $name, "libc")
    };
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        help = "Log violations related to the use of `access' (`faccessat' and related syscalls)"
    )]
    access: bool,
    #[arg(long, help = "Log all uses of the `gets' function")]
    gets: bool,
    #[arg(
        long,
        help = "Log violations related to the use of `memcpy' (expensive and false-positive prone)"
    )]
    memcpy: bool,
    #[arg(
        long,
        help = "Log violations related to the opening of files (monitors the `security_file_open' kernel function)"
    )]
    security_file_open: bool,
    #[arg(
        long,
        help = "Log violations related to the use of `strncpy' (expensive)"
    )]
    strncpy: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();

    if !(args.access || args.gets || args.memcpy || args.security_file_open || args.strncpy) {
        eprintln!("You must specify one of the modes.");
        <Args as CommandFactory>::command().print_help()?;
        exit(1);
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/os-sanitizer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/os-sanitizer"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut ignored_pids: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(bpf.take_map("IGNORED_PIDS").unwrap())?;

    let this_pid = std::process::id();
    ignored_pids.insert(this_pid, 0, 0)?;

    let mut reports =
        AsyncPerfEventArray::try_from(bpf.take_map("FUNCTION_REPORT_QUEUE").unwrap())?;

    let stacktraces = Arc::new(StackTraceMap::try_from(
        bpf.take_map("STACKTRACES").unwrap(),
    )?);

    let keep_going = Arc::new(AtomicBool::new(true));
    let mut tasks = Vec::new();

    let cached_procmaps = Arc::new(Mutex::new(HashMap::new()));

    let observed_stacktraces = Arc::new(RwLock::new(HashSet::new()));

    for cpu_id in online_cpus()? {
        let mut buf = reports.open(cpu_id, None)?;
        {
            let stacktraces = stacktraces.clone();
            let observed_stacktraces = observed_stacktraces.clone();
            let cached_procmaps = cached_procmaps.clone();
            let keep_going = keep_going.clone();
            tasks.push(task::spawn(async move {
                let mut buffers = (0..32)
                    .map(|_| BytesMut::with_capacity(512))
                    .collect::<Vec<_>>();

                while keep_going.load(Ordering::Relaxed) {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let report = unsafe { (buf.as_ptr() as *const OsSanitizerReport).read_unaligned() };

                        let (executable, pid, tgid, stacktrace) = match report {
                            OsSanitizerReport::Strncpy { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Memcpy { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Open { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Access { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Gets { executable, pid_tgid, stack_id, .. } => {
                                let Ok(executable) = CStr::from_bytes_until_nul(&executable).unwrap().to_str() else {
                                    warn!("Couldn't recover the name of an executable.");
                                    continue;
                                };
                                let Ok(stacktrace) = stacktraces.get(&(stack_id as u32), 0) else {
                                    warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                    continue;
                                };
                                (executable.to_string(), (pid_tgid >> 32) as u32, pid_tgid as u32, stacktrace)
                            },
                        };

                        let procmap = {
                            if let Ok(procmap) = ProcMap::new(pid as pid_t).map(Arc::new) {
                                let mut cached_procmaps = cached_procmaps.lock().await;
                                cached_procmaps.insert(pid, Arc::downgrade(&procmap));
                                Some(procmap)
                            } else {
                                let cached_procmaps = cached_procmaps.lock().await;
                                cached_procmaps.get(&pid).and_then(|weak| weak.upgrade())
                            }
                        };

                        let context = if pid == tgid {
                            format!("{executable} (pid: {pid})")
                        } else {
                            format!("{executable} (pid: {pid}, thread: {tgid})")
                        };

                        let (message, level) = match report {
                            OsSanitizerReport::Strncpy { variant: CopyViolation::Strlen, len, dest, src, .. } => {
                                (format!("{context} invoked strncpy with src pointer determining copied length (dest: 0x{dest:x}, src: 0x{src:x}, len: {len})"), Level::Info)
                            }
                            OsSanitizerReport::Strncpy { variant: CopyViolation::Malloc, allocated, len, dest, src, .. } => {
                                (format!("{context} invoked strncpy with src pointer allocated with less length than specified available (dest: 0x{dest:x} (allocated: {allocated}), src: 0x{src:x}, len: {len})"), Level::Warn)
                            }
                            OsSanitizerReport::Memcpy { variant: CopyViolation::Strlen, len, dest, src, .. } => {
                                (format!("{context} invoked memcpy with src pointer determining copied length (dest: 0x{dest:x}, src: 0x{src:x}, len: {len})"), Level::Info)
                            }
                            OsSanitizerReport::Memcpy { variant: CopyViolation::Malloc, allocated, len, dest, src, .. } => {
                                (format!("{context} invoked memcpy with src pointer allocated with less length than specified available (dest: 0x{dest:x} (allocated: {allocated}), src: 0x{src:x}, len: {len})"), Level::Warn)
                            }
                            OsSanitizerReport::Open { i_mode, filename, variant, .. } => {
                                let Ok(filename) = (unsafe {
                                    CStr::from_ptr(filename.as_ptr() as *const c_char).to_str()
                                }) else {
                                    continue;
                                };

                                let filetype = i_mode >> 12;
                                let filetype = match filetype {
                                    0x1 => "fifo",
                                    0x2 => "chardev",
                                    0x4 => "directory",
                                    0x6 => "blockdev",
                                    0x8 => "file",
                                    0xA => "symlink",
                                    0xC => "socket",
                                    _ => unreachable!(),
                                };

                                match variant {
                                    OpenViolation::Perms => {
                                        let mut rendered = [0; 9];
                                        for (i, e) in rendered.iter_mut().enumerate() {
                                            let b = if i_mode & (0b1 << (9 - i - 1)) != 0 {
                                                match i % 3 {
                                                    0 => b'r',
                                                    1 => b'w',
                                                    2 => b'x',
                                                    _ => unreachable!(),
                                                }
                                            } else {
                                                b'-'
                                            };
                                            *e = b;
                                        }
                                        let rendered = core::str::from_utf8(&rendered).unwrap();

                                        if i_mode & 0xF000 == 0x8000 || i_mode & 0xF000 == 0x4000 {
                                            (format!("{context} opened `{filename}' (a {filetype}) with permissions {rendered}"), Level::Warn)
                                        } else {
                                            (format!("{context} opened `{filename}' (a {filetype}) with permissions {rendered}"), Level::Info)
                                        }
                                    }
                                    OpenViolation::Toctou => {
                                        (format!("{context} opened `{filename}' (a {filetype}) after accessing it via access, a known TOCTOU pattern"), Level::Warn)
                                    }
                                }
                            }
                            OsSanitizerReport::Access { .. } => {
                                (format!("{context} invoked access, which is a syscall wrapper explicitly warned against"), Level::Info)
                            }
                            OsSanitizerReport::Gets { .. } => {
                                (format!("{context} invoked gets, which is incredibly stupid"), Level::Error)
                            }
                        };

                        // only error condition is if rx is closed
                        let maybe_resolver =
                            procmap.as_ref().map(|procmap| ProcMapOffsetResolver::from(procmap.as_ref()));

                        let frame_iter = if let Some(resolver) = maybe_resolver.as_ref() {
                            Either::Left(stacktrace.frames().iter().enumerate().map(|(i, frame)| {
                                resolver.resolve_file_offset(frame.ip).map_or_else(
                                    || format!("{i}:\t0x{:x}", frame.ip),
                                    move |(path, offset)| {
                                        if let Some(path) = path.to_str() {
                                            format!("{i}:\t{path}+0x{offset:x}")
                                        } else {
                                            format!(
                                                "{i}:\t{}+0x{offset:x} (name adjusted for utf-8 compat)",
                                                path.to_string_lossy()
                                            )
                                        }
                                    },
                                )
                            }))
                        } else {
                            Either::Right(
                                stacktrace
                                    .frames()
                                    .iter()
                                    .enumerate()
                                    .map(|(i, frame)| format!("{i}:\t0x{:x}", frame.ip)),
                            )
                        };

                        let stacktrace = frame_iter
                            .enumerate()
                            .take_while(|(i, _)| *i <= STACK_MAX_DISPLAYED)
                            .map(|(i, s)| {
                                if i == STACK_MAX_DISPLAYED {
                                    "...".to_string()
                                } else {
                                    s
                                }
                            })
                            .collect::<Vec<_>>();

                        let deduplication_sequence = stacktrace
                            .iter()
                            .cloned()
                            .take_while(|s| {
                                s.split_once(':')
                                    .and_then(|(i, _)| usize::from_str(i).ok())
                                    .map_or(true, |i| i < STACK_DEDUPLICATION_DEPTH)
                            })
                            .collect::<Vec<_>>();

                        let stacktrace = stacktrace.join("\n");

                        let rlock = observed_stacktraces.read().await;
                        if !rlock.contains(&deduplication_sequence) {
                            log!(level, "{message}; stacktrace:\n{stacktrace}");
                            drop(rlock);
                            let mut wlock = observed_stacktraces.write().await;
                            wlock.insert(deduplication_sequence);
                        }

                        // send the procmap N seconds into the future to prevent it from being removed from the weak cache
                        if let Some(procmap) = procmap {
                            let cached_procmaps = cached_procmaps.clone();
                            tokio::spawn(async move {
                                sleep(Duration::from_secs(PROCMAP_CACHE_TIME)).await;
                                let weakened = Arc::downgrade(&procmap);
                                drop(procmap);
                                if weakened.upgrade().is_none() {
                                    let mut cached_procmaps = cached_procmaps.lock().await;
                                    let _ = cached_procmaps.remove(&pid);
                                }
                            });
                        }
                    }
                }
            }));
        }
    }

    let btf = Btf::from_sys_fs()?;

    if args.security_file_open || args.access {
        attach_fentry!(bpf, btf, "security_file_open");
    }

    if args.memcpy || args.strncpy {
        attach_uprobe!(bpf, "malloc", "__libc_malloc");
        attach_uretprobe!(bpf, "malloc", "__libc_malloc");

        attach_uprobe!(bpf, "realloc", "__libc_realloc");
        attach_uretprobe!(bpf, "realloc", "__libc_realloc");

        attach_uprobe!(bpf, "free", "__libc_free");

        attach_uprobe!(bpf, "strlen", "__strlen_avx2");
        attach_uretprobe!(bpf, "strlen", "__strlen_avx2");
    }

    if args.strncpy {
        attach_uprobe!(bpf, "strncpy", "__strncpy_avx2");
    }

    if args.memcpy {
        attach_uprobe!(bpf, "memcpy", "__memcpy_avx_unaligned_erms");
    }

    if args.access {
        attach_fentry!(bpf, btf, "do_faccessat");
        attach_fentry!(bpf, btf, "do_sys_openat2");
        attach_uprobe!(bpf, "access");
    }

    if args.gets {
        attach_uprobe!(bpf, "gets");
    }

    signal::ctrl_c().await?;

    Ok(())
}
