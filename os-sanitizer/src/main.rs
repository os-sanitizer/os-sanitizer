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

use cpp_demangle::DemangleOptions;
use once_cell::sync::Lazy;
use std::time::Duration;
use std::{
    ffi::{c_char, CStr},
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio::{signal, task};

const PROCMAP_CACHE_TIME: u64 = 30;
static DEMANGLE_OPTIONS: Lazy<DemangleOptions> = Lazy::new(DemangleOptions::new);

macro_rules! attach_fentry {
    ($bpf: expr, $btf: expr, $name: literal) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        print!("loading {} (fentry)...", $name);
        let _ = std::io::stdout().lock().flush();
        let program: &mut FEntry = $bpf
            .program_mut(concat!("fentry_", $name))
            .unwrap()
            .try_into()?;
        program.load($name, &$btf)?;
        program.attach()?;
        println!("done");
    };
}

macro_rules! attach_many_uprobe_uretprobe {
    ($program: ident, $name: literal, $variant: literal, [$library: literal, $function: literal]) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        let demangled = ::cpp_demangle::BorrowedSymbol::new($function.as_bytes()).ok().and_then(|mangled| mangled.demangle(&DEMANGLE_OPTIONS).ok()).unwrap_or_else(|| $function.to_string());
        print!("attaching {} {} to {}:{}...", $name, $variant, $library, demangled);
        $program.attach(Some($function), 0, $library, None)?;
        println!("done")
    };

    ($program: ident, $name: literal, $variant: literal, [$library: literal, $function: literal], $([$libraries: literal, $functions: literal]),+) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        let demangled = ::cpp_demangle::BorrowedSymbol::new($function.as_bytes()).ok().and_then(|mangled| mangled.demangle(&DEMANGLE_OPTIONS).ok()).unwrap_or_else(|| $function.to_string());
        print!("attaching {} {} to {}:{}...", $name, $variant, $library, demangled);
        let _ = std::io::stdout().lock().flush();
        if let Err(e) = $program.attach(Some($function), 0, $library, None) {
            println!("failed: {e}");
        } else {
            println!("done");
        }
        attach_many_uprobe_uretprobe!($program, $name, $variant, $([$libraries, $functions]),+)
    };
}

macro_rules! attach_uprobe {
    ($bpf: expr, $name: literal, $([$libraries: literal, $functions: literal]),+$(,)?) => {
        let program: &mut ::aya::programs::UProbe = $bpf
            .program_mut(concat!("uprobe_", $name))
            .unwrap()
            .try_into()?;
        program.load()?;
        attach_many_uprobe_uretprobe!(program, $name, "uprobe", $([$libraries, $functions]),+);
    };

    ($bpf: expr, $name: literal, $library: literal) => {
        attach_uprobe!($bpf, $name, [$library, $name])
    };
}

macro_rules! attach_uretprobe {
    ($bpf: expr, $name: literal, $([$libraries: literal, $functions: literal]),+$(,)?) => {
        let program: &mut ::aya::programs::UProbe = $bpf
            .program_mut(concat!("uretprobe_", $name))
            .unwrap()
            .try_into()?;
        program.load()?;
        attach_many_uprobe_uretprobe!(program, $name, "uretprobe", $([$libraries, $functions]),+);
    };

    ($bpf: expr, $name: literal, $library: literal) => {
        attach_uretprobe!($bpf, $name, [$library, $name])
    };
}

macro_rules! attach_uprobe_and_uretprobe {
    ($bpf: expr, $name: literal, $([$libraries: literal, $functions: literal]),+$(,)?) => {
        attach_uprobe!($bpf, $name, $([$libraries, $functions]),+);
        attach_uretprobe!($bpf, $name, $([$libraries, $functions]),+);
    };

    ($bpf: expr, $name: literal, $library: literal) => {
        attach_uprobe_and_uretprobe!($bpf, $name, [$library, $name])
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
    #[arg(long, help = "Log violations related to the use of `strcpy'")]
    strcpy: bool,
    #[arg(long, help = "Log violations related to the use of `sprintf'")]
    sprintf: bool,
    #[arg(
        long,
        help = "Log violations related to the use of `printf'-like functions with non-constant template parameters"
    )]
    printf_mutability: bool,

    #[arg(
        long,
        short,
        help = "Stack depth shown, or 0 to show the full stack.",
        default_value = "7"
    )]
    visibility_depth: usize,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();

    if !(args.access
        || args.gets
        || args.memcpy
        || args.security_file_open
        || args.strncpy
        || args.strcpy
        || args.sprintf
        || args.printf_mutability)
    {
        eprintln!("You must specify one of the modes.");
        <Args as CommandFactory>::command().print_help()?;
        exit(1);
    }

    let visibility_depth = if args.visibility_depth == 0 {
        usize::MAX
    } else {
        args.visibility_depth
    };

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

    let cached_procmaps = Arc::new(Mutex::new(
        HashMap::<u32, (Arc<ProcMap>, JoinHandle<()>)>::new(),
    ));

    for cpu_id in online_cpus()? {
        let mut buf = reports.open(cpu_id, None)?;
        {
            let stacktraces = stacktraces.clone();
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
                            OsSanitizerReport::PrintfMutability { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Sprintf { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Strcpy { executable, pid_tgid, stack_id, .. }
                              | OsSanitizerReport::Strncpy { executable, pid_tgid, stack_id, .. }
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
                                // update!
                                let mut lock = cached_procmaps.lock().await;
                                let handle = {
                                    let cached_procmaps = cached_procmaps.clone();
                                    tokio::spawn(async move {
                                        sleep(Duration::from_secs(PROCMAP_CACHE_TIME)).await;
                                        let mut lock = cached_procmaps.lock().await;
                                        let _ = lock.remove(&pid);
                                    })
                                };
                                if let Some((_, old)) = lock.insert(pid, (procmap.clone(), handle)) {
                                    old.abort();
                                }
                                Some(procmap)
                            } else {
                                // use the last available
                                let lock = cached_procmaps.lock().await;
                                lock.get(&pid).map(|(existing, _)| existing.clone())
                            }
                        };

                        let context = if pid == tgid {
                            format!("{executable} (pid: {pid})")
                        } else {
                            format!("{executable} (pid: {pid}, thread: {tgid})")
                        };

                        let (message, level) = match report {
                            OsSanitizerReport::PrintfMutability { template_param, template, .. } => {
                                if let Ok(template) = unsafe {
                                    CStr::from_ptr(template.as_ptr() as *const c_char).to_str()
                                } {
                                    // there seems to be a common (but annoying) pattern where vsnprintf is cut up and
                                    // called with individual format arguments
                                    // we skip the report if it looks like this is a standalone printf arg or not utf8

                                    // this is not done in ebpf because it causes some weird verifier issue

                                    // reeeeally basic printf specifier check
                                    if template.starts_with('%')
                                        && template[1..]
                                        .chars()
                                        .all(|c| "ldiuoxXfFeEgGaAcspn%#.*".contains(c))
                                    {
                                        continue;
                                    }
                                    (format!("{context} invoked a printf-like function with a non-constant template string located at 0x{template_param:x}: {template}"), Level::Warn)
                                } else {
                                    (format!("{context} invoked a printf-like function with a non-constant template string located at 0x{template_param:x}, but the template was not string-like"), Level::Warn)
                                }
                            }
                            OsSanitizerReport::Sprintf { dest, .. } => {
                                (format!("{context} invoked sprintf with stack dest pointer (dest: 0x{dest:x})"), Level::Warn)
                            }
                            OsSanitizerReport::Strcpy { len_checked: true, dest, src, .. } => {
                                (format!("{context} invoked strcpy with stack dest pointer with a length check (dest: 0x{dest:x}, src: 0x{src:x})"), Level::Info)
                            }
                            OsSanitizerReport::Strcpy { len_checked: false, dest, src, .. } => {
                                (format!("{context} invoked strcpy with stack dest pointer without a length check (dest: 0x{dest:x}, src: 0x{src:x})"), Level::Warn)
                            }
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
                            OsSanitizerReport::Open { i_mode, filename, variant, toctou, .. } => {
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

                                match (variant, toctou) {
                                    (OpenViolation::Perms, None) => {
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
                                    (OpenViolation::Toctou, Some(variant)) => {
                                        (format!("{context} opened `{filename}' (a {filetype}) after accessing it via {variant}, a known TOCTOU pattern"), Level::Info)
                                    }
                                    _ => unreachable!("Invalid combination of reporting data")
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
                                    || format!("#{i} 0x{:x}", frame.ip),
                                    move |(path, offset)| {
                                        if let Some(path) = path.to_str() {
                                            format!("#{i} 0x{:x}  ({path}+0x{offset:x})", frame.ip)
                                        } else {
                                            format!(
                                                "#{i} 0x{:x}  {}+0x{offset:x} (name adjusted for utf-8 compat)",
                                                frame.ip,
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
                                    .map(|(i, frame)| format!("#{i} 0x{:x}", frame.ip)),
                            )
                        };

                        let stacktrace = frame_iter
                            .enumerate()
                            .take_while(|(i, _)| *i <= visibility_depth)
                            .map(|(i, s)| {
                                if i == visibility_depth {
                                    "...".to_string()
                                } else {
                                    s
                                }
                            })
                            .collect::<Vec<_>>();

                        // since we can't follow these stacktraces, best skip them
                        let level = if stacktrace.len() <= 2 { Level::Info } else { level };

                        let stacktrace = stacktrace.join("\n");
                        log!(level, "{message}; stacktrace:\n{stacktrace}");
                    }
                }
            }));
        }
    }

    let btf = Btf::from_sys_fs()?;

    if args.security_file_open || args.access {
        attach_fentry!(bpf, btf, "security_file_open");
    }

    if args.memcpy || args.strncpy || args.strcpy {
        attach_uprobe_and_uretprobe!(
            bpf,
            "strlen",
            ["libc", "__strlen_avx2"],
            ["libc", "__strnlen_avx2"]
        );
    }

    if args.strcpy {
        attach_uprobe_and_uretprobe!(
            bpf,
            "strcpy_safe_wrapper",
            ["libc", "inet_ntop"],
            ["libc", "realpath"],
            ["libical", "icalrecur_iterator_new"],
            ["libicui18n", "ucol_open_72"],
            ["libicuuc", "ubrk_open_72"],
            ["libicuuc", "uloc_getDisplayName_72"],
            ["libicuuc", "uloc_getTableStringWithFallback_72"],
            ["libicuuc", "ures_getByIndex_72"],
            ["libicuuc", "ures_getByKey_72"],
            ["libicuuc", "ures_getByKeyWithFallback_72"],
            ["libicuuc", "ures_getNextResource_72"],
            [
                "libicuuc",
                "_ZN6icu_726Locale15setKeywordValueENS_11StringPieceES1_R10UErrorCode"
            ],
            [
                "libicuuc",
                "_ZN6icu_726Locale15setKeywordValueEPKcS2_R10UErrorCode"
            ],
            [
                "/usr/lib64/security/pam_gnome_keyring.so",
                "pam_sm_authenticate"
            ],
            [
                "/usr/lib64/security/pam_gnome_keyring.so",
                "pam_sm_open_session"
            ],
            ["libfontconfig", "FcFreeTypeQueryFace"],
            ["libfontconfig", "FcFreeTypeQuery"],
            ["libfontconfig", "FcFreeTypeQueryAll"],
        );
        attach_uprobe!(bpf, "strcpy", ["libc", "__strcpy_avx2"]);
    }

    if args.printf_mutability {
        attach_uprobe!(bpf, "printf_mutability", ["libc", "printf"]);
        attach_uprobe!(bpf, "vprintf_mutability", ["libc", "vprintf"]);

        attach_uprobe!(bpf, "fprintf_mutability", ["libc", "fprintf"]);
        attach_uprobe!(bpf, "dprintf_mutability", ["libc", "dprintf"]);
        attach_uprobe!(bpf, "sprintf_mutability", ["libc", "sprintf"]);
        attach_uprobe!(bpf, "snprintf_mutability", ["libc", "snprintf"]);
        attach_uprobe!(bpf, "vfprintf_mutability", ["libc", "vfprintf"]);
        attach_uprobe!(bpf, "vdprintf_mutability", ["libc", "vdprintf"]);
        attach_uprobe!(bpf, "vsprintf_mutability", ["libc", "vsprintf"]);
        attach_uprobe!(bpf, "vsnprintf_mutability", ["libc", "vsnprintf"]);
    }

    if args.sprintf {
        attach_uprobe_and_uretprobe!(
            bpf,
            "sprintf_safe_wrapper",
            ["libc", "inet_ntop"],
            ["libc", "__pthread_setname_np"],
        );
        attach_uprobe!(bpf, "sprintf", "libc");
    }

    if args.strncpy {
        attach_uprobe!(bpf, "strncpy", ["libc", "__strncpy_avx2"]);
    }

    if args.memcpy {
        attach_uprobe!(bpf, "memcpy", ["libc", "__memcpy_avx_unaligned_erms"]);
    }

    if args.access {
        attach_fentry!(bpf, btf, "do_faccessat");
        attach_fentry!(bpf, btf, "vfs_fstatat");
        attach_fentry!(bpf, btf, "do_statx");
        attach_fentry!(bpf, btf, "do_sys_openat2");
        attach_uprobe!(bpf, "access", "libc");
    }

    if args.gets {
        attach_uprobe!(bpf, "gets", "libc");
    }

    signal::ctrl_c().await?;

    Ok(())
}
