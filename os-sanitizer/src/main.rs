// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use aya::maps::PerfEventArray;
use aya::{
    Btf,
    maps::{Array as AyaArray, HashMap as AyaHashMap, StackTraceMap},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::{CommandFactory, Parser};
use cpp_demangle::DemangleOptions;
use either::Either;
use libc::{PROT_EXEC, pid_t};
use log::{Level, debug, log, warn};
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::{
    ffi::{CStr, c_char},
    process::exit,
    sync::Arc,
};
use tokio::io::unix::AsyncFd;
use tokio::process::Command;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio::{signal, task};
use users::{get_group_by_gid, get_user_by_uid};

use os_sanitizer_common::{
    CopyViolation, FixedMmapViolation, OpenViolation, OsSanitizerReport, ProgId, SERIALIZED_SIZE,
    SnprintfViolation,
};

use crate::resolver::{ProcMap, ProcMapOffsetResolver};

mod resolver;

const PROCMAP_CACHE_TIME: u64 = 30;
static DEMANGLE_OPTIONS: Lazy<DemangleOptions> = Lazy::new(DemangleOptions::new);

macro_rules! attach_fexit {
    ($bpf: expr, $btf: expr, $name: literal, $progname: literal) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        print!("loading {} (fexit: {})...", $progname, $name);
        let _ = std::io::stdout().lock().flush();
        let program: &mut ::aya::programs::FExit = $bpf
            .program_mut(concat!("fexit_", $progname))
            .unwrap()
            .try_into()?;
        program.load($name, &$btf)?;
        program.attach()?;
        println!("done");
    };

    ($bpf: expr, $btf: expr, $name: literal) => {
        attach_fexit!($bpf, $btf, $name, $name)
    };
}

macro_rules! attach_fentry {
    ($bpf: expr, $btf: expr, $name: literal, $progname: literal) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        print!("loading {} (fentry: {})...", $progname, $name);
        let _ = std::io::stdout().lock().flush();
        let program: &mut ::aya::programs::FEntry = $bpf
            .program_mut(concat!("fentry_", $progname))
            .unwrap()
            .try_into()?;
        program.load($name, &$btf)?;
        program.attach()?;
        println!("done");
    };

    ($bpf: expr, $btf: expr, $name: literal) => {
        attach_fentry!($bpf, $btf, $name, $name)
    };
}

macro_rules! attach_lsm {
    ($bpf: expr, $btf: expr, $name: literal, $progname: literal) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        print!("loading {} (lsm: {})...", $progname, $name);
        let _ = std::io::stdout().lock().flush();
        let program: &mut ::aya::programs::Lsm = $bpf
            .program_mut(concat!("lsm_", $progname))
            .unwrap()
            .try_into()?;
        program.load($name, &$btf)?;
        program.attach()?;
        println!("done");
    };

    ($bpf: expr, $btf: expr, $name: literal) => {
        attach_lsm!($bpf, $btf, $name, $name)
    };
}

macro_rules! attach_many_tracepoint {
    ($program: ident, $progname: literal, [$category: literal, $name: literal]) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        print!("attaching {} to {}/{}...", $progname, $category, $name);
        $program.attach($category, $name)?;
        println!("done")
    };

    ($program: ident, $progname: literal, [$category: literal, $name: literal], $([$categories: literal, $names: literal]),+) => {
        attach_many_tracepoint!($program, $progname, [$category, $name]);
        attach_many_tracepoint!($program, $progname, $([$categories, $names]),+)
    };
}

macro_rules! attach_tracepoint {
    ($bpf: expr, $progname: literal, $([$categories: literal, $names: literal]),+$(,)?) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        print!("loading tracepoint_{}...", $progname);
        let _ = std::io::stdout().lock().flush();
        let program: &mut ::aya::programs::TracePoint = $bpf
            .program_mut(concat!("tracepoint_", $progname))
            .unwrap()
            .try_into()?;
        program.load()?;
        println!("done");
        attach_many_tracepoint!(program, $progname, $([$categories, $names]),+)
    };
}

macro_rules! attach_many_uprobe_uretprobe {
    ($program: ident, $name: literal, $variant: literal, [$library: literal, $function: literal]) => {
        #[allow(unused_imports)]
        use ::std::io::Write as _;

        let demangled = ::cpp_demangle::BorrowedSymbol::new($function.as_bytes()).ok().and_then(|mangled| mangled.demangle(&DEMANGLE_OPTIONS).ok()).unwrap_or_else(|| $function.to_string());
        print!("attaching {} {} to {}:{}...", $name, $variant, $library, demangled);
        if let Err(e) = $program.attach($function, $library, None, None) {
            println!("failed: {e}");
        } else {
            println!("done");
        }
    };

    ($program: ident, $name: literal, $variant: literal, [$library: literal, $function: literal], $([$libraries: literal, $functions: literal]),+) => {
        attach_many_uprobe_uretprobe!($program, $name, $variant, [$library, $function]);
        attach_many_uprobe_uretprobe!($program, $name, $variant, $([$libraries, $functions]),+)
    };
}

macro_rules! attach_uprobe {
    ($bpf: expr, $name: literal, $([$libraries: literal, $functions: literal]),+$(,)?) => {
        print!(concat!(concat!("loading uprobe_", $name), "..."));
        let _ = std::io::stdout().lock().flush();
        let program: &mut ::aya::programs::UProbe = $bpf
            .program_mut(concat!("uprobe_", $name))
            .unwrap()
            .try_into()?;
        program.load()?;
        println!("done");
        attach_many_uprobe_uretprobe!(program, $name, "uprobe", $([$libraries, $functions]),+);
    };

    ($bpf: expr, $name: literal, $library: literal) => {
        attach_uprobe!($bpf, $name, [$library, $name])
    };
}

macro_rules! attach_uretprobe {
    ($bpf: expr, $name: literal, $([$libraries: literal, $functions: literal]),+$(,)?) => {
        print!(concat!(concat!("loading uretprobe_", $name), "..."));
        let _ = std::io::stdout().lock().flush();
        let program: &mut ::aya::programs::UProbe = $bpf
            .program_mut(concat!("uretprobe_", $name))
            .unwrap()
            .try_into()?;
        program.load()?;
        println!("done");
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
        help = "Log violations related to the accessing of files (TOCTOU)"
    )]
    access: bool,
    #[arg(long, help = "Log all uses of the `gets' function")]
    gets: bool,
    #[arg(long, help = "Log all uses of RWX memory")]
    rwx_mem: bool,
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
        help = "Log violations related to the use of the return value of `snprintf' to determine a future write"
    )]
    snprintf: bool,
    #[arg(
        long,
        help = "Log violations related to the use of `printf'-like functions with non-constant template parameters"
    )]
    printf_mutability: bool,
    #[arg(
        long,
        help = "Log violations related to the use of system with non-constant command parameters"
    )]
    system_mutability: bool,
    #[arg(
        long,
        help = "Log violations related to the use of system with non-absolute command parameters"
    )]
    system_absolute: bool,
    #[arg(
        long,
        help = "Log violations of file pointer `_unlocked' functions being used on multiple threads"
    )]
    filep_unlocked: bool,
    #[arg(long, help = "Log violations of mmap being used with fixed addresses")]
    fixed_mmap: bool,
    #[arg(
        long,
        help = "Log violations of open being used on interceptable paths"
    )]
    interceptable_path: bool,
    #[arg(
        long,
        help = "TOCTOUs from: https://webpages.charlotte.edu/jwei8/Jinpeng_Homepage_files/toctou-fast05.pdf"
    )]
    toctou_2005: bool,
    #[arg(
        long,
        help = "Log potential Leaky Vessel issues; see: https://www.bleepingcomputer.com/news/security/leaky-vessels-flaws-allow-hackers-to-escape-docker-runc-containers Note: not included in option --all"
    )]
    leaky_vessel: bool,

    #[arg(long, help = "Enable all reporting strategies except --leaky-vessel")]
    all: bool,

    #[arg(
        long,
        help = "Enable recommended set of reporting strategies. Includes all except --memcpy, --strcpy, --strncpy, and --leaky-vessel for reduced performance impact."
    )]
    reference_policy: bool,

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
    let mut args = Args::parse();

    if args.all {
        args.access = true;
        args.gets = true;
        args.rwx_mem = true;
        args.memcpy = true;
        args.security_file_open = true;
        args.strncpy = true;
        args.strcpy = true;
        args.sprintf = true;
        args.snprintf = true;
        args.printf_mutability = true;
        args.system_mutability = true;
        args.system_absolute = true;
        args.filep_unlocked = true;
        args.fixed_mmap = true;
        args.interceptable_path = true;
        args.leaky_vessel = true;
        args.toctou_2005 = true;
    }

    if args.reference_policy {
        args.access = true;
        args.gets = true;
        args.rwx_mem = true;
        // args.memcpy = true;
        args.security_file_open = true;
        // args.strncpy = true;
        // args.strcpy = true;
        args.sprintf = true;
        args.snprintf = true;
        args.printf_mutability = true;
        args.system_mutability = true;
        args.system_absolute = true;
        args.filep_unlocked = true;
        args.fixed_mmap = true;
        args.interceptable_path = true;
        args.leaky_vessel = true;
    }

    if !(args.access
        || args.gets
        || args.rwx_mem
        || args.memcpy
        || args.security_file_open
        || args.strncpy
        || args.strcpy
        || args.sprintf
        || args.snprintf
        || args.printf_mutability
        || args.system_mutability
        || args.system_absolute
        || args.filep_unlocked
        || args.fixed_mmap
        || args.interceptable_path
        || args.leaky_vessel
        || args.toctou_2005)
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

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/os-sanitizer"
    )))?;
    // if let Err(e) = EbpfLogger::init(&mut bpf) {
    //     // This can happen if you remove all log statements from your eBPF program.
    //     warn!("failed to initialize eBPF logger: {}", e);
    // }

    let mut ignored_pids: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(bpf.take_map("IGNORED_PIDS").unwrap())?;

    let this_pid = std::process::id();
    ignored_pids.insert(this_pid, 0, 0)?;

    let mut reports = PerfEventArray::try_from(bpf.take_map("FUNCTION_REPORT_QUEUE").unwrap())?;
    let mut stats = PerfEventArray::try_from(bpf.take_map("STATS_QUEUE").unwrap())?;

    let stacktraces = Arc::new(StackTraceMap::try_from(
        bpf.take_map("STACKTRACES").unwrap(),
    )?);

    let (tx, _rx) = broadcast::channel(1);
    let mut tasks = Vec::new();

    let cached_procmaps = Arc::new(Mutex::new(
        HashMap::<u32, (Arc<ProcMap>, JoinHandle<()>)>::new(),
    ));

    let counters_map: Arc<HashMap<&str, (&[ProgId], [AtomicUsize; 5])>> =
        Arc::new(HashMap::from([
            (
                "access",
                (
                    &[
                        ProgId::fentry_do_faccessat,
                        ProgId::fentry_vfs_fstatat,
                        ProgId::fentry_do_statx,
                        ProgId::fentry_do_sys_openat2,
                    ][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "fixed_mmap",
                (
                    &[ProgId::fentry_fixed_mmap][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "rwx_mem",
                (
                    &[ProgId::fentry_vma_set_page_prot][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "filep_unlocked",
                (
                    &[ProgId::check_filep_usage][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "gets",
                (
                    &[ProgId::uprobe_gets][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "snprintf",
                (
                    &[ProgId::uprobe_snprintf][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "printf_mut",
                (
                    &[ProgId::check_printf_mutability][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "system_mut",
                (
                    &[ProgId::check_system_mutability][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "system_abs",
                (
                    &[ProgId::check_system_absolute][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "sec_file_open",
                (
                    &[ProgId::fentry_security_file_open][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "intercept_path",
                (
                    &[ProgId::fentry_do_filp_open][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "memcpy",
                (
                    &[ProgId::uprobe_memcpy][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "strcpy",
                (
                    &[ProgId::uprobe_strcpy][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "strncpy",
                (
                    &[ProgId::uprobe_strncpy][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "sprintf",
                (
                    &[ProgId::uprobe_sprintf][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
            (
                "leaky_vessel",
                (
                    &[ProgId::uprobe_sprintf][..],
                    [const { AtomicUsize::new(0) }; 5],
                ),
            ),
        ]));

    for cpu_id in online_cpus().map_err(|(_, e)| e)? {
        for source in [&mut reports, &mut stats] {
            let mut buf = AsyncFd::new(source.open(cpu_id, None)?)?;
            {
                let stacktraces = stacktraces.clone();
                let cached_procmaps = cached_procmaps.clone();
                let counters_map = counters_map.clone();
                let mut rx = tx.subscribe();
                tasks.push(task::spawn(async move {
                    let mut buffers = (0..32)
                        .map(|_| BytesMut::with_capacity(SERIALIZED_SIZE))
                        .collect::<Vec<_>>();
                    loop {
                        let mut buf = tokio::select! {
                            biased;
                            _ = rx.recv() => break,
                            buf = buf.readable_mut() => buf,
                        }.unwrap();
                        let events = buf.get_inner_mut().read_events(&mut buffers).unwrap();
                        buf.clear_ready();
                        for buf in buffers.iter_mut().take(events.read) {
                            let report = buf.iter().as_slice();
                            let Ok(report) = OsSanitizerReport::try_from(report) else {
                                warn!("Failed to deserialise a report.");
                                continue;
                            };
                            let stacktraces = stacktraces.clone();
                            let cached_procmaps = cached_procmaps.clone();
                            let counters_map = counters_map.clone();
                            task::spawn(async move {
                                let (executable, pid, thread, stacktrace) = match report {
                                    OsSanitizerReport::PrintfMutability { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::SystemMutability { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::SystemAbsolute { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::FilePointerLocking { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Snprintf { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Sprintf { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Strcpy { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Strncpy { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Memcpy { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Open { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::UnsafeOpen { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Access { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Gets { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::RwxVma { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::FixedMmap { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::LeakyVessel { executable, pid_tgid, stack_id, .. }
                                    | OsSanitizerReport::Toctou2005 { executable, pid_tgid, stack_id, .. }
                                    => {
                                        let Ok(executable) = CStr::from_bytes_until_nul(&executable).unwrap().to_str() else {
                                            warn!("Couldn't recover the name of an executable.");
                                            return;
                                        };
                                        let Ok(stacktrace) = stacktraces.get(&(stack_id as u32), 0) else {
                                            warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                            return;
                                        };
                                        (executable.to_string(), (pid_tgid >> 32) as u32, pid_tgid as u32, stacktrace)
                                    },
                                    OsSanitizerReport::Statistics { executable, pid_tgid, stats } => {
                                        let Ok(executable) = CStr::from_bytes_until_nul(&executable).unwrap().to_str() else {
                                            warn!("Couldn't recover the name of an executable.");
                                            return;
                                        };

                                        let pid = (pid_tgid >> 32) as u32;
                                        let thread = pid_tgid as u32;

                                        let context = if pid == thread {
                                            format!("{executable} (pid: {pid})")
                                        } else {
                                            format!("{executable} (pid: {pid}, thread: {thread})")
                                        };

                                        let entries = stats.into_iter().enumerate().filter(|&(_, e)| e != 0).map(|(id, e)| (ProgId::from_repr(id).expect("invalid pass id"), e))
                                            .map(|(id, e)| format!("\n  {id:?} observed {e} times")).collect::<Vec<_>>().join("");

                                        debug!("{context} terminated with the following statistics:{entries}");

                                        return;
                                    }
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

                                // not actually allocated unless we give an element
                                let mut extra_stacktraces = Vec::new();

                                let context = if pid == thread {
                                    format!("{executable} (pid: {pid})")
                                } else {
                                    format!("{executable} (pid: {pid}, thread: {thread})")
                                };

                                let pass = report.pass();
                                let (message, level) = match report {
                                    OsSanitizerReport::PrintfMutability { template_param, template, .. } => {
                                        if let Ok(template) = unsafe {
                                            CStr::from_ptr(template.as_ptr() as *const c_char).to_str()
                                        } {
                                            let template = template.trim();
                                            // there seems to be a common (but annoying) pattern where vsnprintf is cut up and
                                            // called with individual format arguments
                                            // we skip the report if it looks like this is a standalone printf arg or not utf8

                                            // this is not done in ebpf because it causes some weird verifier issue

                                            // reeeeally basic printf specifier check
                                            if template.starts_with('%')
                                                && template
                                                .chars()
                                                .all(|c| "ldiuoxXfFeEgGaAcspn%#.*0123456789-".contains(c))
                                            {
                                                return;
                                            }
                                            (format!("{context} invoked a printf-like function with a non-constant template string located at 0x{template_param:x}: {template}"), Level::Warn)
                                        } else {
                                            (format!("{context} invoked a printf-like function with a non-constant template string located at 0x{template_param:x}, but the template was not string-like"), Level::Warn)
                                        }
                                    }
                                    OsSanitizerReport::SystemMutability { command_param, command, .. } => {
                                        if let Ok(command) = unsafe {
                                            CStr::from_ptr(command.as_ptr() as *const c_char).to_str()
                                        } {
                                            (format!("{context} invoked system with a non-constant command string located at 0x{command_param:x}: {command}"), Level::Warn)
                                        } else {
                                            (format!("{context} invoked system with a non-constant command string located at 0x{command_param:x}, but the command was not string-like"), Level::Warn)
                                        }
                                    }
                                    OsSanitizerReport::SystemAbsolute { command_param, command, .. } => {
                                        if let Ok(command) = unsafe {
                                            CStr::from_ptr(command.as_ptr() as *const c_char).to_str()
                                        } {
                                            (format!("{context} invoked system with a non-absolute command string located at 0x{command_param:x}: {command}"), Level::Warn)
                                        } else {
                                            (format!("{context} invoked system with a non-absolute command string located at 0x{command_param:x}, but the command was not string-like"), Level::Warn)
                                        }
                                    }
                                    OsSanitizerReport::FilePointerLocking { .. } => {
                                        (format!("{context} invoked a FILE* function with unlocked in another thread from a usage of another FILE* function"), Level::Warn)
                                    }
                                    OsSanitizerReport::Snprintf { srcptr, size, computed, count, kind, second_stack_id, .. } => {
                                        let warning_string = if kind == SnprintfViolation::DefiniteLeak {
                                            "which exceeded the originally specified length"
                                        } else {
                                            "which might leak"
                                        };
                                        let Ok(stacktrace) = stacktraces.get(&(second_stack_id as u32), 0) else {
                                            warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                            return;
                                        };
                                        extra_stacktraces.push(stacktrace);
                                        (format!("{context} invoked a write syscall of an snprintf-constructed string ({srcptr:#x}) using the computed length from snprintf, {warning_string} (wrote {count}, computed {computed}, restricted size {size})"), Level::Warn)
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
                                    OsSanitizerReport::Open { i_mode, filename, variant, .. } => {
                                        let Ok(filename) = (unsafe {
                                            CStr::from_ptr(filename.as_ptr() as *const c_char).to_str()
                                        }) else {
                                            return;
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
                                                    let level = if Command::new("ls")
                                                        .arg(filename)
                                                        .uid(0x1337).gid(0x1337)
                                                        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                                                        .status().await
                                                        .map_or(false, |v| v.success()) {
                                                        Level::Error
                                                    } else {
                                                        Level::Warn
                                                    };
                                                    (format!("{context} opened `{filename}' (a {filetype}) with permissions {rendered}"), level)
                                                } else {
                                                    (format!("{context} opened `{filename}' (a {filetype}) with permissions {rendered}"), Level::Info)
                                                }
                                            }
                                            OpenViolation::Toctou(variant, second_stack_id) => {
                                                let Ok(stacktrace) = stacktraces.get(&(second_stack_id as u32), 0) else {
                                                    warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                                    return;
                                                };
                                                extra_stacktraces.push(stacktrace);
                                                (format!("{context} opened `{filename}' (a {filetype}) after accessing it via {variant}, a known TOCTOU pattern"), Level::Info)
                                            }
                                        }
                                    }
                                    OsSanitizerReport::UnsafeOpen {
                                        original, filename, uid, gid, uids, gids, mask, everyone, ..
                                    } => {
                                        let Ok(filename) = CStr::from_bytes_until_nul(filename.as_slice()).map(|s| s.to_string_lossy()) else {
                                            return;
                                        };
                                        let Ok(original) = (if let Some(original) = &original {
                                            CStr::from_bytes_until_nul(original.as_slice()).map(|s| s.to_string_lossy())
                                        } else {
                                            Ok(Cow::from("<unrecoverable>"))
                                        }) else {
                                            return;
                                        };
                                        let uids = uids.into_iter().take_while(|i| *i != 0).map(|uid| get_user_by_uid(uid).map_or_else(|| uid.to_string(), |user| {
                                            user.name().to_string_lossy().to_string()
                                        })).collect::<Vec<_>>().join(",");
                                        let gids = gids.into_iter().take_while(|i| *i != 0).map(|gid| get_group_by_gid(gid).map_or_else(|| gid.to_string(), |group| {
                                            group.name().to_string_lossy().to_string()
                                        })).collect::<Vec<_>>().join(",");
                                        let level = if mask & 0x1 != 0 {
                                            Level::Error
                                        } else if uid == 0 || gid == 0 {
                                            Level::Warn
                                        } else {
                                            Level::Info
                                        };
                                        let uid = get_user_by_uid(uid).map_or_else(|| uid.to_string(), |user| {
                                            user.name().to_string_lossy().to_string()
                                        });
                                        let gid = get_group_by_gid(gid).map_or_else(|| gid.to_string(), |group| {
                                            group.name().to_string_lossy().to_string()
                                        });
                                        let mut perms = Vec::new();
                                        {
                                            let mut i = 1;
                                            static PERM_ITER: [&str; 8] = ["MAY_EXEC", "MAY_WRITE", "MAY_READ", "MAY_APPEND", "MAY_ACCESS", "MAY_OPEN", "MAY_CHDIR", "MAY_NOT_BLOCK"];
                                            for perm in PERM_ITER {
                                                if i & mask != 0 {
                                                    perms.push(perm);
                                                }
                                                i <<= 1;
                                            }
                                        }
                                        let and_everyone = if everyone {
                                            ", as well as everyone else"
                                        } else {
                                            ""
                                        };
                                        (format!("{context}, acting as {uid}:{gid}, attempted to access {filename} (originally as {original}) with {perms:?} ({mask:#x}), which may be intercepted by uids [{uids}] and gids [{gids}]{and_everyone}"), level)
                                    }
                                    OsSanitizerReport::Access { .. } => {
                                        (format!("{context} invoked access, which is a syscall wrapper explicitly warned against"), Level::Info)
                                    }
                                    OsSanitizerReport::Gets { .. } => {
                                        (format!("{context} invoked gets, which is incredibly stupid"), Level::Error)
                                    }
                                    OsSanitizerReport::RwxVma { start, end, .. } => {
                                        (format!("{context} updated a memory region at {start:#x}-{end:#x} to be simultaneously writable and executable"), Level::Warn)
                                    }
                                    OsSanitizerReport::FixedMmap { protection, variant, .. } => {
                                        match variant {
                                            FixedMmapViolation::HintUsed => {
                                                if protection & PROT_EXEC as u64 != 0 {
                                                    (format!("{context} attempted to map an executable memory region at a fixed address"), Level::Warn)
                                                } else {
                                                    (format!("{context} attempted to map an non-executable memory region at a fixed address"), Level::Info)
                                                }
                                            }
                                            FixedMmapViolation::FixedMmapUnmapped => {
                                                (format!("{context} mapped a memory region with MAP_FIXED without preallocating at the same region"), Level::Warn)
                                            }
                                            FixedMmapViolation::FixedMmapBadProt => {
                                                (format!("{context} mapped a memory region with MAP_FIXED on a memory region which was allocated with non-zero protections"), Level::Info)
                                            }
                                        }
                                    }
                                    OsSanitizerReport::LeakyVessel { orig_pid, orig_uid, chdir_stack, setuid_stack, .. } => {
                                        let (msg, level) = if setuid_stack != 0 {
                                            let Ok(stacktrace) = stacktraces.get(&(setuid_stack as u32), 0) else {
                                                warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                                return;
                                            };
                                            extra_stacktraces.push(stacktrace);
                                            ("running as root before performing setuid", Level::Error)
                                        } else if orig_uid != 0 {
                                            ("a low-privilege process", Level::Info)
                                        } else {
                                            ("running as root", Level::Warn)
                                        };

                                        let Ok(stacktrace) = stacktraces.get(&(chdir_stack as u32), 0) else {
                                            warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                            return;
                                        };
                                        extra_stacktraces.push(stacktrace);

                                        (format!("{context} (originally pid: {orig_pid}), {msg}, exec'd after chdir following fork, which may constitute a leaky vessel vulnerability"), level)
                                    }
                                    OsSanitizerReport::Toctou2005 { second_stack_id, filename, .. } => {
                                        let Ok(filename) = CStr::from_bytes_until_nul(filename.as_slice()).map(|s| s.to_string_lossy()) else {
                                            return;
                                        };
                                        let Ok(stacktrace) = stacktraces.get(&(second_stack_id as u32), 0) else {
                                            warn!("Couldn't recover the stacktrace of the executable {executable}.");
                                            return;
                                        };
                                        extra_stacktraces.push(stacktrace);

                                        (format!("{context} performed a pattern known to induce TOCTOU on the path {filename}"), Level::Warn)
                                    }
                                    OsSanitizerReport::Statistics { .. } => unreachable!("Handled in an earlier branch.")
                                };

                                // only error condition is if rx is closed
                                let maybe_resolver =
                                    procmap.as_ref().map(|procmap| ProcMapOffsetResolver::from(procmap.as_ref()));

                                let frame_iter = if let Some(resolver) = maybe_resolver.as_ref() {
                                    Either::Left(stacktrace.frames().iter().enumerate().chain(extra_stacktraces.iter().flat_map(|s| s.frames().iter().enumerate())).flat_map(|(i, frame)| {
                                        match i.cmp(&visibility_depth) {
                                            core::cmp::Ordering::Less => {
                                                let spacing = if i == 0 { "\n" } else { "" };
                                                Some(Cow::from(resolver.resolve_file_offset(frame.ip).map_or_else(
                                                    || format!("{spacing}#{i} 0x{:x}", frame.ip),
                                                    move |(path, offset)| {
                                                        if let Some(path) = path.to_str() {
                                                            format!("{spacing}#{i} 0x{:x}  ({path}+0x{offset:x})", frame.ip)
                                                        } else {
                                                            format!(
                                                                "{spacing}#{i} 0x{:x}  {}+0x{offset:x} (name adjusted for utf-8 compat)",
                                                                frame.ip,
                                                                path.to_string_lossy()
                                                            )
                                                        }
                                                    },
                                                )))
                                            }
                                            core::cmp::Ordering::Equal => Some(Cow::from("...")),
                                            core::cmp::Ordering::Greater => None,
                                        }
                                    }))
                                } else {
                                    Either::Right(
                                        stacktrace
                                            .frames()
                                            .iter()
                                            .enumerate().chain(extra_stacktraces.iter().flat_map(|s| s.frames().iter().enumerate()))
                                            .flat_map(|(i, frame)| {
                                                match i.cmp(&visibility_depth) {
                                                    core::cmp::Ordering::Less => {
                                                        let spacing = if i == 0 { "\n" } else { "" };
                                                        Some(Cow::from(format!("{spacing}#{i} 0x{:x}", frame.ip)))
                                                    }
                                                    core::cmp::Ordering::Equal => Some(Cow::from("...")),
                                                    core::cmp::Ordering::Greater => None,
                                                }
                                            }),
                                    )
                                };

                                let stacktrace = frame_iter
                                    .collect::<Vec<_>>();

                                // since we can't follow these stacktraces, best skip them
                                // let level = if stacktrace.len() <= 2 { Level::Info } else { level };

                                let stacktrace = stacktrace.join("\n");
                                log!(level, "{message}; stacktrace:{stacktrace}");
                                let (_, counters) = &counters_map[pass];
                                counters[level as usize - 1].fetch_add(1, Ordering::SeqCst);
                            });
                        }
                    }
                }));
            }
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
            ["libc", "__strlen_avx2_rtm"],
            ["libc", "__strlen_sse2"],
            ["libc", "__strlen_evex"],
            ["libc", "__strlen_evex512"],
            ["libc", "__strnlen_avx2"],
            ["libc", "__strnlen_avx2_rtm"],
            ["libc", "__strnlen_sse2"],
            ["libc", "__strnlen_evex"],
            ["libc", "__strnlen_evex512"]
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
            ["libicui18n", "ucol_open_73"],
            ["libicuuc", "ubrk_open_73"],
            ["libicuuc", "uloc_getDisplayName_73"],
            ["libicuuc", "uloc_getTableStringWithFallback_73"],
            ["libicuuc", "ures_getByIndex_73"],
            ["libicuuc", "ures_getByKey_73"],
            ["libicuuc", "ures_getByKeyWithFallback_73"],
            ["libicuuc", "ures_getNextResource_73"],
            [
                "libicuuc",
                "_ZN6icu_726Locale15setKeywordValueENS_11StringPieceES1_R10UErrorCode"
            ],
            [
                "libicuuc",
                "_ZN6icu_726Locale15setKeywordValueEPKcS2_R10UErrorCode"
            ],
            [
                "libicuuc",
                "_ZN6icu_736Locale15setKeywordValueENS_11StringPieceES1_R10UErrorCode"
            ],
            [
                "libicuuc",
                "_ZN6icu_736Locale15setKeywordValueEPKcS2_R10UErrorCode"
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
        attach_uprobe!(
            bpf,
            "strcpy",
            ["libc", "__strcpy_avx2"],
            ["libc", "__strcpy_avx2_rtm"],
            ["libc", "__strcpy_sse2"],
            ["libc", "__strcpy_sse2_unaligned"],
            ["libc", "__strcpy_evex"]
        );
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

    if args.system_mutability {
        attach_uprobe!(bpf, "system_mutability", ["libc", "system"]);
    }

    if args.system_absolute {
        attach_uprobe!(bpf, "system_absolute", ["libc", "system"]);
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

    if args.snprintf {
        // write detection
        attach_fentry!(bpf, btf, "vfs_write", "vfs_write_snprintf");
        attach_uprobe!(
            bpf,
            "xsputn_sprintf",
            ["libc", "_IO_new_file_xsputn"],
            ["libc", "_IO_default_xsputn"],
            ["libc", "_IO_old_file_xsputn"],
        );

        // snprintf init
        attach_uprobe_and_uretprobe!(bpf, "snprintf", ["libc", "snprintf"], ["libc", "vsnprintf"]);
    }

    if args.strncpy {
        attach_uprobe_and_uretprobe!(bpf, "strncpy_safe_wrapper", ["libglib-2.0", "g_strndup"]);
        attach_uprobe!(
            bpf,
            "strncpy",
            ["libc", "__strncpy_avx2"],
            ["libc", "__strncpy_avx2_rtm"],
            ["libc", "__strncpy_sse2_unaligned"],
            ["libc", "__strncpy_evex"]
        );
    }

    if args.memcpy {
        attach_uprobe!(
            bpf,
            "memcpy",
            ["libc", "__memcpy_avx_unaligned_erms"],
            ["libc", "__memcpy_avx_unaligned_erms_rtm"],
            ["libc", "__memcpy_avx512_no_vzeroupper"],
            ["libc", "__memcpy_avx512_unaligned_erms"],
            ["libc", "__memcpy_erms"],
            ["libc", "__memcpy_evex_unaligned_erms"],
            ["libc", "__memcpy_sse2_unaligned_erms"],
            ["libc", "__memcpy_ssse3"],
            ["libc", "__memcpy_chk_avx_unaligned_erms"],
            ["libc", "__memcpy_chk_avx_unaligned_erms_rtm"],
            ["libc", "__memcpy_chk_avx512_no_vzeroupper"],
            ["libc", "__memcpy_chk_avx512_unaligned_erms"],
            ["libc", "__memcpy_chk_erms"],
            ["libc", "__memcpy_chk_evex_unaligned_erms"],
            ["libc", "__memcpy_chk_sse2_unaligned_erms"],
            ["libc", "__memcpy_chk_ssse3"],
            ["libc", "__mempcpy_avx_unaligned_erms"],
            ["libc", "__mempcpy_avx_unaligned_erms_rtm"],
            ["libc", "__mempcpy_avx512_no_vzeroupper"],
            ["libc", "__mempcpy_avx512_unaligned_erms"],
            ["libc", "__mempcpy_erms"],
            ["libc", "__mempcpy_evex_unaligned_erms"],
            ["libc", "__mempcpy_sse2_unaligned_erms"],
            ["libc", "__mempcpy_ssse3"],
            ["libc", "__mempcpy_chk_avx_unaligned_erms"],
            ["libc", "__mempcpy_chk_avx_unaligned_erms_rtm"],
            ["libc", "__mempcpy_chk_avx512_no_vzeroupper"],
            ["libc", "__mempcpy_chk_avx512_unaligned_erms"],
            ["libc", "__mempcpy_chk_erms"],
            ["libc", "__mempcpy_chk_evex_unaligned_erms"],
            ["libc", "__mempcpy_chk_sse2_unaligned_erms"],
            ["libc", "__mempcpy_chk_ssse3"],
        );
    }

    if args.filep_unlocked {
        attach_uprobe!(
            bpf,
            "filep_unlocked_used_arg0",
            ["libc", "getc_unlocked"],
            ["libc", "clearerr_unlocked"],
            ["libc", "fflush_unlocked"],
            ["libc", "fgetc_unlocked"],
            ["libc", "getwc_unlocked"],
            ["libc", "fgetwc_unlocked"],
        );
        attach_uprobe!(
            bpf,
            "filep_unlocked_used_arg1",
            ["libc", "putc_unlocked"],
            ["libc", "fputc_unlocked"],
            ["libc", "fputs_unlocked"],
            ["libc", "fputwc_unlocked"],
            ["libc", "putwc_unlocked"],
            ["libc", "fputws_unlocked"],
        );
        attach_uprobe!(
            bpf,
            "filep_unlocked_used_arg2",
            ["libc", "fgets_unlocked"],
            ["libc", "fgetws_unlocked"],
        );
        attach_uprobe!(
            bpf,
            "filep_unlocked_used_arg3",
            ["libc", "fread_unlocked"],
            ["libc", "fwrite_unlocked"],
        );
        attach_uprobe!(
            bpf,
            "filep_locked_used_arg0",
            ["libc", "getc"],
            ["libc", "clearerr"],
            ["libc", "fflush"],
            ["libc", "fgetc"],
            ["libc", "getwc"],
            ["libc", "fgetwc"],
        );
        attach_uprobe!(
            bpf,
            "filep_locked_used_arg1",
            ["libc", "putc"],
            ["libc", "fputc"],
            ["libc", "fputs"],
            ["libc", "fputwc"],
            ["libc", "putwc"],
            ["libc", "fputws"],
        );
        attach_uprobe!(
            bpf,
            "filep_locked_used_arg2",
            ["libc", "fgets"],
            ["libc", "fgetws"],
        );
        attach_uprobe!(
            bpf,
            "filep_locked_used_arg3",
            ["libc", "fread"],
            ["libc", "fwrite"],
        );
        attach_uprobe!(bpf, "fclose_unlocked", ["libc", "fclose"],);
    }

    if args.access {
        attach_fentry!(bpf, btf, "do_faccessat");
        attach_fentry!(bpf, btf, "vfs_fstatat");
        attach_fentry!(bpf, btf, "do_statx");
        attach_fentry!(bpf, btf, "do_sys_openat2");
        // attach_uprobe!(bpf, "access", "libc");
    }

    if args.interceptable_path {
        attach_fentry!(bpf, btf, "path_openat", "clear_open_permissions");
        attach_fentry!(bpf, btf, "do_filp_open");
        attach_fexit!(bpf, btf, "do_filp_open");
        attach_fentry!(bpf, btf, "may_open");
        attach_lsm!(bpf, btf, "inode_permission", "open_permissions_inode");
        attach_fentry!(bpf, btf, "security_file_open", "open_permissions_file");
    }

    if args.gets {
        attach_uprobe!(bpf, "gets", "libc");
    }

    if args.rwx_mem {
        attach_fentry!(bpf, btf, "vma_set_page_prot");
    }

    if args.fixed_mmap {
        attach_fentry!(bpf, btf, "ksys_mmap_pgoff", "fixed_mmap");
        attach_uprobe_and_uretprobe!(
            bpf,
            "fixed_mmap_safe_function",
            ["ld-linux-x86-64", "_dl_map_object"],
            ["libc", "alloc_new_heap"]
        );
    }

    if args.leaky_vessel {
        attach_tracepoint!(
            bpf,
            "execveat_lv",
            ["syscalls", "sys_enter_execve"],
            ["syscalls", "sys_enter_execveat"]
        );
        attach_fentry!(bpf, btf, "set_fs_pwd", "set_fs_pwd_lv");
        attach_lsm!(bpf, btf, "task_fix_setuid", "setuid_lv");
        attach_tracepoint!(bpf, "fork_lv", ["sched", "sched_process_fork"]);
    }

    if args.toctou_2005 {
        attach_tracepoint!(
            bpf,
            "sched_enter_creation_arg0",
            ["syscalls", "sys_enter_creat"],
            ["syscalls", "sys_enter_open"],
            ["syscalls", "sys_enter_mknod"],
            ["syscalls", "sys_enter_mkdir"],
        );
        attach_tracepoint!(
            bpf,
            "sched_enter_creation_arg1",
            ["syscalls", "sys_enter_link"],
            ["syscalls", "sys_enter_symlink"],
            ["syscalls", "sys_enter_rename"],
        );
        attach_tracepoint!(
            bpf,
            "sched_enter_remove_arg0",
            ["syscalls", "sys_enter_rename"],
            ["syscalls", "sys_enter_rmdir"],
            ["syscalls", "sys_enter_unlink"],
        );
        attach_tracepoint!(
            bpf,
            "sched_enter_normal_use_arg0",
            ["syscalls", "sys_enter_chmod"],
            ["syscalls", "sys_enter_chown"],
            ["syscalls", "sys_enter_truncate"],
            ["syscalls", "sys_enter_utime"],
            ["syscalls", "sys_enter_chdir"],
            ["syscalls", "sys_enter_chroot"],
            ["syscalls", "sys_enter_pivot_root"],
            ["syscalls", "sys_enter_open"],
            ["syscalls", "sys_enter_execve"],
        );
        attach_tracepoint!(
            bpf,
            "sched_enter_normal_use_arg1",
            ["syscalls", "sys_enter_mount"],
        );
        attach_tracepoint!(
            bpf,
            "sched_enter_check_arg0",
            ["syscalls", "sys_enter_access"],
        );
        attach_tracepoint!(
            bpf,
            "sched_enter_check_arg1",
            ["syscalls", "sys_enter_statx"],
        );
    }

    attach_tracepoint!(bpf, "sched_exit_stats", ["sched", "sched_process_exit"]);

    signal::ctrl_c().await?;
    tx.send(())?;

    for task in tasks {
        task.await?;
    }

    let global_statistics: AyaArray<_, u64> =
        AyaArray::try_from(bpf.take_map("GLOBAL_STATISTICS").unwrap())?;

    println!("Pass,ERROR,WARN,INFO,DEBUG,TRACE,Observations");
    for (pass, (repr, counts)) in &*counters_map {
        println!(
            "{pass},{},{}",
            counts
                .iter()
                .map(|count| format!("{}", count.load(Ordering::Acquire)))
                .collect::<Vec<_>>()
                .join(","),
            repr.iter()
                .map(|idx| { global_statistics.get(&(*idx as u32), 0).unwrap() })
                .sum::<u64>()
        );
    }

    Ok(())
}
