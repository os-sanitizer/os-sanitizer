use aya::maps::{AsyncPerfEventArray, HashMap as AyaHashMap, StackTraceMap};
use aya::programs::{FEntry, UProbe};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf, Btf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, error, info, warn};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use os_sanitizer_common::{CopyViolation, FileAccessReport, FunctionInvocationReport};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{c_char, CStr};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

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

    let pid = std::process::id();
    ignored_pids.insert(pid, 0, 0)?;

    let mut file_reports =
        AsyncPerfEventArray::try_from(bpf.take_map("FILE_REPORT_QUEUE").unwrap())?;
    let mut function_reports =
        AsyncPerfEventArray::try_from(bpf.take_map("FUNCTION_REPORT_QUEUE").unwrap())?;

    let stacktraces = Arc::new(StackTraceMap::try_from(
        bpf.take_map("STACKTRACES").unwrap(),
    )?);

    let symbols = Arc::new(RwLock::new(HashMap::<
        PathBuf,
        (Range<u64>, BTreeMap<u64, String>),
    >::new()));

    let observed_stacktraces = Arc::new(Mutex::new(HashSet::<(String, u64)>::new()));

    let keep_going = Arc::new(AtomicBool::new(true));
    let mut tasks = Vec::new();

    for cpu_id in online_cpus()? {
        let mut buf = file_reports.open(cpu_id, None)?;
        {
            let keep_going = keep_going.clone();
            tasks.push(task::spawn(async move {
                let mut buffers = (0..32)
                    .map(|_| BytesMut::with_capacity(512))
                    .collect::<Vec<_>>();

                while keep_going.load(Ordering::Relaxed) {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let ptr = buf.as_ptr() as *const FileAccessReport;
                        let report = unsafe { ptr.read_unaligned() };

                        let Ok(filename) = (unsafe {
                            CStr::from_ptr(report.filename.as_ptr() as *const c_char).to_str()
                        }) else {
                            continue;
                        };
                        let Ok(executable) = (unsafe {
                            CStr::from_ptr(report.executable.as_ptr() as *const c_char).to_str()
                        }) else {
                            continue;
                        };
                        let i_mode = report.i_mode;
                        let pid = report.pid_tgid as u32;

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

                        if i_mode & 0xF000 == 0x8000 || i_mode & 0xF000 == 0x4000 {
                            error!("{executable} (pid {pid}) requested `{filename}' (a {filetype}) with permissions {rendered}");
                        } else {
                            warn!("{executable} (pid {pid}) requested `{filename}' (a {filetype}) with permissions {rendered}")
                        }
                    }
                }
            }));
        }

        let mut buf = function_reports.open(cpu_id, None)?;
        {
            let observed_stacktraces = observed_stacktraces.clone();
            let stacktraces = stacktraces.clone();
            let symbols = symbols.clone();
            let keep_going = keep_going.clone();
            tasks.push(task::spawn(async move {
                let mut buffers = (0..32)
                    .map(|_| BytesMut::with_capacity(512))
                    .collect::<Vec<_>>();

                while keep_going.load(Ordering::Relaxed) {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let report = unsafe { (buf.as_ptr() as *const FunctionInvocationReport).read_unaligned() };

                        let (executable, pid, tgid, mut stacktrace) = match report {
                            FunctionInvocationReport::Strncpy {
                                executable,
                                pid_tgid,
                                stack_id,
                                ..
                            } | FunctionInvocationReport::Memcpy { executable, pid_tgid, stack_id, .. } => {
                                let Ok(executable) = CStr::from_bytes_until_nul(&executable).unwrap().to_str() else {
                                    error!("Couldn't recover the name of the executable.");
                                    continue;
                                };
                                let Ok(stacktrace) = stacktraces.get(&(stack_id as u32), 0) else {
                                    error!("Couldn't recover the stacktrace of the executable {executable}.");
                                    continue;
                                };
                                (executable.to_string(), (pid_tgid >> 32) as u32, pid_tgid as u32, stacktrace)
                            },
                        };

                        let mut observed_lock =
                            observed_stacktraces.lock().await;
                        if !observed_lock.insert((executable.clone(), stacktrace.frames()[0].ip)) {
                            continue;
                        }
                        drop(observed_lock);

                        let mut range = 0..0;
                        if let Ok(path) = which::which(&executable) {
                            let reader = symbols.read().await;
                            if let Some(symdata) = reader.get(&path) {
                                stacktrace.resolve(&symdata.1);
                                range = symdata.0.clone();
                            } else {
                                drop(reader);
                                let mut writer = symbols.write().await;

                                let read_symbols = |executable, path| -> (Range<u64>, BTreeMap<u64, String>) {
                                    if let Ok(bin_data) = std::fs::read(path) {
                                        if let Ok(obj_file) = object::File::parse(&*bin_data) {
                                            if let Some(text_section) = obj_file.section_by_name(".text") {
                                                let range = text_section.address()..(text_section.address() + text_section.size());
                                                return (range, obj_file.symbols()
                                                    .filter(|sym| sym.kind() == SymbolKind::Text && sym.is_global() && sym.section_index() == Some(text_section.index()))
                                                    .filter_map(|sym| sym.name().map(|name| (sym.address(), name.to_string())).ok())
                                                    .collect());
                                            }
                                        }
                                    }
                                    warn!("Couldn't read symbols from {executable}");
                                    (0..0, BTreeMap::new())
                                };

                                let symdata = read_symbols(&executable, &path);

                                stacktrace.resolve(&symdata.1);
                                range = symdata.0.clone();
                                writer.insert(path, symdata);
                            }
                        }

                        let stacktrace = stacktrace.frames().into_iter().enumerate().map(|(i, entry)| {
                            match &entry.symbol_name {
                                Some(sym) if range.contains(&entry.ip) => {
                                    format!("{i}: {sym} (0x{:x})", entry.ip)
                                }
                                _ => {
                                    format!("{i}: 0x{:x}", entry.ip)
                                }
                            }
                        }).collect::<Vec<_>>().join("\n");

                        match report {
                            FunctionInvocationReport::Strncpy { variant: CopyViolation::Strlen, len, dest, src, .. } => {
                                warn!("{executable} (pid: {pid}, thread: {tgid}) invoked strncpy with src pointer determining copied length (dest: 0x{dest:x}, src: 0x{src:x}, len: {len}); stacktrace: \n{stacktrace}", );
                            }
                            FunctionInvocationReport::Strncpy { variant: CopyViolation::Malloc, allocated, len, dest, src, .. } => {
                                warn!("{executable} (pid: {pid}, thread: {tgid}) invoked strncpy with src pointer allocated with less length than specified available (dest: 0x{dest:x} (allocated: {allocated}), src: 0x{src:x}, len: {len}); stacktrace: \n{stacktrace}", );
                            }
                            FunctionInvocationReport::Memcpy { variant: CopyViolation::Strlen, len, dest, src, .. } => {
                                warn!("{executable} (pid: {pid}, thread: {tgid}) invoked memcpy with src pointer determining copied length (dest: 0x{dest:x}, src: 0x{src:x}, len: {len}); stacktrace: \n{stacktrace}", );
                            }
                            FunctionInvocationReport::Memcpy { variant: CopyViolation::Malloc, allocated, len, dest, src, .. } => {
                                warn!("{executable} (pid: {pid}, thread: {tgid}) invoked memcpy with src pointer allocated with less length than specified available (dest: 0x{dest:x} (allocated: {allocated}), src: 0x{src:x}, len: {len}); stacktrace: \n{stacktrace}", );
                            }
                        }
                    }
                }
            }));
        }
    }

    let btf = Btf::from_sys_fs()?;
    let program: &mut FEntry = bpf
        .program_mut("fentry_security_file_open")
        .unwrap()
        .try_into()?;
    program.load("security_file_open", &btf)?;
    program.attach()?;

    let program: &mut UProbe = bpf.program_mut("uprobe_malloc").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__libc_malloc"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uretprobe_malloc").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__libc_malloc"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_realloc").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__libc_realloc"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uretprobe_realloc").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__libc_realloc"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_strlen").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__strlen_avx2"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uretprobe_strlen").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__strlen_avx2"), 0, "libc", None)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_strncpy").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__strncpy_avx2"), 0, "libc", None)?;

    // memcpy is very noisy! It seems there is some flaw in this logic
    // let program: &mut UProbe = bpf.program_mut("uprobe_memcpy").unwrap().try_into()?;
    // program.load()?;
    // program.attach(Some("__memcpy_avx_unaligned_erms"), 0, "libc", None)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    program.unload()?;

    Ok(())
}
