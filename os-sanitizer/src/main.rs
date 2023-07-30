use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use libc::c_char;
use log::{debug, info, warn};
use os_sanitizer_common::Report;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

    let program: &mut KProbe = bpf
        .program_mut("os_sanitizer_complete_walk_kprobe")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("complete_walk", 0)?;

    let mut reports = AsyncPerfEventArray::try_from(bpf.take_map("REPORT_QUEUE").unwrap())?;

    let keep_going = Arc::new(AtomicBool::new(true));
    let mut tasks = Vec::new();
    for cpu_id in online_cpus()? {
        let mut buf = reports.open(cpu_id, None)?;
        let keep_going = keep_going.clone();

        tasks.push(task::spawn(async move {
            let mut buffers = (0..32)
                .map(|_| BytesMut::with_capacity(512))
                .collect::<Vec<_>>();

            while keep_going.load(Ordering::Relaxed) {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const Report;
                    let report = unsafe { ptr.read_unaligned() };

                    let Ok(filename) = (unsafe {
                        CStr::from_ptr(report.filename.as_ptr() as *const c_char).to_str()
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

                    if i_mode & 0b010 != 0 && i_mode & 0xA000 != 0xA000 {
                        warn!("pid {pid} requested {filename} (a {filetype}) with permissions {rendered}");
                    } else {
                        info!("pid {pid} requested {filename} (a {filetype}) with permissions {rendered}");
                    }
                }
            }
        }));
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
