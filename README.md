# os-sanitizer

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Installing as a service

You will need to adjust the `DEBUGINFOD_URLS` environmental variable according to your operating
system.

```bash
cargo xtask build-ebpf --release
cargo build --release
sudo cp target/release/os-sanitizer /usr/local/sbin/
sudo cp os-sanitizer.service /usr/lib/systemd/system/
sudo systemctl enable os-sanitizer
sudo service os-sanitizer start
```

You can then monitor for warnings under:

```bash
sudo journalctl -b -fu os-sanitizer
```