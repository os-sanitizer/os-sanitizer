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
RUST_LOG=info cargo xtask run --help
```

### Installing as a service

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

### Symbolisation

You need to install `debuginfod-find` for your system and set the `DEBUGINFOD_URLS` variable
accordingly before using symbolisation.

To symbolise the logs from os-sanitizer, you will need to apply the symboliser to a _finite length_
input. For example, you can run os-sanitizer and pipe it to a file:

```bash
RUST_LOG=info cargo xtask run --access | tee access.log
```

Then, in another terminal, you can do:

```bash
cargo run --release -p os-sanitizer-symbolizer access.log
```

If you're using the service form of os-sanitizer, you can similarly do:

```bash
sudo journalctl -b -u os-sanitizer | cargo run --release -p os-sanitizer-symbolizer
```

As a fun little bonus: os-sanitizer-symbolizer also symoblises ASAN stacktraces -- fun!
