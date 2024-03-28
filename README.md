# os-sanitizer

## Prerequisites

1. Install clang (you need at least libclang.so) of your choice.
2. Install Rust *nightly*: https://rustup.rs/
3. Install bpf-linker: `cargo install --force --git https://github.com/aya-rs/bpf-linker`
4. Install `bpftool` for your system (e.g., for Ubuntu: `sudo apt install linux-tools-common`)
5. Install `aya-tool`: `cargo install bindgen-cli; cargo install --git https://github.com/aya-rs/aya aya-tool`

## Generate Bindings

Your system will use different struct layouts for kernel structures depending on its version.
To generate a fresh set of bindings, use the command:

```sh
aya-tool generate task_struct dentry > os-sanitizer-ebpf/src/binding.rs
```

**You will need to do this every kernel upgrade.**

## Build eBPF

```bash
cargo xtask build-ebpf --release
```

Users of older kernels (version <6) may need to additionally add the `--compat` flag.

## Build Userspace

```bash
cargo build --release
```

You can additionally add a `--target` flag to specify a target architecture, but you will need a binding file for your
desired target.

## Run

```bash
sudo env RUST_LOG=info ./target/release/os-sanitizer --help
```

If you used a different target, you will need to use `./target/<TARGET>/release/os-sanitizer` instead.

### Installing as a service

```bash
cargo xtask build-ebpf --release
cargo build --release
sudo cp target/release/os-sanitizer /usr/local/sbin/
sudo cp target/release/os-sanitizer-symbolizer /usr/local/bin/
sudo cp os-sanitizer.service /usr/lib/systemd/system/
sudo systemctl enable os-sanitizer
sudo service os-sanitizer start
```

You can then monitor for warnings under:

```bash
sudo journalctl -b -fu os-sanitizer
```

### Symbolisation

Not all OSes have good debuginfod support. This has been tested on Fedora, but is known to not
fetch source information on Ubuntu.

From: https://ubuntu.com/server/docs/service-debuginfod
> Currently, the service only provides DWARF information. There are plans to make it also index and serve source-code in
> the future.

You need to install `debuginfod-find` for your system and set the `DEBUGINFOD_URLS` variable
accordingly before using symbolisation.

To symbolise the logs from os-sanitizer, you will need to apply the symboliser to a _finite length_
input. For example, you can run os-sanitizer and pipe it to a file:

```bash
RUST_LOG=info cargo xtask run --access | tee access.log
```

Then, in another terminal, you can do:

```bash
os-sanitizer-symbolizer access.log
```

If you're using the service form of os-sanitizer, you can similarly do:

```bash
sudo journalctl -b -u os-sanitizer | os-sanitizer-symbolizer
```

As a fun little bonus: os-sanitizer-symbolizer also symoblises ASAN stacktraces -- fun!
