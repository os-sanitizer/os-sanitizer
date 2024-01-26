# os-sanitizer

## Prerequisites

1. Install clang (you need at least libclang.so) of your choice.
2. Install Rust *nightly*: https://rustup.rs/
3. Install bpf-linker from the `feature/fix-di` branch: `cargo install --git https://github.com/aya-rs/bpf-linker --branch feature/fix-di`
4. Install `x86_64-unknown-linux-musl`: `rustup target add x86_64-unknown-linux-musl`
5. Install `musl-gcc` for your system (e.g., for Ubuntu: `sudo apt install musl-tools`)
6. Locally clone aya and apply the patch: `pushd ..; git clone https://github.com/aya-rs/aya.git; pushd aya; git apply ../os-sanitizer/aya.patch; popd; popd`
7. Install `bpftool` for your system (e.g., for Ubuntu: `sudo apt install linux-tools-common`)
8. Install `aya-tool`: `cargo install bindgen-cli; cargo install --path ../aya/aya-tool`

## Generate Bindings

Your system will use different struct layouts for kernel structures depending on its version.
To generate a fresh set of bindings, use the command:

```sh
aya-tool generate task_struct dentry > os-sanitizer-ebpf/src/binding.rs
```

**You will need to do this every kernel upgrade.**

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
sudo cp target/x86_64-unknown-linux-musl/release/os-sanitizer /usr/local/sbin/
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
> Currently, the service only provides DWARF information. There are plans to make it also index and serve source-code in the future.

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
