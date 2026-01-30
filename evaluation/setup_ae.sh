#!/usr/bin/env bash
#
# Copyright (c) OS-Sanitizer developers, 2026, licensed under the EUPL-1.2-or-later.
#
# See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).
#
set -e

# this script is in os-sanitizer/evaluation/ directory
OS_SAN_PATH=$(dirname $(dirname $(realpath $0)))
SPEC_PATH="$OS_SAN_PATH/evaluation/SPEC_cpu2017"

# Verify kernel and Fedora release
KERNEL_VERSION=$(uname -r)
FEDORA_RELEASE=$(cat /etc/fedora-release)
if [[ ! "$FEDORA_RELEASE" =~ "Fedora release 42" ]]; then
    echo "[WARN] Expected Fedora release 42, but found: $FEDORA_RELEASE"
fi
if [[ ! "$KERNEL_VERSION" =~ ^6\.14\.0 ]]; then
    echo "[WARN] Expected kernel version 6.14.0-*, but found $KERNEL_VERSION"
    echo "       Older kernels (<~ 6.11) have a buggy uretprobe implementation when using AVX-512."
    echo "       Newer kernels (>~ 6.18) have changed kernel structs and are not currently supported"
    echo "       -> https://github.com/os-sanitizer/os-sanitizer/issues/2"
fi

# NOTE: Disk usage (via vagrant cloud-image/fedora-42)
#       unmodified 2.7G
#       after `base` 4.9G
#       after `cargo clean` 4.7G
#       after `spec`: 6.0G
#       after `browserbench`: 7.4G

case "$1" in
    base)
        set +x
        sudo dnf install -y git clang bpftool time tmux vim

        # Setup Rust nightly
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
        source ~/.bashrc
        rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

        # Install aya toolchain
        cargo install --force --git https://github.com/aya-rs/bpf-linker bpf-linker
        cargo install bindgen-cli
        cargo install --git https://github.com/aya-rs/aya aya-tool

        pushd "$OS_SAN_PATH"
        aya-tool generate task_struct dentry > os-sanitizer-ebpf/src/binding.rs
        cargo build --release
        sudo cp target/release/os-sanitizer /usr/local/bin/
        sudo cp target/release/os-sanitizer-symbolizer /usr/local/bin/
        cargo clean
        popd

        make -C "$OS_SAN_PATH/examples"

        os-sanitizer --version
        ;;

    spec)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 spec <path-to-cpu2017-1.1.0.iso>"
            exit 1
        fi
        ISO_PATH="$2"
        if [[ ! -f "$ISO_PATH" ]]; then
            echo "Error: ISO file not found: $ISO_PATH"
            exit 1
        fi

        set +x
        sudo dnf install -y gcc g++ gfortran vim libnsl libxcrypt-compat
        sudo mount -t iso9660 -o ro,exec,loop "$ISO_PATH" /mnt
        /mnt/install.sh -d "$SPEC_PATH" -f
        sudo umount /mnt/
        cd "$SPEC_PATH"
        source shrc
        runcpu --update=noconfirm
        cp config/Example-gcc-linux-x86.cfg config/s_Example-gcc-linux-x86.cfg
        sed -i 's/= base,peak/= base/' config/s_Example-gcc-linux-x86.cfg
        sed -i 's/opt\/rh\/devtoolset-9\/root//' config/s_Example-gcc-linux-x86.cfg

        echo "Installed SPEC CPU2017 to $SPEC_PATH"
        ;;

    browserbench)
        set +x
        sudo dnf install -y nodejs git chromium
        npm install puppeteer
        ;;

    *)
        echo "Usage: $0 {base|spec <iso-path>}"
        echo "  base              - Install base dependencies and build os-sanitizer"
        echo "  spec <iso-path>   - Setup SPEC CPU2017 from the provided ISO"
        echo "  browserbench      - Setup browserbench"
        exit 1
        ;;
esac
