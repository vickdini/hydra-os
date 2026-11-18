#!/bin/bash
# Group 11's own build root (Ubuntu 22.04 "jammy" by debootstrap) for clang's FreeBSD cross
# builds and for Darling. It never touches /opt/u2604 (the shared QEMU root).
#
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-11/tools/personality/g11root.sh create|mount|packages|shell CMD...
#
# create    debootstrap jammy into $R (minbase)
# mount     (re)mount proc, sys, dev, dev/pts and resolv.conf for chroot use (WSL drops them when idle)
# packages  apt sources + the packages: clang/lld 15 (FreeBSD cross), Darling's documented
#           Ubuntu 22.04 build dependencies, ninja
# shell     run CMD inside the root, niced (nice 19, ionice idle)
set -euo pipefail
R=${R:-/opt/g11root}
mnt() {
    for d in proc sys dev dev/pts; do mkdir -p "$R/$d"; done
    mountpoint -q "$R/proc"    || mount -t proc proc "$R/proc"
    mountpoint -q "$R/sys"     || mount --rbind /sys "$R/sys"
    mountpoint -q "$R/dev"     || mount --rbind /dev "$R/dev"
    mountpoint -q "$R/dev/pts" || mount -t devpts devpts "$R/dev/pts" 2>/dev/null || true
    cp /etc/resolv.conf "$R/etc/resolv.conf"
}
case "${1:-}" in
create)
    mkdir -p "$R"
    nice -n 19 ionice -c3 debootstrap --variant=minbase --include=ca-certificates,gnupg jammy "$R" http://archive.ubuntu.com/ubuntu ;;
mount) mnt ;;
packages)
    mnt
    cat > "$R/etc/apt/sources.list" <<SRC
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
SRC
    chroot "$R" /usr/bin/env DEBIAN_FRONTEND=noninteractive bash -c "
        apt-get update -q &&
        nice -n 19 apt-get install -y -q --no-install-recommends \
          build-essential clang-15 lld-15 llvm-15 libclang-15-dev ninja-build python3 file xz-utils \
          cmake automake bison flex libfuse-dev libudev-dev pkg-config libc6-dev-i386 gcc-multilib \
          libcairo2-dev libgl1-mesa-dev curl libglu1-mesa-dev libtiff5-dev libfreetype6-dev git git-lfs \
          libelf-dev libxml2-dev libegl1-mesa-dev libfontconfig1-dev libbsd-dev libxrandr-dev \
          libxcursor-dev libgif-dev libavutil-dev libpulse-dev libavformat-dev libavcodec-dev \
          libswresample-dev libdbus-1-dev libxkbfile-dev libssl-dev libstdc++-12-dev \
          libvulkan-dev libcap2-bin libpython3-dev libxkbcommon-dev &&
        apt-get clean" ;;
shell) shift; mnt; chroot "$R" /usr/bin/env HOME=/root nice -n 19 ionice -c3 "$@" ;;
*) echo "usage: $0 create|mount|packages|shell CMD..."; exit 2 ;;
esac
