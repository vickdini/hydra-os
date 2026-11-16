#!/bin/bash
# Wine 11.0, new WoW64 (32-bit Windows code in 64-bit processes), for Hydra's Ubuntu 26.04 chroot.
# Runs inside an Ubuntu 26.04 build root, the release of Hydra's /ubuntu chroot, so Wine links
# against the same libraries. Output: /root/wine-11.0-hydra-wow64.tar.xz (unpacks to opt/wine).
#
# Hydra has no 32-bit Linux system calls, so 32-bit Windows programs need Wine's "new WoW64"
# (--enable-archs=i386,x86_64): 32-bit Windows code runs in 64-bit Linux processes.
#
# Setting up the build root in WSL (as root: wsl -u root -e bash):
#   1. debootstrap 1.0.142 or later (older ones fail on 26.04's merged /usr): fetch
#      debootstrap_*_all.deb from the 26.04 archive, dpkg-deb -x it to /tmp/dbs, then
#      DEBOOTSTRAP_DIR=/tmp/dbs/usr/share/debootstrap /tmp/dbs/usr/sbin/debootstrap \
#        --variant=minbase resolute /opt/u2604 http://archive.ubuntu.com/ubuntu
#   2. Add universe to /opt/u2604/etc/apt/sources.list; bind-mount /proc /sys /dev /dev/pts.
#   3. apt-get install the build dependencies inside it (apt-get build-dep wine fails on a
#      unicode-cldr-core version pin): gcc make flex bison gettext pkgconf
#      gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 libwayland-dev libxkbcommon-dev
#      libfreetype-dev libfontconfig-dev libgnutls28-dev libvulkan-dev libpulse-dev
#      libasound2-dev libdbus-1-dev libudev-dev libusb-1.0-0-dev libsdl2-dev libcups2-dev
#      libunwind-dev libgl-dev libegl-dev libx11-dev (and the other X11 -dev packages),
#      libgstreamer-plugins-base1.0-dev libkrb5-dev libpcap0.8-dev libpcsclite-dev libssl-dev
#   4. Copy this script and tools/wine-patches/ to /opt/u2604/root/ and run:
#      chroot /opt/u2604 /root/build-wine.sh
# Strip afterwards (strip for bin/ and *-unix, {i686,x86_64}-w64-mingw32-strip for the
# Windows DLLs) before packing: 1.6 GB unstripped, 500 MB stripped, 70 MB packed.
#
# Wine Mono (Wine's .NET Framework) goes into the package as a shared install, in
# share/wine/mono, where wineboot finds it: .NET programs then work without a download or a
# question. Its version is the one this Wine release asks for (dlls/appwiz.cpl/addons.c).
set -e
cd /root
[ -f wine-11.0.tar.xz ] || curl -s -O https://dl.winehq.org/wine/source/11.0/wine-11.0.tar.xz
rm -rf wine-11.0 build stage
tar xf wine-11.0.tar.xz
# Hydra's changes to Wine (tools/wine-patches), in order
for p in /root/wine-patches/*.patch; do
  [ -e "$p" ] || continue
  patch -d wine-11.0 -p1 < "$p" || { echo "PATCH FAILED: $p"; exit 1; }
done
mkdir build
cd build
../wine-11.0/configure --prefix=/opt/wine --enable-archs=i386,x86_64 --disable-tests > ../configure.log 2>&1
grep -E "configure: (WARNING|error)" ../configure.log | cut -c1-160 || true
make -j12 > ../make.log 2>&1
make install DESTDIR=/root/stage > ../install.log 2>&1
cd /root
MONO=wine-mono-10.4.1
[ -f $MONO-x86.tar.xz ] || curl -s -O https://dl.winehq.org/wine/wine-mono/10.4.1/$MONO-x86.tar.xz
echo "a16606ef0724202e6a6848ece6e0cbba64d11e2f11aefe744af1d93c6d9f99bb  $MONO-x86.tar.xz" | sha256sum -c
mkdir -p stage/opt/wine/share/wine/mono
tar xf $MONO-x86.tar.xz -C stage/opt/wine/share/wine/mono
cd /root/stage
tar cJf /root/wine-11.0-hydra-wow64.tar.xz opt
ls -l /root/wine-11.0-hydra-wow64.tar.xz
echo BUILD_OK
