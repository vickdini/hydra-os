#!/bin/bash
# Builds Darling (darlinghq/darling, cloned with submodules to /opt/g11root/src/darling) in
# Group 11's build root, following its documented Linux build (docs.darlinghq.org,
# "Build Instructions"), niced, 64-bit only (TARGET_i386=OFF: Hydra's macOS plan is x86_64).
#
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-11/tools/personality/build-darling.sh [configure|build|install]
#
# Log: /opt/g11root/src/darling/build/g11-build.log. -j4, nice 19, ionice idle: the other
# groups' VMs come first.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=${R:-/opt/g11root}
bash "$HERE/g11root.sh" mount
# Darling's build calls plain `clang`/`clang++` in places: point them at clang 15 (only inside
# the build root)
for t in clang clang++ ld.lld llvm-ar llvm-nm llvm-objcopy llvm-ranlib llvm-strip llvm-tblgen; do
    v=$(ls "$R/usr/bin/$t-15" 2>/dev/null || true)
    [ -n "$v" ] && ln -sf "/usr/bin/$t-15" "$R/usr/local/bin/$t"
done
step=${1:-build}
chroot "$R" /usr/bin/env -i HOME=/root PATH=/usr/local/bin:/usr/bin:/bin bash -euc "
  cd /src/darling && mkdir -p build && cd build
  if [ $step = configure ] || [ ! -f build.ninja ]; then
    nice -n 19 cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DTARGET_i386=OFF \
       -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ 2>&1 | tail -30
  fi
  if [ $step = build ] || [ $step = configure ]; then
    start=\$(date +%s)
    nice -n 19 ionice -c3 ninja -j4 -k 0 > g11-build.log 2>&1; rc=\$?
    echo \"ninja rc=\$rc after \$(( (\$(date +%s) - start) / 60 )) min\" | tee -a g11-build.log
  fi
  if [ $step = install ]; then
    nice -n 19 ionice -c3 env DESTDIR=/src/darling-install ninja install > g11-install.log 2>&1; echo install rc=\$?
  fi
"
