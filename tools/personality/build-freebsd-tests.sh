#!/bin/bash
# Builds Group 11's FreeBSD test programs (tests/freebsd/*.c) with clang's FreeBSD target,
# against the extracted base.txz as the sysroot, inside Group 11's build root.
#
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-11/tools/personality/build-freebsd-tests.sh
#
# Needs: tools/personality/g11root.sh create + packages (clang-15, lld-15), and
# make-freebsd-root.sh (the extracted root at /opt/g11work/freebsd-15.1/root).
# Output: /opt/g11work/fbsd-tests/*  (FreeBSD ELF binaries; readelf summary in marking.txt)
set -euo pipefail
R=${R:-/opt/g11root}
V=${V:-15.1}
HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../.." && pwd)
SYS=/opt/g11work/freebsd-$V/root
OUT=/opt/g11work/fbsd-tests
bash "$HERE/g11root.sh" mount
# The sysroot, the sources and the output, seen inside the build root
for d in sysroot src-tests out; do mkdir -p "$R/g11/$d"; done
mountpoint -q "$R/g11/sysroot"   || mount --bind -o ro "$SYS" "$R/g11/sysroot"
mountpoint -q "$R/g11/src-tests" || mount --bind -o ro "$TREE/tests/freebsd" "$R/g11/src-tests"
mkdir -p "$OUT"
mountpoint -q "$R/g11/out"       || mount --bind "$OUT" "$R/g11/out"
T="--target=x86_64-unknown-freebsd$V"
chroot "$R" /usr/bin/env -i PATH=/usr/bin:/bin bash -euc "
  cd /g11/out
  CC='nice -n 19 clang-15 $T --sysroot=/g11/sysroot -fuse-ld=lld -O1 -Wall -Wno-unused'
  \$CC -static -nostdlib -ffreestanding -fno-stack-protector -o rawsys /g11/src-tests/rawsys.c
  \$CC -o fbsdinfo /g11/src-tests/fbsdinfo.c
  \$CC -o fbsdkq   /g11/src-tests/fbsdkq.c
  \$CC -pthread -o fbsdthr /g11/src-tests/fbsdthr.c
  \$CC -static -o fbsdinfo.static /g11/src-tests/fbsdinfo.c
  for f in rawsys fbsdinfo fbsdkq fbsdthr fbsdinfo.static; do
    echo \"== \$f\"
    readelf -h \$f | grep -E 'OS/ABI|Type:'
    readelf -n \$f | grep -E 'FreeBSD|description' | head -4
    readelf -l \$f | grep 'interpreter' || echo '      (static: no interpreter)'
  done > marking.txt
"
cat "$OUT/marking.txt"
ls -l "$OUT"
