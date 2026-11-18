#!/bin/bash
# Builds Group 11's macOS test programs (tests/macos/*.c) as Mach-O x86_64 files with clang 15
# and Darling's ld64 (cctools-port), inside Group 11's build root. Needs Darling's build to have
# produced x86_64-apple-darwin20-ld (an early step of build-darling.sh).
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-11/tools/personality/build-macos-tests.sh
# Output: /opt/g11work/mac-tests/
set -euo pipefail
R=${R:-/opt/g11root}
HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../.." && pwd)
OUT=/opt/g11work/mac-tests
bash "$HERE/g11root.sh" mount
mkdir -p "$OUT" "$R/g11/src-mac" "$R/g11/mac-out"
mountpoint -q "$R/g11/src-mac" || mount --bind -o ro "$TREE/tests/macos" "$R/g11/src-mac"
mountpoint -q "$R/g11/mac-out" || mount --bind "$OUT" "$R/g11/mac-out"
chroot "$R" /usr/bin/env -i PATH=/usr/bin:/bin bash -euc '
  LD=/src/darling/build/src/external/cctools-port/cctools/ld64/src/x86_64-apple-darwin20-ld
  cd /g11/mac-out
  clang-15 -target x86_64-apple-macos11 -ffreestanding -fno-stack-protector -nostdlib -O1 -Wall -c /g11/src-mac/rawmac.c -o rawmac.o
  $LD -static -e start -arch x86_64 -platform_version macos 11.0 11.0 -o rawmac rawmac.o
  file rawmac
  od -A x -t x4 -N 32 rawmac
'
