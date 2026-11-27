#!/bin/bash
# Builds the personality hook's FreeBSD test programs (wave 5, Group 14): tests/freebsd/fbhook.c
# and rawsys.c, static and without a C library, with clang 15's FreeBSD target in Group 11's
# build root (no FreeBSD sysroot needed), then copies them, with Group 11's dynamic fbsdinfo,
# into esp/bin under the names tests/linux/persona_test.c expects:
#   fbhook.elf, fbrawsys.elf, fbinfo.elf   (and persona.elf, built with gcc, Mach-O rawmac inside)
#   wave 12: fbsdrun.elf (gcc, tests/linux/fbsdrun_test.c) and fbsdthr.elf (libthr test)
#
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-14/tools/personality/build-fbhook.sh
set -euo pipefail
R=${R:-/opt/g11root}
HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../.." && pwd)
W=/tmp/g14-fbsd
bash "$HERE/g11root.sh" mount >/dev/null
mkdir -p "$R$W"
cp "$TREE/tests/freebsd/fbhook.c" "$TREE/tests/freebsd/rawsys.c" "$R$W/"
chroot "$R" /usr/bin/env -i PATH=/usr/bin:/bin bash -euc "
  cd $W
  for p in fbhook rawsys; do
    nice -n 19 clang-15 --target=x86_64-unknown-freebsd15.1 -static -nostdlib -ffreestanding -fno-stack-protector \
      -fuse-ld=lld -O1 -Wall -Wno-unused -o \$p \$p.c
  done
"
cp "$R$W/fbhook" "$TREE/esp/bin/fbhook.elf"
cp "$R$W/rawsys" "$TREE/esp/bin/fbrawsys.elf"
cp /opt/g11work/fbsd-tests/fbsdinfo "$TREE/esp/bin/fbinfo.elf"
# The Mach-O file goes into persona itself (the boot import takes only ELF files)
(cd /opt/g11work/mac-tests && xxd -i rawmac) > /tmp/rawmac_bin.h
gcc -O1 -w -pthread -I/tmp -DRAWMAC_H='"rawmac_bin.h"' -o "$TREE/esp/bin/persona.elf" "$TREE/tests/linux/persona_test.c"
# wave12 FK: the milestone test (Linux, runs FreeBSD programs in /freebsd) and libthr's test
# program (build-freebsd-tests.sh builds it into /opt/g11work/fbsd-tests)
gcc -O1 -w -o "$TREE/esp/bin/fbsdrun.elf" "$TREE/tests/linux/fbsdrun_test.c"
cp /opt/g11work/fbsd-tests/fbsdthr "$TREE/esp/bin/fbsdthr.elf"
file "$TREE"/esp/bin/{fbhook,fbrawsys,fbinfo,persona,fbsdrun,fbsdthr}.elf
