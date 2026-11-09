#!/bin/sh
# Builds Hydra's vDSO (vdso.so, embedded in the kernel by src/arch/vdso.rs). Run on Linux
# (WSL): a position-independent shared object with no relocations, linked at 0.
set -e
cd "$(dirname "$0")"
gcc -O2 -fPIC -fno-stack-protector -fno-asynchronous-unwind-tables -fno-builtin -nostdlib -shared \
    -Wl,-soname=linux-vdso.so.1 -Wl,--hash-style=both -Wl,--version-script=vdso.map \
    -Wl,-z,max-page-size=4096 -Wl,-z,norelro -Wl,--no-undefined -Wl,-T,vdso.lds \
    -o vdso.so vdso.c
strip --strip-unneeded vdso.so
# No relocations: the image is mapped as is
if readelf -r vdso.so | grep -q "R_X86_64"; then
    echo "vdso.so has relocations" >&2
    exit 1
fi
ls -l vdso.so
