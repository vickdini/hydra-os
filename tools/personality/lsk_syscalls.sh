#!/bin/bash
# Counts the raw `syscall` instructions in a built Mach-O libsystem_kernel.dylib and splits
# them by the number loaded into eax just before: macOS class-encoded (>= 0x1000000) or
# small (Linux numbers, Darling's emulation). Run inside Group 11's build root.
#   lsk_syscalls.sh libsystem_kernel.dylib
f=$1
llvm-objdump-15 -d --no-show-raw-insn "$f" > /tmp/lsk.txt
echo "syscall instructions: $(grep -cE 'syscall$' /tmp/lsk.txt)"
grep -B4 -E 'syscall$' /tmp/lsk.txt | sed -nE 's/.*movl?[[:space:]]+\$0x([0-9a-f]+), %(e|r)ax.*/\1/p' \
  | while read -r x; do v=$((16#$x)); if [ $v -ge $((0x1000000)) ]; then echo mac; else echo small; fi; done | sort | uniq -c
grep -B4 -E 'syscall$' /tmp/lsk.txt | head -30
