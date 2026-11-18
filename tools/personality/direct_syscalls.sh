#!/bin/bash
# Lists the system call numbers an ELF file makes directly (mov $N,%eax ... syscall), for
# FreeBSD's rtld and libc (which otherwise go through libsys). Usage: direct_syscalls.sh FILE...
for f in "$@"; do
    printf '%s: ' "$f"
    objdump -d --no-show-raw-insn "$f" | grep -B3 -E 'syscall *$' \
        | sed -nE 's/.*mov +\$0x([0-9a-f]+),%e?ax.*/\1/p' | sort -u \
        | while read -r x; do printf '%d ' "$((16#$x))"; done
    echo
done
