#!/bin/bash
# Group 16: vfsbench (tests/linux/vfsbench.c) in one VM, as root. Run in WSL as root:
#   bench.sh NAME "EXTRA HARNESS ARGS"
# Uses this tree's dist/x86_64/kernel.iso (copied to WSL's disk first) and esp/bin/vfsbench.elf.
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd); TAG=${TAG:-$(basename "$TREE" | tr -d -)}
NAME=$1; EXTRA=$2
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
for m in c d e; do mkdir -p $R/mnt/$m; mountpoint -q $R/mnt/$m || mount --bind /mnt/$m $R/mnt/$m; done
mkdir -p $R/tmp/$TAG; cp "$TREE/dist/x86_64/kernel.iso" $R/tmp/$TAG/$NAME.iso
exec bash "$TREE/tools/lxbench/vm.sh" "$NAME" $NAME.iso 900 "--wait 800 --prompt hydra:/bin\$ --prompt-timeout 700 --until VFSB-ALL-END $EXTRA" \
  "cp /bin/vfsbench.elf /ubuntu/tmp/vfsbench.elf" \
  "linux chroot /ubuntu /usr/bin/bash -c 'cat /tmp/vfsbench.elf > /tmp/vfsb; chmod 755 /tmp/vfsb; echo hydra | sudo -S /tmp/vfsb; echo VFSB-AL\"\"L-END'"
