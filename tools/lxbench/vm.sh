#!/bin/bash
# One measurement VM (Linux-server design, wave 2 group 6). Run in WSL as root:
#   vm.sh NAME ISO TIMEOUT "HARNESS ARGS" CMD...
# ISO is a file name in /opt/u2604/tmp/$TAG (copy the built dist/x86_64/kernel.iso there first).
# Every VM file stays on WSL's own disk (/opt/u2604/tmp/$TAG, /root/pool/$TAG-*.qcow2, an
# overlay of the pool that is deleted afterwards); the log is copied to scratch/lxbench.
# TAG defaults to the worktree's name without dashes (os-6 -> os6).
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd)
TAG=${TAG:-$(basename "$TREE" | tr -d -)}
NAME=$1; ISO=$2; TO=$3; HARGS=$4; shift 4
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
mkdir -p $R/tmp/$TAG/tree/tools "$TREE/scratch/lxbench"
cp "$TREE/tools/hydra_run.py" "$TREE/tools/ppm2png.py" $R/tmp/$TAG/tree/tools/
CMDS=""; for c in "$@"; do CMDS="$CMDS $(printf '%q' "$c")"; done
OV=/root/pool/$TAG-$NAME.qcow2
timeout $TO chroot $R /usr/local/bin/vmslot /bin/bash -c "cd /tmp/$TAG/tree && export HYDRA_ISO=/tmp/$TAG/$ISO && rm -f $OV && qemu-img create -q -f qcow2 -F qcow2 -b /root/pool/hydrapool.qcow2 $OV && timeout $((TO-30)) python3 tools/hydra_run.py --shared-host --smp 2 --accel kvm --disk $OV --log /tmp/$TAG/$NAME.log --boot-wait 240 $HARGS $CMDS > /tmp/$TAG/$NAME.harness.txt 2>&1; echo harness rc=\$?; rm -f $OV"
echo "exit $?"
rm -f $R$OV
cp $R/tmp/$TAG/$NAME.log $R/tmp/$TAG/$NAME.harness.txt "$TREE/scratch/lxbench/" 2>/dev/null
tr -d '\000\r' < "$TREE/scratch/lxbench/$NAME.log" | grep -a -E 'BENCH|lxbench:|EXCEPTION|PANIC|^real' | head -80
