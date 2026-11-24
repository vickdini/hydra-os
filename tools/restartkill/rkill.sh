#!/bin/bash
# Wave 11 Group R: kill tests of restart robustness in one console VM (no desktop):
#   1. lx-sec's cgroup device programs across a kept-state reset (two lx_sec kills within 30 s):
#      DEV KEPT OK + DEV DETACH OK
#   2. a console read in flight at a tty_server kill is sent again: a `while read` loop reads
#      every typed line through two kills ("READEND rc=0 n=3")
#   3. ptrace attach/detach/kill: `ptperm bench 50` five times in one boot, each must end
#      within 60 s ("PTBENCH 5/5")
#   wsl -d Ubuntu-20.04 -u root -e bash $TREE/tools/restartkill/rkill.sh NAME [ISO]
# Output: <tree>/scratch/rkill-NAME.log (serial log) and the verdict lines on stdout.
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd); T=$(basename "$TREE" | tr -d -c "a-z0-9")
NAME=$1; ISO=${2:-$TREE/dist/x86_64/kernel.iso}
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
D=$R/tmp/rkill-$T; mkdir -p $D/tree/tools; cp "$ISO" $D/kernel-$NAME.iso
cp $TREE/tools/hydra_run.py $D/tree/tools/
C=( "cp /bin/ptperm.elf /ubuntu/tmp/ptperm.elf" "~2" "cp /bin/lxsec.elf /ubuntu/tmp/lxsec.elf" "~2"
    "linux chroot /ubuntu /usr/bin/bash -c 'cd /tmp; cat ptperm.elf>p; cat lxsec.elf>lxsec; chmod 755 p lxsec; echo hydra | sudo -S ./lxsec devset'" "~5"
    "service kill lx_sec" "~5" "service kill lx_sec" "~6"
    "linux chroot /ubuntu /usr/bin/bash -c 'cd /tmp; echo hydra | sudo -S ./lxsec devcheck'" "~6"
    "service kill tty_server after 8" "~1" "service kill tty_server after 40" "~1"
    "linux chroot /ubuntu /usr/bin/bash -c 'n=0; while read l; do n=\$((n+1)); echo GOT \$l; done; echo READ\"\"END rc=\$? n=\$n'"
    "~14" "@one" "%ret" "~4" "@two" "%ret" "~34" "@three" "%ret" "~3" "%ctrl-d" "~4"
    "linux chroot /ubuntu /usr/bin/bash -c 'cd /tmp; ok=0; for i in 1 2 3 4 5; do echo hydra | sudo -S timeout 60 ./p bench 50 >/dev/null 2>&1 && ok=\$((ok+1)); done; echo PTBENCH \$ok/5; echo RK\"\"DONE'" )
timeout 1500 chroot $R /usr/local/bin/vmslot /bin/bash -c "rm -f /root/pool/$T-rkill-$NAME.qcow2 && qemu-img create -q -f qcow2 -F qcow2 -b /root/pool/hydrapool.qcow2 /root/pool/$T-rkill-$NAME.qcow2 && cd /tmp/rkill-$T/tree && HYDRA_ISO=/tmp/rkill-$T/kernel-$NAME.iso timeout 1400 python3 tools/hydra_run.py --accel kvm --smp 2 --shared-host --disk /root/pool/$T-rkill-$NAME.qcow2 --log /tmp/rkill-$T/$NAME.log --boot-wait 240 --wait 900 --until 'RKDONE|CPU EXCEPTION|KERNEL PANIC' $(printf '%q ' "${C[@]}") > /tmp/rkill-$T/$NAME.harness.txt 2>&1; rm -f /root/pool/$T-rkill-$NAME.qcow2"
rm -f $D/kernel-$NAME.iso
cp $D/$NAME.log $TREE/scratch/rkill-$NAME.log
tr -d '\000\r' < $TREE/scratch/rkill-$NAME.log | grep -a -E 'DEV KEPT|DEV DETACH|READEND|^GOT|PTBENCH|in flight|signal [0-9]* at' | grep -av 'linux chroot'
