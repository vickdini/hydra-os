#!/bin/bash
# Boots an ISO into SDDM on an overlay of the pool, in control mode (steps dropped as files by ctl.sh),
# with a QEMU monitor, a sound card recorded to a WAV, and the serial log on WSL's disk.
#   wsl -d Ubuntu-20.04 -u root -e bash $TREE/tools/devcrash/kde_vm.sh NAME [ISO] [extra hydra_run args]
# ISO: a path on /mnt/... (default: this tree's dist/x86_64/kernel.iso). Files: /opt/u2604/tmp/devcrash-$T/.
# Overlay /root/pool/$T-dc-NAME.qcow2 (deleted at the end); never the pool itself.
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd); T=$(basename "$TREE" | tr -d -c "a-z0-9")
NAME=${1:-kde}; ISO=${2:-$TREE/dist/x86_64/kernel.iso}; shift 2 2>/dev/null
D=$R/tmp/devcrash-$T
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
mkdir -p $R/mnt/d $R/mnt/c $R/mnt/e
for m in d c e; do mountpoint -q $R/mnt/$m || mount --bind /mnt/$m $R/mnt/$m; done
mkdir -p $D/ctl-$NAME $D/shots $D/tree/tools
rm -f $D/ctl-$NAME/* $D/$NAME.wav
cp "$ISO" $D/kernel-$NAME.iso
cp $TREE/tools/hydra_run.py $TREE/tools/ppm2png.py $D/tree/tools/
exec chroot $R /usr/local/bin/vmslot /bin/bash -c "rm -f /root/pool/$T-dc-$NAME.qcow2 && qemu-img create -q -f qcow2 -F qcow2 -b /root/pool/hydrapool.qcow2 /root/pool/$T-dc-$NAME.qcow2 && cd /tmp/devcrash-$T/tree && rm -f /tmp/devcrash-$T/mon-$NAME.sock && HYDRA_QEMU_EXTRA='-monitor unix:/tmp/devcrash-$T/mon-$NAME.sock,server,nowait -audiodev wav,id=snd0,path=/tmp/devcrash-$T/$NAME.wav -device intel-hda -device hda-duplex,audiodev=snd0' HYDRA_ISO=/tmp/devcrash-$T/kernel-$NAME.iso timeout 2400 python3 tools/hydra_run.py --accel kvm --smp 2 --shared-host --disk /root/pool/$T-dc-$NAME.qcow2 --log /tmp/devcrash-$T/$NAME.log --no-cancel --boot-wait 300 --wait 1500 --control /tmp/devcrash-$T/ctl-$NAME $* > /tmp/devcrash-$T/$NAME.harness.txt 2>&1; rm -f /root/pool/$T-dc-$NAME.qcow2 /tmp/devcrash-$T/kernel-$NAME.iso; echo VM-END"
