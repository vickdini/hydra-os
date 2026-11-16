#!/bin/bash
# Puts Hydra's rebuilt Wine DLLs (tools/wine-patches applied; today: user32.dll, patch 0001,
# icon-less windows get their program's icon) into /opt/wine on the MAIN pool
# (/opt/u2604/root/pool/hydrapool.qcow2), keeping the old ones as *.orig. Boots that pool
# headless under KVM with this checkout's kernel image (which also writes this build's
# devices.rs files into it), copies, checks, and powers off cleanly.
#
# It changes the user's own system: run it only with their approval, and only while their VM
# is shut down. As root in WSL:
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/d/os/tools/wine-deploy/deploy-main-pool.sh --yes-main-pool
# Undo: the same with --undo (puts the *.orig files back). A trial on a throwaway overlay of
# the pool (changes nothing of the user's): --test.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
R=/opt/u2604
POOL=/root/pool/hydrapool.qcow2
# The DLLs: built in the WSL build tree (tools/build-wine.sh), stripped
DLLS=$R/root/u32
PORT=8779
MODE=install
case "${1:-}" in
--yes-main-pool) ;;
--undo) MODE=undo ;;
--test) POOL=/root/pool/wine-deploy-test.qcow2 ;;
*) echo "This changes the MAIN pool. Run with --yes-main-pool (or --undo) once the user has approved."; exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { echo "run as root (wsl -u root)"; exit 2; }
for a in i386 x86_64; do
    [ -f "$DLLS/$a-windows/user32.dll" ] || { echo "missing $DLLS/$a-windows/user32.dll"; exit 1; }
done
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
mountpoint -q $R/mnt/d || mount --bind /mnt/d $R/mnt/d
# Two VMs on one pool corrupt it; a test VM on an overlay of it is just as unsafe while the
# pool changes underneath (a --test overlay is safe beside other overlays; HYDRA_RUN names a
# harness that allows that)
if [ "${1:-}" != --test ] && pgrep -f qemu-system >/dev/null; then echo "A QEMU is running: not touching the main pool"; exit 1; fi
if [ "${1:-}" = --test ]; then
    chroot $R qemu-img create -q -f qcow2 -F qcow2 -b /root/pool/hydrapool.qcow2 $POOL || exit 1
fi

# What the guest runs (as root, in the Ubuntu chroot): fetch, verify, swap, report
STAGE=$(mktemp -d)
cp "$HERE/guest-install.sh" "$STAGE/"
for a in i386 x86_64; do
    mkdir -p "$STAGE/$a-windows"
    cp "$DLLS/$a-windows/user32.dll" "$STAGE/$a-windows/"
done
(cd "$STAGE" && sha256sum */user32.dll > SHA256SUMS)
(cd "$STAGE" && exec python3 -m http.server $PORT --bind 127.0.0.1 >/dev/null 2>&1) &
HTTP=$!
LOG=scratch/wine_deploy_main.log
chroot $R /bin/bash -c "cd '$REPO' && python3 ${HYDRA_RUN:-tools/hydra_run.py} --accel kvm --disk $POOL --smp 4 --login hydra:hydra --wait 900 \
  --prompt 'hydra:/bin\$ ' --prompt-timeout 800 --log $LOG --until 'Powering off' \
  \"linux chroot /ubuntu /usr/bin/bash -c 'echo hydra | sudo -S bash -c \\\"curl -s http://10.0.2.2:$PORT/guest-install.sh | bash -s $MODE $PORT\\\"'\" \
  \"linux chroot /ubuntu /usr/bin/bash -c 'echo hydra | sudo -S /sbin/poweroff -f'\" >/dev/null 2>&1"
kill $HTTP
rm -rf "$STAGE"
tr -d '\000' < "$REPO/$LOG" | grep -a -E "WINE_DEPLOY|FAILED|OK$|user32.dll|Committing|Powering off" | head -20
if [ "${1:-}" = --test ]; then
    chroot $R rm -f $POOL
fi
