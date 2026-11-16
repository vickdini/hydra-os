#!/bin/bash
# Hydra in a QEMU window with KVM, inside WSL2 (qemu-kvm.bat runs this as root in WSL).
#
# QEMU comes from the Ubuntu 26.04 root at /opt/u2604 (tools/build-wine.sh's build root; packages
# qemu-system-x86 qemu-system-gui qemu-utils ovmf). The window appears on the Windows desktop
# through WSLg. The pool is the copy inside WSL, /opt/u2604/root/pool/hydrapool.qcow2 (WSL's own
# disk: images under /mnt/d are slow to use from WSL), separate from dist/x86_64/hydrapool.qcow2.
#
# Extra arguments go to QEMU. HYDRA_SMP (default 4) sets the CPUs.
set -eu
R=/opt/u2604
POOL=/root/pool/hydrapool.qcow2
[ -x $R/usr/bin/qemu-system-x86_64 ] || { echo "[!] No QEMU in $R (see the header of this script)"; exit 1; }
[ -e /dev/kvm ] || { echo "[!] /dev/kvm is missing: WSL2 needs nested virtualization"; exit 1; }
if pgrep -x qemu-system-x86 >/dev/null || pgrep -f "^qemu-system-x86_64" >/dev/null; then
    echo "[!] A QEMU VM is already running in WSL: two VMs on one pool corrupt it"
    exit 1
fi
# A real procfs: Ubuntu 26.04's coreutils (uutils, via rustix) refuse a bind-mounted /proc
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
mkdir -p $R/mnt/d $R/mnt/wslg $R/tmp/.X11-unix
mountpoint -q $R/mnt/d || mount --bind /mnt/d $R/mnt/d
mountpoint -q $R/mnt/wslg || mount --bind /mnt/wslg $R/mnt/wslg
mountpoint -q $R/tmp/.X11-unix || mount --bind /tmp/.X11-unix $R/tmp/.X11-unix
[ -f $R$POOL ] || { echo "[!] No pool at $R$POOL"; exit 1; }
echo "[*] Launching Hydra with KVM (pool $POOL inside WSL)..."
# The mouse: Hydra switches QEMU's VMware pointer (vmmouse) to absolute mode, so the window
# passes the host pointer's position 1:1 and needs no special settings. HYDRA_GDK_BACKEND
# (wayland, x11) and HYDRA_ZOOM (on, off) override GTK's choices if needed.
export HYDRA_GDK_BACKEND="${HYDRA_GDK_BACKEND:-}" HYDRA_ZOOM="${HYDRA_ZOOM:-on}"
# Sound: an Intel HD Audio card whose output plays on Windows through WSLg's PulseAudio
# server (HYDRA_SOUND=off leaves the card out)
HYDRA_AUDIO=""
if [ "${HYDRA_SOUND:-on}" != off ] && [ -e $R/usr/lib/x86_64-linux-gnu/qemu/audio-pa.so ] && [ -S /mnt/wslg/PulseServer ]; then
    HYDRA_AUDIO="-audiodev pa,id=snd0 -device intel-hda -device hda-duplex,audiodev=snd0"
fi
export HYDRA_AUDIO
exec chroot $R /bin/bash -c '
export DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir PULSE_SERVER=/mnt/wslg/PulseServer
[ -n "$HYDRA_GDK_BACKEND" ] && export GDK_BACKEND="$HYDRA_GDK_BACKEND"
exec qemu-system-x86_64 -accel kvm -cpu host -m 4G -smp "${HYDRA_SMP:-4}" \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive file='"$POOL"',format=qcow2,if=ide,index=0,media=disk \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device virtio-scsi-pci,id=scsi0 -drive file=/mnt/d/os/dist/x86_64/kernel.iso,if=none,id=bootcd,media=cdrom,format=raw \
    -device scsi-cd,drive=bootcd,bootindex=0 \
    -vga std -display gtk,zoom-to-fit="$HYDRA_ZOOM" -name Hydra $HYDRA_AUDIO "$@"' qemu "$@"
