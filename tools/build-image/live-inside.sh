#!/bin/bash
# Runs INSIDE the live pool (a copy of the clean pool booted as a live session), as root:
# fetches the clean install image from the build host (build-image.sh serves it over the VM's
# network at 10.0.2.2) into /opt/hydra-install/, checks it, and powers the VM off.
# Prints LIVE-OK or LIVE-FAILED.
set -u
URL=http://10.0.2.2:${PORT:-8731}
D=/opt/hydra-install
rm -rf "$D"
mkdir -p "$D/esp"
ok=1
for f in pool.conf pool.img.sha256 esp.tar pool.img.zst; do
    echo "[live] fetching $f"
    curl -sSf --retry 3 -o "$D/$f.part" "$URL/$f" && mv "$D/$f.part" "$D/$f" || ok=0
done
if [ $ok = 1 ]; then
    want=$(sed -n 's/^zst_sha256=//p' "$D/pool.conf")
    have=$(sha256sum "$D/pool.img.zst" | cut -d' ' -f1)
    echo "[live] sha256 of pool.img.zst: want $want have $have"
    [ -n "$want" ] && [ "$want" = "$have" ] || ok=0
    tar -C "$D/esp" -xf "$D/esp.tar" --no-same-owner && rm -f "$D/esp.tar" || ok=0
fi
chmod -R a+rX "$D"
ls -la "$D"; find "$D/esp" -maxdepth 2; df -h /
if [ $ok = 1 ]; then echo LIVE-OK; else echo LIVE-FAILED; fi
sync
/sbin/poweroff -f
