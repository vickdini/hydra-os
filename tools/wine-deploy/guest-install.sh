#!/bin/bash
# Runs inside Hydra's Ubuntu chroot as root (deploy-main-pool.sh serves it): replaces Wine's
# user32.dll in /opt/wine with Hydra's rebuilt one, old one kept as user32.dll.orig.
#   guest-install.sh install|undo PORT
set -u
MODE=$1
PORT=$2
W=/opt/wine/lib/wine
cd /tmp
if [ "$MODE" = undo ]; then
    for a in i386 x86_64; do
        [ -f "$W/$a-windows/user32.dll.orig" ] && mv -f "$W/$a-windows/user32.dll.orig" "$W/$a-windows/user32.dll"
    done
    echo WINE_DEPLOY_UNDONE
    exit 0
fi
rm -rf wd && mkdir wd && cd wd
curl -s -O http://10.0.2.2:$PORT/SHA256SUMS || { echo DOWNLOAD FAILED; exit 1; }
for a in i386 x86_64; do
    mkdir -p $a-windows
    curl -s -o $a-windows/user32.dll http://10.0.2.2:$PORT/$a-windows/user32.dll || { echo DOWNLOAD FAILED; exit 1; }
done
sha256sum -c SHA256SUMS || { echo CHECKSUM FAILED; exit 1; }
# Running Wine programs keep the old file mapped; nothing of the user's runs during this boot
for a in i386 x86_64; do
    [ -f "$W/$a-windows/user32.dll.orig" ] || cp -p "$W/$a-windows/user32.dll" "$W/$a-windows/user32.dll.orig"
    cp $a-windows/user32.dll "$W/$a-windows/user32.dll.new"         && chmod --reference="$W/$a-windows/user32.dll.orig" "$W/$a-windows/user32.dll.new"         && mv -f "$W/$a-windows/user32.dll.new" "$W/$a-windows/user32.dll" || { echo COPY FAILED; exit 1; }
done
cd /tmp && rm -rf wd
sha256sum $W/*-windows/user32.dll
sync
echo WINE_DEPLOY_OK
