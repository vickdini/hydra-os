#!/bin/bash
# Installs the FreeBSD 15.1 root (made by make-freebsd-root.sh) as /freebsd inside the pool's
# Ubuntu root (wave 12, Group FK; decision 42). Run INSIDE the Ubuntu root, as root:
#
#   install-freebsd-root.sh [TARBALL-OR-URL [SHA256-FILE-OR-URL]]
#
# - TARBALL-OR-URL: a local path or an http(s) URL of freebsd-root-15.1.tar.xz
#   (default /var/tmp/freebsd-root-15.1.tar.xz). The checksum file defaults to the same name
#   plus .sha256; it is checked before anything is unpacked.
# - The root lands in /freebsd of the Ubuntu root (the pool's /ubuntu/freebsd). Ubuntu
#   programs reach it as /freebsd; hydra-shell's `freebsd` command runs programs there
#   (`linux chroot /ubuntu/freebsd ...`, or `/freebsd` of the pool if that exists).
#   Why there: the Ubuntu root cannot see the pool's own root, so a root "next to /ubuntu"
#   could not be installed or entered from the Ubuntu side.
# - Idempotent: a second run with the same tarball only checks it and refreshes the wrapper.
#   A different tarball replaces the old root (unpacked beside it first, then swapped).
# - Also installs /usr/local/bin/freebsd: `freebsd PROGRAM [ARGS]` runs a FreeBSD program in
#   that root (as root; other users go through sudo).
# - The last line is FREEBSD-ROOT-OK on success, FREEBSD-ROOT-FAILED: <why> otherwise.
set -u
SRC=${1:-/var/tmp/freebsd-root-15.1.tar.xz}
SUM=${2:-$SRC.sha256}
TARGET=${FREEBSD_TARGET:-/freebsd}
WORK=/var/tmp/hydra-freebsd
fail() { echo "FREEBSD-ROOT-FAILED: $*"; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
mkdir -p "$WORK" || fail "cannot create $WORK"

fetch() { # SRC DEST
    case "$1" in
    http://*|https://*)
        if command -v curl >/dev/null; then curl -fsS -o "$2" "$1"; else wget -q -O "$2" "$1"; fi ;;
    *) [ "$1" = "$2" ] || cp "$1" "$2" ;;
    esac
}

TAR=$WORK/freebsd-root.tar.xz
case "$SRC" in
http://*|https://*) echo "fetching $SRC"; fetch "$SRC" "$TAR" || fail "cannot fetch $SRC" ;;
*) [ -f "$SRC" ] || fail "no tarball at $SRC"; TAR=$SRC ;;
esac
fetch "$SUM" "$WORK/sum" || fail "cannot fetch $SUM"
WANT=$(awk '{print $1; exit}' "$WORK/sum")
[ ${#WANT} = 64 ] || fail "no SHA-256 in $SUM"
echo "checking SHA-256"
HAVE=$(sha256sum "$TAR" | awk '{print $1}')
[ "$HAVE" = "$WANT" ] || fail "checksum mismatch ($HAVE, want $WANT)"

STAMP=$TARGET/.hydra-installed
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$WANT" ] && [ -x "$TARGET/libexec/ld-elf.so.1" ]; then
    echo "already installed: $TARGET ($WANT)"
else
    NEW=$TARGET.new
    rm -rf "$NEW"
    mkdir -p "$NEW" || fail "cannot create $NEW"
    echo "unpacking into $NEW"
    xz -dc "$TAR" | tar --numeric-owner -xpf - -C "$NEW" || fail "unpacking failed"
    [ -x "$NEW/libexec/ld-elf.so.1" ] && [ -x "$NEW/bin/sh" ] || fail "the tarball has no FreeBSD root"
    echo "$WANT" > "$NEW/.hydra-installed"
    if [ -e "$TARGET" ]; then
        rm -rf "$TARGET.old"
        mv "$TARGET" "$TARGET.old" || fail "cannot move the old root away"
    fi
    mv "$NEW" "$TARGET" || fail "cannot put the new root in place"
    rm -rf "$TARGET.old"
fi
# What FreeBSD programs expect to find (devfs, a writable /tmp; the kernel fills /dev when a
# program starts there through hydra-shell)
mkdir -p "$TARGET/dev" "$TARGET/tmp" "$TARGET/var/tmp" "$TARGET/proc"
chmod 1777 "$TARGET/tmp" "$TARGET/var/tmp"
for f in resolv.conf hosts; do
    [ -f "/etc/$f" ] && cp -L "/etc/$f" "$TARGET/etc/$f"
done

mkdir -p /usr/local/bin
cat > /usr/local/bin/freebsd <<EOF
#!/bin/sh
# Runs a FreeBSD program in the FreeBSD root ($TARGET): freebsd PROGRAM [ARGS]
# (installed by Hydra's install-freebsd-root.sh). A name without a slash is looked up in the
# root's /bin, /usr/bin, /sbin and /usr/sbin; no program starts the root's /bin/sh.
R=$TARGET
[ \$# -gt 0 ] || set -- /bin/sh
case "\$1" in
*/*) ;;
*) for d in /bin /usr/bin /sbin /usr/sbin /rescue; do
       if [ -x "\$R\$d/\$1" ]; then p="\$d/\$1"; shift; set -- "\$p" "\$@"; break; fi
   done ;;
esac
if [ "\$(id -u)" = 0 ]; then exec chroot "\$R" "\$@"; fi
exec sudo chroot "\$R" "\$@"
EOF
chmod 755 /usr/local/bin/freebsd
echo "FreeBSD root: $TARGET; wrapper /usr/local/bin/freebsd"
echo FREEBSD-ROOT-OK
