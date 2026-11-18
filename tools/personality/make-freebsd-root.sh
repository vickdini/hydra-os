#!/bin/bash
# Builds the /freebsd root tarball for Hydra's FreeBSD personality (microkernel wave 11) from
# an official FreeBSD/amd64 release's base.txz. Step 0 (wave 4, Group 11) only builds and
# inspects it; nothing on Hydra uses it yet.
#
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-11/tools/personality/make-freebsd-root.sh [VERSION]
#
# VERSION   FreeBSD release, default 15.1 (15.1-RELEASE).
# Env:      DL   download dir (default /opt/g11dl/freebsd-$VERSION; a new, empty dir per release)
#           WORK work dir    (default /opt/g11work/freebsd-$VERSION; the extracted root is WORK/root)
#           OUT  result dir  (default /opt/g11work/out)
#           TESTS=1          also unpack tests.txz (FreeBSD's ATF/kyua test suite, /usr/tests)
#
# Result: $OUT/freebsd-root-$VERSION.tar.xz (+ .sha256): the base system with numeric owners,
# ready to be unpacked as /freebsd in the Hydra pool, the way /ubuntu is today. The kernel
# (kernel.txz), /boot and the 32-bit libraries are left out: Hydra is the kernel, and wave 11
# targets 64-bit programs only.
#
# Downloads are untrusted data: each release gets its own new directory, the archives are
# checked against the release's MANIFEST (SHA-256, fetched over HTTPS), and nothing from them
# is ever executed on the build host (we only extract, readelf and repack).
set -euo pipefail
V=${1:-15.1}
URL=https://download.freebsd.org/releases/amd64/$V-RELEASE
DL=${DL:-/opt/g11dl/freebsd-$V}
WORK=${WORK:-/opt/g11work/freebsd-$V}
OUT=${OUT:-/opt/g11work/out}
NICE="nice -n 19 ionice -c3"
say() { echo "[freebsd-root] $*"; }

mkdir -p "$DL" "$OUT"
fetch() {   # fetch NAME: download into $DL if missing, then check its SHA-256 against MANIFEST
    local f=$1
    [ -s "$DL/MANIFEST" ] || curl -sfo "$DL/MANIFEST" "$URL/MANIFEST"
    [ -s "$DL/$f" ] || { say "downloading $URL/$f"; $NICE curl -sfo "$DL/$f" "$URL/$f"; }
    local want got
    want=$(awk -v f="$f" '$1==f {print $2}' "$DL/MANIFEST")
    got=$(sha256sum "$DL/$f" | cut -d' ' -f1)
    [ -n "$want" ] && [ "$want" = "$got" ] || { say "CHECKSUM MISMATCH for $f: want '$want' got '$got'"; exit 1; }
    say "$f sha256 $got (matches MANIFEST)"
}
fetch base.txz
[ "${TESTS:-0}" = 1 ] && fetch tests.txz

say "extracting into $WORK/root"
rm -rf "$WORK/root"; mkdir -p "$WORK/root"
# GNU tar warns about FreeBSD's file-flag pax headers (SCHILY.fflags, e.g. schg on libc):
# harmless here, Hydra's ZFS has no BSD file flags.
$NICE tar --numeric-owner -xpJf "$DL/base.txz" -C "$WORK/root" --warning=no-unknown-keyword
[ "${TESTS:-0}" = 1 ] && $NICE tar --numeric-owner -xpJf "$DL/tests.txz" -C "$WORK/root" --warning=no-unknown-keyword

R=$WORK/root
say "trimming"
rm -rf "$R/boot"                      # loader, EFI loader, kernel config: Hydra boots itself
rm -rf "$R/usr/lib32" "$R/libexec/ld-elf32.so.1" 2>/dev/null || true
rm -rf "$R/var/db/etcupdate"          # etcupdate's copy of /etc (about 10 MB), not needed

say "configuring"
# Name resolution: the same resolver Hydra writes for /ubuntu (admin::linux::prepare_network_files
# rewrites it at start); a placeholder until wave 11 does the same for /freebsd.
echo "nameserver 10.0.2.3" > "$R/etc/resolv.conf"
cat > "$R/etc/hydra-root" <<EOF
personality=freebsd
release=$V-RELEASE
source=$URL/base.txz
sha256=$(sha256sum "$DL/base.txz" | cut -d' ' -f1)
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
# pkg(8) bootstrap configuration is already in /etc/pkg/FreeBSD.conf (quarterly, signed).
# The pkg tool itself is not in base: /usr/sbin/pkg is the bootstrapper that fetches it.

say "packing"
T="$OUT/freebsd-root-$V.tar.xz"
$NICE tar --numeric-owner -C "$R" -cf - . | $NICE xz -T4 -6 > "$T.tmp"
mv "$T.tmp" "$T"
(cd "$OUT" && sha256sum "$(basename "$T")" > "$(basename "$T").sha256")
say "done: $T ($(du -h "$T" | cut -f1)), root $(du -sh "$R" | cut -f1), $(find "$R" -type f | wc -l) files"
