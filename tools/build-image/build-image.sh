#!/bin/bash
# Builds Hydra's clean install image and the live USB stick image from the main pool.
#
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/d/os-f/tools/build-image/build-image.sh [STEP...]
#
# Steps (all, in this order, when none are named):
#   snapshot  copy the main pool (/root/pool/hydrapool.qcow2 in the QEMU root /opt/u2604) into
#             work/base.qcow2 through a throwaway overlay; the main pool is only read
#   clean     boot a throwaway copy of it, run clean-inside.sh in it (removes people's accounts,
#             homes and everything personal, see that script), power off -> work/clean.raw
#   pack      hydra-pool-pack: only the live blocks of work/clean.raw, in a compact pool with a
#             new GUID -> out/pool.img, compressed with zstd -> out/pool.img.zst, its SHA-256
#             -> out/pool.img.sha256, sizes -> out/pool.conf; the installed system's EFI
#             partition files -> out/esp.tar (the install set, see LAYOUT.md section F)
#   verify    boot a copy of out/pool.img as a live session and list what is in it
#             (accounts, homes, logs...) -> out/verify-clean.txt
#   live      the live pool: the clean pool packed again with room for the install set,
#             booted as a live session that fetches it into /opt/hydra-install/ -> work/live.raw
#   liveiso   (not in "all") only work/hydra-live-test.iso: the tree's boot ISO with \hydra\live,
#             to try the live session on a pool disk without the stick
#   espimg    (not in "all"; wave 11) only work/esp-test.img: the stick's EFI partition
#   restick   (not in "all"; wave 11) out/hydra-live.img from an existing stick image (BASE,
#             default the lead's /root/pool/m-out/hydra-live.img, only read) with this tree's
#             kernel and boot files: on the stick's EFI partition and in its install set
#             (/opt/hydra-install/esp in the live pool, what the installer copies to the disk).
#             No pool snapshot and no cleaning: for a kernel-side change. Needs one VM boot.
#             EXTRA="treepath=poolpath ..." also installs files of this tree into the live pool
#             (mode 755), e.g. EXTRA="userland/hydra-logind/hydra-session=/usr/libexec/hydra-session".
#   stick     out/hydra-live.img: GPT disk image, EFI partition (kernel, boot files, \hydra\live)
#             + Hydra pool partition (work/live.raw)
#
# Needs: the kernel and boot files built in the tree (cargo build --release, make build), the
# QEMU root /opt/u2604 (qemu, OVMF, python3, zstd) and, in WSL itself, gcc, sfdisk, mtools,
# dosfstools, xorriso. Work files: /opt/u2604/root/pool/f-work, results: /opt/u2604/root/pool/f-out
# (WORK, OUT override; paths as seen inside /opt/u2604). TREE: the source tree (default: the
# one this script is in). PORT: the web server the VMs fetch from (default 8731).
set -euo pipefail
R=/opt/u2604
HERE=$(cd "$(dirname "$0")" && pwd)
TREE=${TREE:-$(cd "$HERE/../.." && pwd)}
CTREE=${TREE#$R}                       # the tree as seen inside the chroot (/mnt/d/...)
POOL=/root/pool/hydrapool.qcow2
WORK=${WORK:-/root/pool/f-work}
OUT=${OUT:-/root/pool/f-out}
PORT=${PORT:-8731}
# Damaged objects no directory names any more, left out of the image (hydra-pool-pack refuses
# a pool with damaged blocks otherwise; it leaves an object out only when it is damaged).
# 81915: a folder of the login screen's runtime files (uid 101) the main pool lost on
# 2026-11-09, unlinked by `zfs fsck repair` then but still allocated
DROP_OBJECTS=${DROP_OBJECTS-81915}
HEADROOM_CLEAN=${HEADROOM_CLEAN:-2G}   # free space in the install image's pool (it grows on boot)
HEADROOM_LIVE=${HEADROOM_LIVE:-1536M}  # free space in the stick's pool for the live session
ESP_MIB=${ESP_MIB:-512}
STEPS=${*:-snapshot clean pack verify live stick}
DROPS=""
for o in $DROP_OBJECTS; do DROPS="$DROPS --drop-object $o"; done

say() { echo "[build-image] $*"; }
die() { echo "[build-image] ERROR: $*" >&2; exit 1; }
inroot() { chroot $R /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root HYDRA_ISO="${HYDRA_ISO:-}" /bin/bash -c "$1"; }
# The same, holding one of the shared VM slots (the QEMU root's /usr/local/bin/vmslot, when it
# exists: several builders share one WSL): for VMs and big disk-image jobs
SLOT=""
[ -x $R/usr/local/bin/vmslot ] && SLOT=/usr/local/bin/vmslot
heavy() { chroot $R $SLOT /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root HYDRA_ISO="${HYDRA_ISO:-}" /bin/bash -c "$1"; }

# The QEMU root's mounts (WSL drops them when it idles)
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
# The tree may be on D: or E: (D:\os can be a junction to E:\os, which WSL shows as a link
# into /mnt/e), so the QEMU root needs both, and C:
if [ -d /mnt/e ] && ! mountpoint -q /mnt/e; then mount -t drvfs E: /mnt/e -o metadata 2>/dev/null || true; fi
for m in c d e; do
    if [ -d /mnt/$m ]; then
        mkdir -p $R/mnt/$m
        mountpoint -q $R/mnt/$m || mount --bind /mnt/$m $R/mnt/$m
    fi
done
mkdir -p $R$WORK $R$OUT

# A web server for the VMs (they reach the host at 10.0.2.2), serving directory $1
serve() {
    stop_serving
    inroot "cd '$1' && (setsid python3 -m http.server $PORT --bind 127.0.0.1 >/dev/null 2>&1 &)"
    sleep 1
}
stop_serving() { pkill -f "http.server $PORT" 2>/dev/null || true; }
trap stop_serving EXIT

# Boots disk $1 with the harness; $2 = log file name, $3 = --until regex, $4 = seconds, rest =
# harness arguments and commands
vm() {
    local disk=$1 log=$2 until=$3 wait=$4
    shift 4
    if pgrep -f "file=$disk," >/dev/null; then die "a VM already uses $disk"; fi
    local q=""
    for a in "$@"; do q="$q '${a//\'/\'\\\'\'}'"; done
    heavy "cd '$CTREE' && python3 tools/hydra_run.py --accel kvm --shared-host --smp 2 --disk '$disk' --wait $wait --until '$until' --log '$OUT/$log' $q" >/dev/null || true
    tr -d '\000' < "$R$OUT/$log" > "$R$OUT/$log.txt"
}

# The boot ISO with \hydra\live on its boot volume: the live session without the stick
live_iso() {
    local dist=$TREE/dist/x86_64 t=$R$WORK/liveiso
    [ -f "$dist/hydra.img" ] || die "no $dist/hydra.img: run make build"
    rm -rf "$t" && mkdir -p "$t/root/EFI/BOOT" "$t/root/bin"
    cp "$dist/hydra.img" "$t/root/efiboot.img"
    : > "$t/live"
    mmd -i "$t/root/efiboot.img" ::/hydra
    mcopy -i "$t/root/efiboot.img" "$t/live" ::/hydra/live
    cp "$dist/bootx64.efi" "$t/root/EFI/BOOT/BOOTX64.EFI"
    cp -r "$TREE"/esp/bin/* "$t/root/bin/"
    xorriso -as mkisofs -quiet -V HYDRALIVE -e efiboot.img -no-emul-boot -isohybrid-gpt-basdat -o "$R$WORK/hydra-live-test.iso" "$t/root"
    rm -rf "$t"
    export HYDRA_ISO=$WORK/hydra-live-test.iso
}

pack_tool() {
    gcc -O2 -Wall -o "$R$WORK/hydra-pool-pack" "$HERE/hydra-pool-pack.c"
}

conf_get() { sed -n "s/^$1=//p" "$R$OUT/pool.conf"; }

# The files of an EFI partition into directory $1: the kernel (fallback path and Hydra's own
# boot entry path) and the boot files it imports into the pool
esp_tree() {
    local d=$1 dist=$TREE/dist/x86_64
    [ -f "$dist/bootx64.efi" ] || die "no $dist/bootx64.efi: run make build"
    rm -rf "$d" && mkdir -p "$d/EFI/BOOT" "$d/EFI/hydra" "$d/bin"
    cp "$dist/bootx64.efi" "$d/EFI/BOOT/BOOTX64.EFI"
    cp "$dist/bootx64.efi" "$d/EFI/hydra/hydra.efi"
    cp -r "$TREE"/esp/bin/* "$d/bin/"
    [ -f "$TREE/esp/readme.txt" ] && cp "$TREE/esp/readme.txt" "$d/README.TXT"
    # wave11 GH: the start menu (normal / safe mode / safe mode, console), shown briefly
    # on an installed system; the stick waits longer (see the stick steps)
    mkdir -p "$d/hydra"
    printf '# Hydra start menu: shown at every start; entry 1 starts after this many seconds.\r\ntimeout=3\r\n' > "$d/hydra/menu"
    return 0
}

# wave11 GH: the stick's EFI partition image (512 MiB FAT32) into file $1: the tree's EFI
# files, the live flag, a 5 s start menu and a short note for whoever opens the stick on
# another computer
esp_image() {
    local E=$1
    rm -f "$E"
    mkfs.vfat -F 32 -n HYDRA-LIVE -C "$E" $((ESP_MIB << 10)) >/dev/null
    esp_tree "$R$WORK/esptree"
    mkdir -p "$R$WORK/esptree/hydra"
    printf 'Hydra live session: this file makes Hydra start as "try Hydra" from this stick.\r\n' > "$R$WORK/esptree/hydra/live"
    printf '# Hydra start menu: shown at every start; entry 1 starts after this many seconds.\r\ntimeout=5\r\n' > "$R$WORK/esptree/hydra/menu"
    # Boot breadcrumbs (\logs\steps.txt and on screen) from the very first instruction
    printf 'This file makes Hydra write each early start step into \\logs\\steps.txt (diagnostics).\r\n' > "$R$WORK/esptree/hydra/crumbs"
    printf '# Extra start words for Hydra, one or more per line (# starts a comment), e.g.\r\n#   verbose      boot messages instead of the logo\r\n#   iommu=off    no DMA remapping\r\n#   cpus=1       one processor\r\n' > "$R$WORK/esptree/hydra/options.txt"
    mkdir -p "$R$WORK/esptree/logs"
    printf 'Hydra writes a log of every start here: boot001.txt, boot002.txt, ... (the highest number is the newest).\r\nPlease send the newest one (or all of them) back.\r\n' > "$R$WORK/esptree/logs/README.TXT"
    mcopy -s -i "$E" "$R$WORK"/esptree/* ::/
    rm -rf "$R$WORK/esptree"
}

for step in $STEPS; do
    say "=== $step"
    case $step in
    snapshot)
        if pgrep -f "file=$POOL" >/dev/null; then die "the main pool is in use by a VM: try again when it is off"; fi
        heavy "set -e; cd '$WORK'; rm -f snap.qcow2 base.qcow2
                qemu-img create -q -f qcow2 -F qcow2 -b $POOL snap.qcow2
                qemu-img convert -O qcow2 snap.qcow2 base.qcow2
                rm -f snap.qcow2"
        say "copied the main pool to $WORK/base.qcow2"
        ;;
    clean)
        inroot "set -e; cd '$WORK'; rm -f clean.qcow2 clean.raw; qemu-img create -q -f qcow2 -F qcow2 -b $WORK/base.qcow2 clean.qcow2"
        serve "$CTREE/tools/build-image"
        # First the pool's own check of /run (runtime files only; it repairs damaged directories
        # there: the main pool had one in /run/user/101 on 2026-11-16)
        vm "$WORK/clean.qcow2" clean.log "Powering off" 1500 --login hydra:hydra --prompt '/bin$ ' \
            "zfs fsck /ubuntu/run repair" \
            "linux chroot /ubuntu /usr/bin/bash -c \"echo hydra | sudo -S bash -c 'curl -s http://10.0.2.2:$PORT/clean-inside.sh -o /tmp/c.sh; bash /tmp/c.sh'\""
        stop_serving
        grep -q "^CLEAN-OK" "$R$OUT/clean.log.txt" || die "cleaning failed (see $OUT/clean.log.txt)"
        grep -a "^\[clean\]" "$R$OUT/clean.log.txt" || true
        heavy "set -e; cd '$WORK'; qemu-img convert -O raw clean.qcow2 clean.raw; rm -f clean.qcow2"
        ;;
    pack)
        pack_tool
        heavy "set -e; cd '$OUT'; rm -f pool.img pool.img.zst
                '$WORK/hydra-pool-pack' $DROPS --headroom $HEADROOM_CLEAN '$WORK/clean.raw' pool.img > '$WORK/pack-clean.txt'"
        cat "$R$WORK/pack-clean.txt"
        say "compressing (zstd)"
        heavy "set -e; cd '$OUT'
                zstd -q -T2 -12 -o pool.img.zst pool.img
                sha256sum pool.img > pool.img.sha256
                {
                  echo '# Hydra install image (tools/build-image/build-image.sh); see LAYOUT.md, section F'
                  echo 'format=hydra-pool-raw+zstd'
                  echo \"image_bytes=\$(stat -c %s pool.img)\"
                  sed -n 's/^used_bytes=/data_bytes=/p; s/^pool_guid=/pool_guid=/p' '$WORK/pack-clean.txt'
                  echo \"zst_bytes=\$(stat -c %s pool.img.zst)\"
                  echo \"sha256=\$(cut -d' ' -f1 pool.img.sha256)\"
                  echo \"zst_sha256=\$(sha256sum pool.img.zst | cut -d' ' -f1)\"
                  echo \"built=\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
                  echo \"source=${SOURCE:-$(git -C "$TREE" rev-parse --short HEAD 2>/dev/null || echo unknown)}\"
                } > pool.conf"
        cat "$R$OUT/pool.conf"
        # The installed system's EFI partition (without the live flag)
        esp_tree "$R$WORK/esptree"
        tar -C "$R$WORK/esptree" -cf "$R$OUT/esp.tar" .
        rm -rf "$R$WORK/esptree"
        ;;
    verify)
        live_iso
        inroot "set -e; cd '$WORK'; rm -f verify.qcow2; qemu-img create -q -f qcow2 -F raw -b $OUT/pool.img verify.qcow2"
        serve "$CTREE/tools/build-image"
        vm "$WORK/verify.qcow2" verify.log "\nVERIFY-DONE" 600 --login "" \
            "linux chroot /ubuntu /usr/bin/bash -c \"curl -s http://10.0.2.2:$PORT/verify-inside.sh -o /tmp/v.sh; bash /tmp/v.sh\""
        stop_serving
        sed -n '/^VERIFY-BEGIN/,/^VERIFY-DONE/p' "$R$OUT/verify.log.txt" > "$R$OUT/verify-clean.txt"
        cat "$R$OUT/verify-clean.txt"
        inroot "rm -f '$WORK/verify.qcow2'"
        grep -q "^VERIFY-DONE" "$R$OUT/verify-clean.txt" || die "verification did not finish"
        ;;
    live)
        live_iso
        pack_tool
        zst=$(conf_get zst_bytes)
        [ -n "$zst" ] && [ -f "$R$OUT/esp.tar" ] || die "no install set: run the pack step"
        # The clean pool again, with room for the install set and the live session
        head=$(( zst + $(stat -c %s "$R$OUT/esp.tar") + $(numfmt --from=iec "$HEADROOM_LIVE") ))
        heavy "set -e; cd '$WORK'; rm -f live.raw live.qcow2
                ./hydra-pool-pack $DROPS --headroom $head clean.raw live.raw > pack-live.txt
                qemu-img create -q -f qcow2 -F raw -b $WORK/live.raw live.qcow2"
        cat "$R$WORK/pack-live.txt"
        serve "$OUT"
        cp "$HERE/live-inside.sh" "$R$OUT/live-inside.sh"
        vm "$WORK/live.qcow2" live.log "Powering off" 2400 --login "" \
            "linux chroot /ubuntu /usr/bin/bash -c \"curl -s http://10.0.2.2:$PORT/live-inside.sh -o /tmp/l.sh; PORT=$PORT bash /tmp/l.sh\""
        stop_serving
        rm -f "$R$OUT/live-inside.sh"
        grep -q "^LIVE-OK" "$R$OUT/live.log.txt" || die "the live pool did not get the install image (see $OUT/live.log.txt)"
        inroot "set -e; cd '$WORK'; qemu-img commit -q live.qcow2; rm -f live.qcow2"
        ;;
    stick)
        L=$R$WORK/live.raw
        [ -f "$L" ] || die "no live pool: run the live step"
        dist=$TREE/dist/x86_64
        pool_bytes=$(stat -c %s "$L")
        esp_bytes=$((ESP_MIB << 20))
        total=$(( (1 << 20) + esp_bytes + pool_bytes + (1 << 20) ))
        S=$R$OUT/hydra-live.img
        rm -f "$S" "$R$WORK/esp.img"
        truncate -s "$total" "$S"
        # GPT: 1 = EFI system partition, 2 = Hydra pool (type GUID in LAYOUT.md)
        sfdisk --quiet --label gpt "$S" <<EOF
label: gpt
start=2048, size=$((esp_bytes / 512)), type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"
start=$((2048 + esp_bytes / 512)), size=$((pool_bytes / 512)), type=7685A0B8-DF41-47EB-AF4F-02CE6FB01879, name="Hydra"
EOF
        # The EFI partition: the kernel at the fallback path and Hydra's own, the boot files the
        # kernel imports, the live flag and the start menu (esp_image)
        E=$R$WORK/esp.img
        esp_image "$E"
        dd if="$E" of="$S" bs=1M seek=1 conv=notrunc,sparse status=none
        dd if="$L" of="$S" bs=1M seek=$((1 + ESP_MIB)) conv=notrunc,sparse status=none
        rm -f "$E"
        python3 "$HERE/mbr-message.py" "$S"
        sfdisk --list "$S"
        (cd "$R$OUT" && sha256sum hydra-live.img > hydra-live.img.sha256)
        say "stick image: $OUT/hydra-live.img ($(numfmt --to=iec "$total")), $(cat "$R$OUT/hydra-live.img.sha256")"
        ;;
    restick)
        # wave11 GH: a stick from an existing one, with this tree's EFI files
        BASE=${BASE:-/root/pool/m-out/hydra-live.img}
        [ -f "$R$BASE" ] || die "no base stick $BASE"
        # The base's partition 1 must be the EFI partition this script makes (1 MiB, ESP_MIB)
        p1=$(sfdisk --dump "$R$BASE" | sed -n 's/.*: start= *\([0-9]*\), size= *\([0-9]*\), type=C12A7328.*/\1 \2/p' | head -1)
        [ "$p1" = "2048 $((ESP_MIB << 11))" ] || die "the base stick's EFI partition is not at 1 MiB with $ESP_MIB MiB ($p1)"
        live_iso
        inroot "set -e; cd '$WORK'; rm -f restick.qcow2; qemu-img create -q -f qcow2 -F raw -b $BASE restick.qcow2"
        # The install set's EFI files (what the installer copies to the disk)
        esp_tree "$R$WORK/esptree"
        tar -C "$R$WORK/esptree" -cf "$R$OUT/esp.tar" .
        rm -rf "$R$WORK/esptree"
        # Files of this tree for the live pool (EXTRA), and the list the VM installs from
        rm -rf "$R$OUT/extra" && mkdir -p "$R$OUT/extra"
        : > "$R$OUT/extra/list"
        i=0
        for pair in ${EXTRA:-}; do
            src=${pair%%=*}; dst=${pair#*=}
            [ -f "$TREE/$src" ] || die "EXTRA: no $TREE/$src"
            cp "$TREE/$src" "$R$OUT/extra/f$i"
            echo "f$i $dst" >> "$R$OUT/extra/list"
            i=$((i + 1))
        done
        cat > "$R$OUT/restick-inside.sh" <<'INSIDE'
#!/bin/bash
# Runs inside the stick's live pool (booted from the build's test ISO): replaces the install
# set's EFI files with the build host's, installs the EXTRA files, then powers off. Prints
# RESTICK-OK or RESTICK-FAILED.
D=/opt/hydra-install
ok=1
curl -sSf --retry 3 -o /tmp/extra.list "http://10.0.2.2:$PORT/extra/list" || ok=0
while read -r f dst; do
    [ -n "$f" ] || continue
    if curl -sSf --retry 3 -o "$dst.new" "http://10.0.2.2:$PORT/extra/$f"; then
        chmod 755 "$dst.new" && mv "$dst.new" "$dst" && echo "installed $dst" || ok=0
    else
        ok=0
    fi
done < /tmp/extra.list
curl -sSf --retry 3 -o /tmp/esp.tar "http://10.0.2.2:$PORT/esp.tar" || ok=0
if [ $ok = 1 ] && [ -d "$D" ]; then
    rm -rf "$D/esp.new" && mkdir -p "$D/esp.new" && tar -C "$D/esp.new" -xf /tmp/esp.tar --no-same-owner || ok=0
    [ -f "$D/esp.new/EFI/BOOT/BOOTX64.EFI" ] || ok=0
    if [ $ok = 1 ]; then rm -rf "$D/esp" && mv "$D/esp.new" "$D/esp" && chmod -R a+rX "$D/esp"; fi
else
    ok=0
fi
sha256sum "$D/esp/EFI/BOOT/BOOTX64.EFI"; find "$D/esp" -maxdepth 2 | head -20
rm -f /tmp/esp.tar
if [ $ok = 1 ]; then echo RESTICK-OK; else echo RESTICK-FAILED; fi
sync
/sbin/poweroff -f
INSIDE
        serve "$OUT"
        vm "$WORK/restick.qcow2" restick.log "Powering off" 900 --login "" \
            "linux chroot /ubuntu /usr/bin/bash -c \"curl -s http://10.0.2.2:$PORT/restick-inside.sh -o /tmp/r.sh; PORT=$PORT bash /tmp/r.sh\""
        stop_serving
        rm -f "$R$OUT/restick-inside.sh"
        rm -rf "$R$OUT/extra"
        grep -a "^installed " "$R$OUT/restick.log.txt" || true
        grep -q "^RESTICK-OK" "$R$OUT/restick.log.txt" || die "the install set was not updated (see $OUT/restick.log.txt)"
        grep -a "BOOTX64.EFI" "$R$OUT/restick.log.txt" | head -2 || true
        sha256sum "$TREE/dist/x86_64/bootx64.efi"
        # The new EFI partition, then the whole stick as a raw image
        esp_image "$R$WORK/esp.img"
        heavy "set -e; cd '$WORK'
                qemu-io -f qcow2 -c 'write -q -s $WORK/esp.img 1048576 $((ESP_MIB << 20))' restick.qcow2
                rm -f '$OUT/hydra-live.img'
                qemu-img convert -O raw restick.qcow2 '$OUT/hydra-live.img'
                rm -f restick.qcow2 esp.img"
        python3 "$HERE/mbr-message.py" "$R$OUT/hydra-live.img"
        sfdisk --list "$R$OUT/hydra-live.img"
        (cd "$R$OUT" && sha256sum hydra-live.img > hydra-live.img.sha256)
        say "stick image: $OUT/hydra-live.img, $(cat "$R$OUT/hydra-live.img.sha256")"
        ;;
    espimg)
        # wave11 GH (not in "all"): only work/esp-test.img, the stick's EFI partition from this
        # tree, for tests that put it on an overlay of a stick (qemu-io write at 1 MiB)
        esp_image "$R$WORK/esp-test.img"
        say "EFI partition image: $WORK/esp-test.img"
        ;;
    liveiso)
        # Only the test ISO (the kernel of the tree with \hydra\live): work/hydra-live-test.iso
        live_iso
        ;;
    *) die "unknown step $step" ;;
    esac
done
say "done: $STEPS"
