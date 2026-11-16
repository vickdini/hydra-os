#!/bin/bash
# Runs INSIDE a throwaway copy of the Hydra pool, as root, in the Ubuntu system of the pool
# (build-image.sh starts it): removes everything personal so the pool can become the clean
# install image. What stays: the system, its apps and Hydra's default settings.
#
# It ends by printing CLEAN-OK (or CLEAN-FAILED) and powering the VM off.
set -u
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
say() { echo "[clean] $*"; }

# 0. What the installer needs on the live system (Group G's installer writes the target disk
#    with these: zstd for the image, sgdisk/sfdisk for the partitions, mkfs.vfat/mtools for the
#    EFI partition, efibootmgr for the boot entry). Installed before the apt lists go.
PKGS=""
for p in zstd gdisk fdisk dosfstools mtools efibootmgr; do
    dpkg-query -W -f='${db:Status-Status}' "$p" 2>/dev/null | grep -qx installed || PKGS="$PKGS $p"
done
if [ -n "$PKGS" ]; then
    say "installing:$PKGS"
    apt-get update -q >/dev/null 2>&1
    apt-get install -y -q --no-install-recommends $PKGS >/dev/null 2>&1 || say "WARNING: could not install$PKGS"
fi
for c in zstd sgdisk sfdisk mkfs.vfat mcopy efibootmgr; do command -v "$c" >/dev/null || say "WARNING: $c missing"; done

# 1. People's accounts (uid 1000-59999) and their homes, mail, cron jobs, access-control
#    records, AccountsService records
USERS=$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd)
for u in $USERS; do
    say "removing user $u"
    rm -f "/etc/hydra/access/subjects/$u" "/var/lib/AccountsService/users/$u" "/var/lib/AccountsService/icons/$u" \
          "/var/spool/cron/crontabs/$u" "/var/mail/$u" "/var/spool/mail/$u" "/etc/sudoers.d/$u"
    userdel --force --remove "$u" 2>/dev/null || userdel --force "$u"
    getent group "$u" >/dev/null && groupdel "$u" 2>/dev/null
done
# Names of removed people left as members of system groups (groupmems, usermod -aG)
for u in $USERS; do
    for f in /etc/group /etc/gshadow; do
        [ -f "$f" ] && sed -i -E "s/([:,])$u(,|\$)/\1\2/g; s/,,/,/g; s/:,/:/g; s/,\$//" "$f"
    done
done
rm -rf /home/* /home/.[!.]* 2>/dev/null
# Earlier copies of the account files (they still name the removed people)
rm -f /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- /etc/subuid- /etc/subgid-
rm -rf /var/backups/*
# The login screen remembers the last user and session
find /var/lib/sddm -mindepth 1 -delete 2>/dev/null

# 2. root's own files: only the stock shell settings stay
find /root -mindepth 1 -maxdepth 1 ! -name .bashrc ! -name .profile -exec rm -rf {} + 2>/dev/null

# 3. Identity of this computer: a new machine-id is made at the next boot (hydra-session)
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id /var/lib/systemd/random-seed
rm -f /etc/ssh/ssh_host_*

# 4. Logs, crash dumps
find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' -o -name '*.xz' \) -delete 2>/dev/null
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null
rm -rf /var/log/journal/* /var/crash/* /var/lib/systemd/coredump/* 2>/dev/null

# 5. Package caches and lists (Hydra Apps fetches the lists again when they are missing)
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/debconf/*-old 2>/dev/null
mkdir -p /var/lib/apt/lists/partial

# 6. Networks this computer knew, leases, Bluetooth pairings
rm -rf /etc/NetworkManager/system-connections/* /var/lib/NetworkManager/* /var/lib/dhcp/* /var/lib/bluetooth/* 2>/dev/null

# 7. sudo and polkit state of the removed people
rm -rf /var/lib/sudo/lectured/* /var/lib/sudo/ts/* 2>/dev/null

# 8. Temporary files (the X11/ICE socket directories come back at boot)
rm -rf /tmp/* /tmp/.[!.]* /var/tmp/* /var/tmp/.[!.]* 2>/dev/null

# Check
left=$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd)
homes=$(ls -A /home)
if [ -z "$left" ] && [ -z "$homes" ] && [ ! -s /etc/machine-id ]; then
    say "users now: $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | tr '\n' ' ')"
    say "used: $(df -h / | tail -1)"
    echo CLEAN-OK
else
    say "left: users [$left] homes [$homes]"
    echo CLEAN-FAILED
fi
sync
/sbin/poweroff -f
