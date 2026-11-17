#!/bin/bash
# Runs INSIDE a copy of the clean install image booted as a live session (root): lists what
# could still be personal. Everything between VERIFY-BEGIN and VERIFY-DONE goes into
# out/verify-clean.txt. Expected: every list below empty, except where noted.
export LC_ALL=C
echo VERIFY-BEGIN
P="-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o"
echo "== accounts with uid >= 1000 (expected: only nobody 65534)"; awk -F: '$3 >= 1000' /etc/passwd
echo "== passwords set (expected: none)"; awk -F: '$2 !~ /^[!*]/ && $2 != ""' /etc/shadow | cut -d: -f1
echo "== account file backups (expected: none)"; ls /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- /var/backups 2>/dev/null
echo "== the removed names anywhere in /etc (expected: none)"; grep -rIl -i -E '\b(vick|hydra:x:1000)\b' /etc 2>/dev/null | head -20
echo "== members of groups (expected: no people)"; awk -F: '$4 != ""' /etc/group
echo "== /home (expected: empty)"; ls -A /home
echo "== /root (expected: .bashrc .profile)"; ls -A /root
echo "== machine-id bytes (expected: 0)"; stat -c %s /etc/machine-id; ls /var/lib/dbus/machine-id 2>/dev/null
echo "== SSH host keys (expected: none)"; ls /etc/ssh/ssh_host_* 2>/dev/null
echo "== non-empty logs (expected: none or only this boot's)"; find /var/log -type f -size +0 2>/dev/null | head -20
echo "== journal, crash dumps (expected: none)"; ls -A /var/log/journal /var/crash /var/lib/systemd/coredump 2>/dev/null
echo "== apt lists and downloaded packages (expected: only lock/partial)"; ls -A /var/lib/apt/lists; ls /var/cache/apt/archives/*.deb 2>/dev/null | wc -l
echo "== network connections, leases, Bluetooth (expected: none)"; ls -A /etc/NetworkManager/system-connections /var/lib/NetworkManager /var/lib/dhcp /var/lib/bluetooth 2>/dev/null
echo "== sddm state (expected: nothing but this boot's)"; find /var/lib/sddm -type f 2>/dev/null
echo "== temporary files (expected: only X11/ICE socket dirs)"; ls -A /tmp /var/tmp
echo "== files owned by uid 1000-59999 (expected: none)"; find / $P \( -uid +999 -a -uid -60000 \) -print 2>/dev/null | head -30
echo "== histories, Wine prefixes, browser profiles, thumbnails (expected: none)"
find / $P \( -name '.bash_history' -o -name '.python_history' -o -name '.lesshst' -o -name '.wine' -o -name '.mozilla' -o -name 'places.sqlite' -o -name 'Cookies' -o -name 'thumbnails' -o -name '.viminfo' -o -name '.sudo_as_admin_successful' \) -print 2>/dev/null | head -30
echo "== installer tools"; for c in zstd sgdisk sfdisk mkfs.vfat mcopy efibootmgr; do printf '%s: %s\n' $c "$(command -v $c)"; done
echo "== size"; df -h / | tail -1
echo VERIFY-DONE
