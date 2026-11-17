#!/bin/bash
# Group 6: workload timings and system call profiles (stock kernel): work.sh NAME ISO
NAME=$1; ISO=$2
P() { A+=( "linux prof reset" "linux prof on" "linux chroot /ubuntu /usr/bin/bash -c '$1; echo $2-DONE'" "linux prof off" "linux prof show 400" ); }
A=()
P "cd /tmp; time (find /usr > /dev/null 2>&1); time (find /usr > /dev/null 2>&1)" FIND
P "time (tar cf - /usr/share/doc 2>/dev/null | cat > /dev/null)" TAR
P "time (du -s /usr/lib > /dev/null 2>&1)" DU
P "time (echo hydra | sudo -S apt-get update 2>&1 | tail -2)" APT
P "cd /tmp; time (timeout 120 firefox --headless --screenshot /tmp/ff.png about:blank > /dev/null 2>&1)" FF1
P "cd /tmp; time (timeout 120 firefox --headless --screenshot /tmp/ff.png about:blank > /dev/null 2>&1)" FF2
A+=( "linux chroot /ubuntu /usr/bin/bash -c 'echo LXB-WORK-E\"\"ND'" )
exec bash "$(dirname "$0")/vm.sh" $NAME $ISO 1500 "--wait 1400 --prompt hydra:/bin\$ --prompt-timeout 500 --until LXB-WORK-END" "${A[@]}"
