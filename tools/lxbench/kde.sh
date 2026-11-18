#!/bin/bash
# Group 6: KDE login-to-desktop time and the system calls of a desktop start.
#   kde.sh NAME ISO   (screendumps -> /opt/u2604/tmp/TAG/kde-NAME/*.ppm, their mtimes are the times)
NAME=$1; ISO=$2
TREE=$(cd "$(dirname "$0")/../.." && pwd); TAG=${TAG:-$(basename "$TREE" | tr -d -)}
D=/tmp/$TAG/kde-$NAME
rm -rf /opt/u2604$D; mkdir -p /opt/u2604$D
A=( "linux plasma" "~150" "!screendump $D/sddm.ppm"
    "!sendkey ctrl-alt-f1" "~4" "@linux prof reset" "~2" "@linux prof on" "~2" "!sendkey ctrl-alt-f2" "~6"
    "!screendump $D/f000.ppm" "@hydra" "!screendump $D/f001.ppm" "%ret" )
for i in $(seq 2 100); do A+=( "!screendump $D/f$(printf %03d $i).ppm" "~0.7" ); done
A+=( "!sendkey ctrl-alt-f1" "~4" "@linux prof off" "~2" "@linux prof show 400" "~8"
     "@linux chroot /ubuntu /usr/bin/bash -c 'echo LXB-KDE-E\"\"ND'" )
exec bash "$(dirname "$0")/vm.sh" $NAME $ISO ${KDE_TO:-900} "--wait 400 --gap 0.3 --until LXB-KDE-END" "${A[@]}"
