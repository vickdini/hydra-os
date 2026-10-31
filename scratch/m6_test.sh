#!/bin/sh
# M6 check: unattended boot into Plasma, open the launcher, switch to the console and back.
cd /d/os
args=""
corner=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    corner="$corner|!mouse_move -120 120|~0.3"
done
IFS='|'
set -- \
    "~480" \
    "!screendump D:/os/scratch/m6_desktop.ppm" \
    ${corner#|} \
    "!mouse_move 15 -12" "~1" "!mouse_move 15 -12" "~3" \
    "!mouse_button 1" "~0.3" "!mouse_button 0" "~60" \
    "!screendump D:/os/scratch/m6_launcher.ppm" \
    "!sendkey ctrl-alt-f1" "~5" \
    "!screendump D:/os/scratch/m6_console.ppm" \
    "!sendkey ctrl-alt-f2" "~10" \
    "!screendump D:/os/scratch/m6_back.ppm" \
    "%f12" "~2"
unset IFS
timeout 1000 python scratch/hydra_run.py --no-cancel --wait 3 "$@" > scratch/m6_run.log 2>&1
for n in m6_desktop m6_launcher m6_console m6_back; do
    python scratch/ppm2png.py scratch/$n.ppm scratch/$n.png
done
