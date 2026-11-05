#!/bin/sh
# Rough-edges check: unattended boot into Plasma, Konsole from the launcher's search,
# typing into it, scrolling its output with the wheel.
cd /d/os
corner=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    corner="$corner|!mouse_move -120 120|~0.3"
done
IFS='|'
set -- \
    "~960" \
    ${corner#|} \
    "!mouse_move 15 -12" "~1" "!mouse_move 15 -12" "~3" \
    "!mouse_button 1" "~0.3" "!mouse_button 0" "~40" \
    "@konsole" "~20" "%ret" "~90" \
    "!screendump D:/os/scratch/rb_konsole.ppm" \
    "@seq 1 200" "%ret" "~20" \
    "!mouse_move 300 -300" "~2" "!mouse_move 100 -50" "~2" \
    "!screendump D:/os/scratch/rb_before_wheel.ppm" \
    "!mouse_move 0 0 -5" "~1" "!mouse_move 0 0 -5" "~8" \
    "!screendump D:/os/scratch/rb_after_wheel.ppm" \
    "%f12" "~2"
unset IFS
timeout 1600 python tools/hydra_run.py --no-cancel --wait 3 --stall-dump 300 "$@" > scratch/rb_run.log 2>&1
for n in rb_konsole rb_before_wheel rb_after_wheel; do
    python tools/ppm2png.py scratch/$n.ppm scratch/$n.png
done
