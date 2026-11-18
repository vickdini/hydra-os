#!/bin/bash
# Example measurement session (Group 15, wave 5): the steps of run 1 of docs/display-input-design.md.
# Needs a copy of the lead's kde_kde.sh / kde_ctl.sh in scratch/ (git-ignored) and a VM booted with
#   wsl -d Ubuntu-20.04 -u root -e bash /mnt/e/os-N/scratch/kde_kde.sh NAME --login=
# on an instrumented build (instrument.py). Run it in WSL as root: bash session_example.sh NAME /mnt/e/os-N
N=${1:-g15}; TREE=${2:-/mnt/e/os-15}
C="bash $TREE/scratch/kde_ctl.sh $N"
ts() { date +%H:%M:%S; }
echo "$(ts) wait for sddm"; $C "~150" "shot g15-sddm"
echo "$(ts) console: prof on"; $C "%ctrl-alt-f1" "~5" "hydra" "~3" "hydra" "~5" "linux prof on" "~3" "exit" "~3" "%ctrl-alt-f2" "~5"
echo "$(ts) phase sddm-idle (20s)"; $C "~20"
echo "$(ts) login"; $C "%shift" "~2" "@hydra" "%ret" "~80" "shot g15-desktop"
echo "$(ts) phase desktop-idle (30s)"; $C "~30"
echo "$(ts) phase pointer (moves)"
steps=(); for r in 1 2 3; do for x in $(seq 100 40 1180); do steps+=(">move $x $((200+r*150))" "~0.05"); done; done
$C "${steps[@]}"
echo "$(ts) phase pointer done; idle 15"; $C "~15"
echo "$(ts) phase keys (krunner)"
steps=("%alt-f2" "~4"); for k in h e l l o w o r l d k o n s o l e s y s t e m; do steps+=("%$k" "~0.4"); done
steps+=("%esc" "~3"); $C "${steps[@]}"
echo "$(ts) phase keys done; idle 15"; $C "~15"
echo "$(ts) phase firefox start"; $C ">click 982 716" "~3" "%alt-f2" "~4" "@firefox https://en.wikipedia.org/wiki/Microkernel" "~2" "%ret" "~100" "shot g15-ff"
echo "$(ts) phase firefox scroll"
steps=(); for i in $(seq 1 15); do steps+=("%pgdn" "~1"); done; for i in $(seq 1 15); do steps+=("%pgup" "~1"); done
$C "${steps[@]}" "shot g15-ff2"
echo "$(ts) phase firefox idle (20s)"; $C "~20"
echo "$(ts) phase sound start (console)"
$C "%ctrl-alt-f1" "~5" "hydra" "~3" "hydra" "~5" "linux chroot /ubuntu /usr/bin/bash -c \"XDG_RUNTIME_DIR=/run/user/1000 timeout 60 bash -c 'while true; do pw-play /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga; done' >/dev/null 2>&1 &\"" "~5" "exit" "~3" "%ctrl-alt-f2" "~5"
echo "$(ts) phase sound + idle desktop (25s)"; $C "~25"
echo "$(ts) phase sound + pointer"
steps=(); for r in 1 2; do for x in $(seq 100 40 1180); do steps+=(">move $x $((250+r*150))" "~0.05"); done; done
$C "${steps[@]}"
echo "$(ts) phase sound end wait"; $C "~20"
echo "$(ts) console: prof show"; $C "%ctrl-alt-f1" "~5" "hydra" "~3" "hydra" "~5" "linux prof show 40" "~8" "shot g15-prof" "exit" "~3"
echo "$(ts) quit"; $C "quit"
