#!/bin/bash
# Kills one device service under KDE (once, then again within 30 s: the restart ladder's second
# crash, FailObjects) and records what the desktop does (wave 8, Group H).
#   wsl -d Ubuntu-20.04 -u root -e bash $TREE/tools/devcrash/devcrash.sh NAME SERVICE [ISO]
# SERVICE: input | sound | display | tty | ipc. ISO: default this tree's dist/x86_64/kernel.iso.
# Output: <tree>/scratch/devcrash-NAME.txt (summary), NAME-*.png (screens), NAME.log (serial log).
#
#   input    Konsole open; kill input_server, type; kill again, type one line a second
#            (t0, t1, ...: the first line on the screen tells when the keyboard came back),
#            open the start menu with a click (the pointer).
#   sound    a 60 s sine with pw-play; kill sound_server twice 10 s apart; PipeWire and
#            WirePlumber still running? a new 10 s pw-play (rc 0 = it played), the sinks, the
#            recorded WAV's gaps.
#   display  kill display_server: the session ends on purpose, SDDM comes back (decision 28).
#   tty      Konsole open; kill tty_server twice: its shell ends with its window, the desktop
#            stays, a new Konsole works.
#   ipc      kill lx_ipc: the session ends on purpose, SDDM comes back.
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd); T=$(basename "$TREE" | tr -d -c "a-z0-9")
NAME=$1; SVC=$2; ISO=${3:-$TREE/dist/x86_64/kernel.iso}
D=$R/tmp/devcrash-$T
C="bash $TREE/tools/devcrash/ctl.sh $NAME"
OUT=$TREE/scratch/devcrash-$NAME.txt
bash $TREE/tools/devcrash/kde_vm.sh $NAME "$ISO" > /tmp/devcrash-$NAME.vm.txt 2>&1 &
VPID=$!
for i in $(seq 1 600); do [ -d $D/ctl-$NAME ] && [ -e $D/$NAME.log ] && break; sleep 2; done
# Log in, open Konsole
$C "~150" "%shift" "~2" "@hydra" "%ret" "~90" ">click 982 716" "~3" "%alt-f2" "~8" "@konsole" "~4" "%ret" "~25" "@echo before-kill" "%ret" "~3" "shot $NAME-0-before"
CONSOLE=("%ctrl-alt-f1" "~4" "hydra" "~2" "hydra" "~3")
case $SVC in
input)
  $C "${CONSOLE[@]}" "service kill input_server" "~3" "%ctrl-alt-f2" "~3" "@echo after-kill-1" "%ret" "~3" "shot $NAME-1-kill1"
  $C "%ctrl-alt-f1" "~3" "service kill input_server" "~2" "%ctrl-alt-f2" \
     "@echo t0" "%ret" "~1" "@echo t1" "%ret" "~1" "@echo t2" "%ret" "~1" "@echo t3" "%ret" "~1" "@echo t4" "%ret" "~1" \
     "@echo t5" "%ret" "~2" "@echo t7" "%ret" "~3" "@echo t10" "%ret" "~5" "@echo t15" "%ret" "~3" "shot $NAME-2-kill2"
  $C ">click 30 779" "~4" "shot $NAME-3-pointer" "%esc" "~2"
  ;;
sound)
  $C "${CONSOLE[@]}" "cp /bin/sinegen.elf /ubuntu/tmp/sinegen.elf" "~3" \
     "linux chroot /ubuntu /usr/bin/bash -c 'cd /tmp; cat sinegen.elf > sinegen; chmod 755 sinegen; ./sinegen /tmp/sine.wav 60; ./sinegen /tmp/sine10.wav 10; XDG_RUNTIME_DIR=/run/user/1000 setsid nohup pw-play /tmp/sine.wav > /tmp/pw.out 2>&1 & echo STARTED'" "~10"
  $C "service kill sound_server" "~10" "service kill sound_server" "~15"
  $C "linux chroot /ubuntu /usr/bin/bash -c 'echo PW1: \$(cat /tmp/pw.out); echo PROCS \$(pgrep -l pipewire) \$(pgrep -l wireplumber) \$(pgrep -l pw-play); echo KILL\"\"CHECK'" "~6"
  $C "linux chroot /ubuntu /usr/bin/bash -c 'cd /tmp; XDG_RUNTIME_DIR=/run/user/1000 timeout 25 pw-play /tmp/sine10.wav; echo PW2 rc=\$?; XDG_RUNTIME_DIR=/run/user/1000 timeout 5 wpctl status 2>&1 | grep -A2 -i sinks | head -3; echo KILL\"\"DONE'" "~30" "%ctrl-alt-f2" "~4" "shot $NAME-1-after"
  ;;
display)
  $C "${CONSOLE[@]}" "service kill display_server" "~40" "%ctrl-alt-f2" "~5" "shot $NAME-1-after"
  ;;
tty)
  $C "${CONSOLE[@]}" "service kill tty_server" "~3" "service kill tty_server" "~5" "%ctrl-alt-f2" "~5" "shot $NAME-1-after"
  $C "%alt-f2" "~4" "@konsole" "~2" "%ret" "~20" "@echo new-konsole" "%ret" "~3" "shot $NAME-2-newkonsole"
  ;;
ipc)
  $C "${CONSOLE[@]}" "service kill lx_ipc" "~40" "%ctrl-alt-f2" "~5" "shot $NAME-1-after"
  ;;
esac
$C "%ctrl-alt-f1" "~3" "service status" "~3" "quit"
wait $VPID
cp $D/$NAME.log $D/$NAME.harness.txt $TREE/scratch/ 2>/dev/null
L=$TREE/scratch/$NAME.log
{
  echo "== devcrash $NAME: $SVC, ISO $ISO"
  tr -d '\000\r' < $L | grep -a -E '\[hotplug\]|went away|online \(process|PW1|PW2|PROCS|Sinks|^ .*\*|screend|session|desktop|greeter|sddm' | grep -av 'linux chroot' | head -60
  echo "== crashes (signal N at): $(tr -d '\000\r' < $L | grep -ac 'signal [0-9]* at')"
  tr -d '\000\r' < $L | grep -a 'signal [0-9]* at' | head -5
  if [ $SVC = sound ]; then python3 $TREE/tools/wavgaps.py $D/$NAME.wav 2>&1 | head -12; fi
  echo "== screens: $(ls $TREE/scratch/$NAME-*.png 2>/dev/null | xargs -n1 basename | tr '\n' ' ')"
} > $OUT
rm -f $D/$NAME.wav
cat $OUT
