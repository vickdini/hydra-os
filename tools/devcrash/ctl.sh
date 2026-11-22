#!/bin/bash
# Drops one step file into a running kde_vm.sh VM and waits for it (at most 300 s).
#   ctl.sh NAME 'step' 'step' ...     "shot X" saves a screendump as <tree>/scratch/X.png
# Steps are hydra_run.py's: text typed + Enter, ~N wait, %key, @text (typed, no Enter), >click X Y, quit.
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd); T=$(basename "$TREE" | tr -d -c "a-z0-9")
NAME=$1; shift
D=$R/tmp/devcrash-$T/ctl-$NAME
[ -d $D ] || { echo "no VM $NAME"; exit 1; }
N=$(date +%s%N)
shots=()
: > $D/$N.tmp
for s in "$@"; do
  if [[ $s == shot\ * ]]; then
    x=${s#shot }; shots+=("$x")
    echo "!screendump /tmp/devcrash-$T/shots/$x.ppm" >> $D/$N.tmp
    echo "~1" >> $D/$N.tmp
  else
    echo "$s" >> $D/$N.tmp
  fi
done
mv $D/$N.tmp $D/$N.cmd
for i in $(seq 1 600); do [ -e $D/$N.done ] && break; sleep 0.5; done
[ -e $D/$N.done ] || { echo "STEP NOT DONE (VM gone?)"; exit 1; }
cat $D/$N.out 2>/dev/null
for x in "${shots[@]}"; do
  timeout 60 chroot $R python3 /tmp/devcrash-$T/tree/tools/ppm2png.py /tmp/devcrash-$T/shots/$x.ppm /tmp/devcrash-$T/shots/$x.png >/dev/null && cp $R/tmp/devcrash-$T/shots/$x.png $TREE/scratch/$x.png && echo "shot $x saved"
done
