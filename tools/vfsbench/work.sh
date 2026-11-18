#!/bin/bash
# Group 16 (wave 5): system call profiles of real workloads for the VFS design.
#   work.sh NAME [WORKLOADS...]   (in WSL as root; uses this tree's dist/x86_64/kernel.iso)
# WORKLOADS: FIND LSLR GIT TAR GCC APT FF (default: all). BENCH=1 runs vfsbench first;
# REPO="dirs" picks what the git repository holds (default /usr/share/doc /usr/include).
# Each workload runs three times in the Ubuntu root: once to warm the caches, once timed
# without profiling, once under `linux prof` (counts; the profiler's own cost does not
# matter for counts). With the group 16 counter build (tools/vfsbench/prototype.patch)
# `linux prof show` also prints `[g16]` lines: descriptor calls by descriptor kind, path
# calls by path class, ZFS client cache hits. Parse with tools/vfsbench/vfsparse.py.
# Needs esp/bin/g16src.elf: a tar of a small C project (30 files of tests/linux plus a Makefile),
# named .elf because the boot import copies only .elf files into /bin.
R=/opt/u2604
TREE=$(cd "$(dirname "$0")/../.." && pwd); TAG=${TAG:-$(basename "$TREE" | tr -d -)}
NAME=$1; shift; WL=" ${*:-FIND LSLR GIT TAR GCC APT FF} "
mountpoint -q $R/proc || mount -t proc proc $R/proc
for m in sys dev dev/pts; do mountpoint -q $R/$m || mount --bind /$m $R/$m; done
for m in c d e; do mkdir -p $R/mnt/$m; mountpoint -q $R/mnt/$m || mount --bind /mnt/$m $R/mnt/$m; done
mkdir -p $R/tmp/$TAG; cp "$TREE/dist/x86_64/kernel.iso" $R/tmp/$TAG/$NAME.iso
S='echo hydra | sudo -S'
A=( "cp /bin/g16src.elf /ubuntu/tmp/g16src.tar" )
[ -n "$BENCH" ] && A+=( "cp /bin/vfsbench.elf /ubuntu/tmp/vfsbench.elf" "linux chroot /ubuntu /usr/bin/bash -c 'cat /tmp/vfsbench.elf > /tmp/vfsb; chmod 755 /tmp/vfsb; $S /tmp/vfsb; echo VFSB-B\"\"ENCH-END'" )
A+=( "linux chroot /ubuntu /usr/bin/bash -c '(command -v git && command -v gcc && command -v make) > /dev/null || ($S apt-get install -y -q git gcc make libc6-dev > /tmp/inst.log 2>&1; tail -2 /tmp/inst.log); $S apt-get install -d -y -q hello > /tmp/dl.log 2>&1; tail -1 /tmp/dl.log; cd /tmp; mkdir -p repo proj; cd repo; cp -a ${REPO:-/usr/share/doc /usr/include} . 2> /dev/null; git init -q; git add -A; git -c user.email=g16@x -c user.name=g16 commit -qm init; git ls-files | wc -l; cd /tmp/proj; tar xf /tmp/g16src.tar; ls *.c | wc -l; echo SETUP-D\"\"ONE'" )
# let the pool write back what the setup wrote before anything is timed
A+=( "linux chroot /ubuntu /usr/bin/bash -c 'sync; sleep 120; echo SETTLE-D\"\"ONE'" )
# W name 'command' [cleanup run after each run, not profiled]
W() {
  local n=$1 c=$2 after=${3:-true}
  [[ $WL == *" $n "* ]] || return 0
  A+=( "linux chroot /ubuntu /usr/bin/bash -c '$c > /dev/null 2>&1; $after > /dev/null 2>&1; echo $n-W\"\"ARM'"
       "linux chroot /ubuntu /usr/bin/bash -c 'echo $n-TIMED; time ( $c > /dev/null 2>&1 ); $after > /dev/null 2>&1; echo $n-T\"\"IMEEND'"
       "linux prof reset" "linux prof on"
       "linux chroot /ubuntu /usr/bin/bash -c '$c > /dev/null 2>&1; echo $n-P\"\"ROF'"
       "linux prof off" "linux prof show 400"
       "linux chroot /ubuntu /usr/bin/bash -c '$after > /dev/null 2>&1; echo $n-D\"\"ONE'" )
}
W FIND 'find /usr'
W LSLR 'ls -lR /usr/share'
W GIT 'cd /tmp/repo; git status'
W TAR 'tar cf - /usr/share/doc | cat'
W GCC 'cd /tmp/proj; make -s -j2' 'cd /tmp/proj; rm -f *.o'
W APT "$S apt-get install -y hello" "$S apt-get remove -y hello"
W FF 'cd /tmp; timeout 120 firefox --headless --screenshot /tmp/ff.png about:blank'
A+=( "linux chroot /ubuntu /usr/bin/bash -c 'echo VFSW-E\"\"ND'" )
exec bash "$TREE/tools/lxbench/vm.sh" "$NAME" $NAME.iso 2700 "--wait 2500 --prompt hydra:/bin\$ --prompt-timeout 900 --until VFSW-END" "${A[@]}"
