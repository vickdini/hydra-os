#!/bin/bash
# lxbench in one VM: bench.sh NAME ISO [PROBE_EP]   (esp/bin/lxbench.elf must be in the ISO)
D=$(dirname "$0"); NAME=$1; ISO=$2; EP=${3:-0x22}
exec bash "$D/vm.sh" "$NAME" "$ISO" 590 "--wait 500 --until LXB-ALL-END" "cp /bin/lxbench.elf /ubuntu/tmp/lxbench.elf" \
  "linux chroot /ubuntu /usr/bin/bash -c 'cat /tmp/lxbench.elf > /tmp/lxb; chmod 755 /tmp/lxb; /tmp/lxb; PROBE_EP=$EP /tmp/lxb probe_handoff probe_queued probe_handoff_k probe_queued_k; echo LXB-AL\"\"L-END'"
