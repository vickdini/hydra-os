"""vfscost.py LOG.vfs.json [...]: the added time of each VFS option per workload
(Group 16, wave 5; docs/vfs-design.md section 5). Call counts come from vfsparse.py;
the per-call costs are the vfsbench medians (KVM, 2 CPUs, PCID on, section 3 of the
design), given in COST below (override with name=value arguments, e.g. stat=3.5).

Columns:
  A       everything in linux-server: every class of call below is forwarded;
  B-lean  linux-server owns the VFS; the kernel keeps the descriptor table (handles) and
          answers fstat, close, fcntl, dup, lseek, poll and reads by handle (page cache);
  B-full  B-lean plus a kernel name/attribute cache answering stat, access and readlink
          on a hit (rate `hit`, default 0.95: a cache sized for the workload);
  C       the VFS stays in the kernel: nothing added;
  last    the extra for A and B when linux-server's file-server requests cost 3.2 us
          more than the kernel's (today's Queued call, CPU awake) instead of the same
          (a direct server-to-server call, to be built).
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vfsparse import classes

COST = {
    'fwd': 2.0,     # forwarded call that only needs its arguments: lx_null - getpgrp
    'path': 4.2,    # forwarded path call: stat_stub - getpgrp - server lookup (~0.2)
    'read': 3.3,    # forwarded 4 KiB read of cached data: read_stub_4k - getpgrp - today's copy
    'dents': 4.7,   # forwarded getdents64 (32 KiB buffer, SYS_LX_WRITE): dents_stub_32k - getpgrp
    'zfs': 0.0,     # extra per file-server request made by the server instead of the kernel
    'hit': 0.95,
}


def added_us(c, opt, k):
    f, p, r, d = k['fwd'], k['path'], k['read'], k['dents']
    z = k['zfs'] * c['zfs_req']
    if opt == 'C':
        return 0.0
    if opt == 'A':
        return (z + (c['path_zfs'] + c['path_pseudo']) * p + c['file_read'] * r
                + (c['file_data'] - c['file_read']) * f + c['file_meta'] * f + c['dir_getdents'] * d
                + c['pseudo_fd'] * f + c['other_table'] * f + c['poll'] * f + c['dup'] * f)
    if opt == 'B':
        return (z + c['path_open'] * p + c['path_stat'] * (1 - k['hit']) * p + c['path_change'] * p
                + c['path_pseudo'] * p + c['dir_getdents'] * d + c['pseudo_fd'] * f + c['file_write'] * f)
    raise ValueError(opt)


def main():
    k = dict(COST)
    files = []
    for a in sys.argv[1:]:
        if '=' in a:
            n, v = a.split('=', 1)
            k[n] = float(v)
        else:
            files.append(a)
    print('| Workload | Time today (s) | A: everything out | B-lean: table and file reads stay | B-full: B-lean + kernel name cache | C | Extra if linux-server calls zfs-server Queued (A, B) |')
    print('|---|---:|---:|---:|---:|---:|---:|')
    for p in files:
        for name, b in json.load(open(p)).items():
            c = classes(b)
            t = b.get('time_s')
            cells = []
            for opt, hit in (('A', 0), ('B', 0.0), ('B', k['hit']), ('C', 0)):
                us = added_us(c, opt, dict(k, zfs=0.0, hit=hit))
                cells.append(f"+{us/1e3:,.0f} ms ({100*us/1e6/t:.0f} %)" if t else f"+{us/1e3:,.0f} ms")
            q = 3.2 * c['zfs_req']
            cells.append(f"+{q/1e3:,.0f} ms ({100*q/1e6/t:.0f} %)" if t else f"+{q/1e3:,.0f} ms")
            print(f"| {name} | {t if t else '?'} | " + ' | '.join(cells) + ' |')


if __name__ == '__main__':
    main()
