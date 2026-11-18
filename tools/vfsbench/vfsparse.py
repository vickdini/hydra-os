"""vfsparse.py LOG [LOG...] -> per-workload call counts by kind (Group 16, wave 5, VFS design).

Reads serial logs of tools/vfsbench/work.sh (or tools/lxbench/kde.sh) runs on the group 16
counter build: each `linux prof show` block (with its `[g16]` lines) belongs to the marker
`NAME-PROF` before it; `NAME-TIMED` ... `real XmY.YYYs` is the unprofiled time.
Prints a summary per workload and writes LOG.vfs.json for vfscost.py.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
names = {}
for l in open(os.path.join(HERE, '..', '..', 'src', 'compat', 'linux', 'syscalls.rs'), encoding='utf-8'):
    m = re.match(r'\s*pub const SYS_([A-Z0-9_]+):\s*u64\s*=\s*(\d+)', l)
    if m:
        names[int(m.group(2))] = m.group(1).lower()

POLL_NRS = {7, 23, 232, 270, 271, 281, 441}  # poll, select, epoll_wait, pselect6, ppoll, epoll_pwait, epoll_pwait2
EPOLL_CTL = {233}
PATH_PSEUDO = {'proc', 'sys', 'dev', 'run'}


def parse(path):
    txt = open(path, encoding='utf-8', errors='replace').read().replace('\r', '').replace('\x00', '')
    lines = txt.split('\n')
    out = {}
    cur = None
    times = {}
    timed = None
    i = 0
    while i < len(lines):
        l = lines[i]
        m = re.search(r'\b([A-Z0-9]+)-TIMED\b', l)
        if m and 'echo' not in l:
            timed = m.group(1)
        m = re.match(r'real\s+(\d+)m([\d.]+)s', l.strip())
        if m and timed:
            times[timed] = int(m.group(1)) * 60 + float(m.group(2))
            timed = None
        m = re.search(r'\b([A-Z0-9]+)-PROF\b', l)
        if m and 'echo' not in l:
            cur = m.group(1)
        if l.startswith('[prof] page faults:') and cur:
            blk = {'sc': {}, 'fs': {}, 'fd': {}, 'path': {}, 'cache': None, 'faults': {}}
            sect = 'faults'
            j = i + 1
            while j < len(lines) and (lines[j].startswith('[prof]') or lines[j].startswith('[g16]')):
                x = lines[j]
                if x.startswith('[g16] cache'):
                    v = list(map(int, re.findall(r'(\d+)', x[len('[g16] cache'):])))
                    blk['cache'] = {'names': v[0:2], 'attrs': v[2:4], 'links': v[4:6]}
                elif x.startswith('[g16] fd nr'):
                    m2 = re.match(r'\[g16\] fd nr (\d+)(.*)', x)
                    blk['fd'][int(m2.group(1))] = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', m2.group(2))}
                elif x.startswith('[g16] path nr'):
                    m2 = re.match(r'\[g16\] path nr (\d+)(.*)', x)
                    blk['path'][int(m2.group(1))] = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', m2.group(2))}
                elif 'file-server requests' in x:
                    sect = 'fs'
                elif 'system calls by total time' in x:
                    sect = 'sc'
                elif sect == 'faults':
                    m2 = re.match(r'\[prof\]\s+(\d+)\s+(\d+) ms\s+(\d+) \S+/each\s+(.*)', x)
                    if m2:
                        blk['faults'][m2.group(4)] = int(m2.group(1))
                elif sect == 'fs':
                    m2 = re.match(r'\[prof\]\s+(\d+)\s+(\d+) ms\s+(\d+) us/each\s+(\S+)', x)
                    if m2:
                        blk['fs'][m2.group(4)] = int(m2.group(1))
                        blk.setdefault('fs_ms', {})[m2.group(4)] = int(m2.group(2))
                elif sect == 'sc':
                    m2 = re.match(r'\[prof\]\s+nr\s+(\d+)\s+(\d+) calls\s+(\d+) ms', x)
                    if m2:
                        blk['sc'][int(m2.group(1))] = int(m2.group(2))
                j += 1
            out[cur] = blk
            cur = None
            i = j
            continue
        i += 1
    for k, v in out.items():
        v['time_s'] = times.get(k)
    return out


def classes(b):
    """Calls of one workload by the kinds that matter for the VFS options."""
    ik = lambda d: {int(k): v for k, v in d.items()}  # (JSON keys are strings)
    fd, path, sc = ik(b['fd']), ik(b['path']), ik(b['sc'])
    c = {}
    def fdk(nrs, kinds):
        return sum(fd.get(n, {}).get(k, 0) for n in nrs for k in kinds)
    DATA = [0, 1, 17, 18, 19, 20, 8, 9, 40]      # read write pread pwrite readv writev lseek mmap sendfile
    META = [3, 5, 72, 16, 74, 75, 77, 81, 262, 332]  # close fstat fcntl ioctl dup2 fsync fdatasync ftruncate fchdir fstatat/statx(empty)
    c['path_zfs'] = sum(v for p in path.values() for k, v in p.items() if k not in PATH_PSEUDO)
    c['path_pseudo'] = sum(v for p in path.values() for k, v in p.items() if k in PATH_PSEUDO)
    c['path_open'] = sum(v for n in (2, 257, 437) for k, v in path.get(n, {}).items() if k not in PATH_PSEUDO)
    c['path_stat'] = sum(v for n in (4, 6, 262, 332, 21, 269, 439, 89, 267, 191, 192) for k, v in path.get(n, {}).items() if k not in PATH_PSEUDO)
    c['path_change'] = c['path_zfs'] - c['path_open'] - c['path_stat']
    c['file_data'] = fdk(DATA, ['file'])
    c['file_read'] = fdk([0, 17, 19], ['file'])
    c['file_write'] = fdk([1, 18, 20], ['file'])
    c['file_meta'] = fdk(META, ['file', 'dir'])
    c['dir_getdents'] = fdk([217], ['dir', 'file'])
    c['pseudo_fd'] = fdk(DATA + META + [217], ['pseudo'])
    c['other_table'] = fdk([3, 5, 72, 262, 332], ['pipe', 'unix', 'inet', 'srvobj', 'device', 'tty', 'event', 'memfd'])
    c['poll'] = sum(sc.get(n, 0) for n in POLL_NRS) + sum(sc.get(n, 0) for n in EPOLL_CTL)
    c['dup'] = sum(sc.get(n, 0) for n in (32, 33, 292))
    c['total'] = sum(sc.values())
    c['zfs_req'] = sum(b['fs'].values())
    c['zfs_ms'] = sum(b.get('fs_ms', {}).values())
    return c


def main():
    allw = {}
    for p in sys.argv[1:]:
        r = parse(p)
        json.dump(r, open(p + '.vfs.json', 'w'), indent=1)
        for k, b in r.items():
            allw[k] = b
            c = classes(b)
            t = b['time_s']
            print(f"=== {k} ({os.path.basename(p)}): time {t} s, {c['total']} normal-path calls" + (f", {c['total']/t:,.0f}/s" if t else ''))
            print('   ', {kk: vv for kk, vv in c.items() if kk != 'total'})
            print('    cache', b['cache'], ' zfs', b['fs'])
            top = sorted(b['sc'].items(), key=lambda kv: -kv[1])[:16]
            print('    top', ', '.join(f"{names.get(n, n)}={v}" for n, v in top))
            for n, kinds in sorted(b['fd'].items(), key=lambda kv: -sum(kv[1].values()))[:10]:
                print(f"    fd {names.get(n, n)}: {kinds}")
            for n, kinds in sorted(b['path'].items(), key=lambda kv: -sum(kv[1].values()))[:10]:
                print(f"    path {names.get(n, n)}: {kinds}")


if __name__ == '__main__':
    main()
