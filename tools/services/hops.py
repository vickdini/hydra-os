#!/usr/bin/env python3
"""Cross-service hops of real workloads under the service map of docs/linux-services-design.md.

Input: the exact per-call counts Group 16 profiled (`linux prof` plus throwaway counters by
descriptor kind and path prefix; docs/vfs-design.md section 3.3), copied into data/:
  kde25.vfs.json (KDE login), vw1 (APT, FF), vw2 (FIND, LSLR, GIT, TAR), vw5 (GCC = make).

For each workload it sorts every system call to the service that answers it in the target
shape (section 2 of the design), then counts:
  - forwards per service (calls that leave the kernel);
  - redirects (a lookup under /proc, /sys or /dev: vfs-server answers "ask service X");
  - synchronous calls between services (execve: process service -> vfs-server; connect/bind
    of a Unix socket: lx-ipc -> vfs-server, counted for every connect/bind, an upper bound);
  - process events (fork, exec, exit) posted to more than one service's ring.

and prints what each shape adds, in ms and % of the workload's time:
  A  one linux-server + vfs-server (Group 16's F1: the minimum decision 9 asks for);
  B  the full split (section 2), the kernel routing each call to its owner;
  C  the full split WITHOUT owner routing: linux-server relays every call of the other
     Linux services (Group 15's "B1 relay"), with today's Queued call or a direct call.

Usage: python tools/services/hops.py [--dcall 2.5] [--queued 9.0] [--table]
"""
import argparse
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

# (workload, file, key, time in s as docs/vfs-design.md section 3.3 states it)
WORKLOADS = [
    ("find /usr (warm)", "vw2.log.vfs.json", "FIND", 1.07),
    ("ls -lR /usr/share", "vw2.log.vfs.json", "LSLR", 7.92),
    ("git status", "vw2.log.vfs.json", "GIT", 0.58),
    ("tar of /usr/share/doc", "vw2.log.vfs.json", "TAR", 1.41),
    ("make of 30 C files", "vw5.log.vfs.json", "GCC", 8.30),
    ("apt-get install hello", "vw1.log.vfs.json", "APT", 11.8),
    ("Firefox headless start", "vw1.log.vfs.json", "FF", 5.05),
    ("KDE login", "kde25.vfs.json", "KDE", 25.0),
]

# --- the service map (section 2 of the design) -------------------------------------------
K, VFS, NET, IPC, PROC, DEV, TTY, SEC = "kernel", "vfs", "net", "ipc", "proc", "dev", "tty", "sec"
SERVICES = [VFS, NET, IPC, PROC, DEV, TTY, SEC]

# Answered in the kernel by number (design 5.1 of linux-server-design.md, plus the handle
# table of vfs-design.md section 7).
KERNEL_NR = {
    9, 10, 11, 12, 25, 26, 27, 28, 149, 150, 151, 152, 324,          # memory
    202, 273, 218, 334, 24, 203, 204, 309, 158, 205, 211, 154, 60,   # threads, futex, exit
    13, 14, 131, 15,                                                 # signal mask/handlers
    39, 186, 110, 102, 104, 107, 108, 118, 120, 228, 229, 96, 201,   # identity, time
    35, 230, 318,                                                    # sleep, getrandom
    8, 5, 3, 32, 33, 292, 436, 81,                                   # handle table
    7, 23, 270, 271, 232, 281, 233, 213, 291, 441,                   # poll family, epoll
    317, 0x6710, 319, 95, 239, 127, 237, 238,                         # seccomp, test call, memfd_create, umask, mempolicy, sigpending
}
# Path calls (vfs-server); a lookup under /proc, /sys or /dev is redirected.
PATH_NR = {2, 257, 437, 85, 4, 6, 262, 332, 21, 269, 439, 89, 267, 83, 258, 133, 259, 87,
           263, 84, 82, 264, 316, 86, 265, 88, 266, 90, 268, 92, 94, 260, 280, 132, 235,
           76, 191, 192, 188, 189, 194, 195, 197, 198, 137, 80, 161, 165, 166, 79, 155,
           428, 429, 430, 431, 432, 433, 442, 254, 255, 253, 294, 444, 445, 446,
           303, 304, 457, 458}
# Descriptor calls that change files (vfs-server) when the descriptor is a file/directory.
FILE_CHANGE_NR = {1, 18, 20, 296, 217, 78, 77, 74, 75, 91, 93, 73, 190, 193, 196, 199, 138,
                  285, 277, 326, 40, 221}
# Read-type descriptor calls answered by the kernel on a file handle.
FILE_READ_NR = {0, 17, 19, 295}
# Process and signal policy (the process service after step 7).
PROC_NR = {56, 435, 57, 58, 59, 322, 61, 247, 62, 234, 200, 231, 112, 109, 121, 124, 111,
           105, 106, 113, 114, 117, 119, 116, 115, 157, 302, 97, 160, 98, 100, 99, 63, 170,
           171, 272, 308, 125, 126, 101, 222, 223, 224, 225, 226, 36, 38, 37, 140, 141,
           142, 143, 144, 145, 146, 147, 148, 251, 252, 122, 123, 103, 159, 164, 227,
           424, 434, 438, 310, 311, 312, 153, 163, 169, 167, 168, 179}
# Local IPC objects created by number.
IPC_NR = {22, 293, 290, 284, 283, 286, 287, 282, 289, 240, 241, 242, 243, 244, 245,
          64, 65, 66, 220, 68, 69, 70, 71, 29, 30, 31, 67, 275, 276, 278}
SEC_NR = {248, 249, 250, 321}
SOCKET_NR = {41, 53, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 288, 299, 307}
FORK_NR = {56, 435, 57, 58}
EXEC_NR = {59, 322}
EXIT_NR = {231, 60}

# Descriptor kind (Group 16's counters) -> service.
KIND = {"file": VFS, "dir": VFS, "pseudo": PROC, "pipe": IPC, "unix": IPC, "event": IPC,
        "device": DEV, "tty": TTY, "memfd": K, "bad": K, "inet": NET}
# "pseudo" (an open /proc, /sys or /dev pseudo file, /dev/null included) is counted as the
# process service's; /sys and /dev files belong to the device services, and /dev/null could
# even be answered in the kernel. It does not change the totals of a shape.

# Workloads whose sockets are mostly Internet sockets (the rest: Unix).
INET_SHARE = {"APT": 0.5, "FF": 0.3}


def classify(name, w):
    """Returns (forwards per service, redirects, dcalls (count, reason), process events)."""
    sc = {int(k): v for k, v in w["sc"].items()}
    fd = {int(k): v for k, v in w.get("fd", {}).items()}
    paths = {int(k): v for k, v in w.get("path", {}).items()}
    fwd = Counter()
    redirects = 0
    for nr, n in sc.items():
        if nr in fd:  # split by descriptor kind
            kinds = fd[nr]
            known = sum(kinds.values())
            for kind, m in kinds.items():
                svc = KIND.get(kind, K)
                if svc == VFS and nr in FILE_READ_NR:
                    svc = K  # read of a file handle: the kernel
                if svc == VFS and nr not in FILE_CHANGE_NR and nr not in PATH_NR:
                    svc = K  # e.g. fcntl, fstat on a file: the handle table
                if svc != K:
                    fwd[svc] += m
            rest = n - known  # calls the counters did not split (none in practice)
            if rest > 0 and nr not in KERNEL_NR and nr not in FILE_READ_NR:
                fwd[VFS] += rest
            continue
        if nr in KERNEL_NR or nr in FILE_READ_NR:
            continue
        if nr in PATH_NR:
            fwd[VFS] += n
            pp = paths.get(nr, {})
            redirects += pp.get("proc", 0) + pp.get("sys", 0) + pp.get("dev", 0)
        elif nr in FILE_CHANGE_NR:
            fwd[VFS] += n
        elif nr in PROC_NR:
            fwd[PROC] += n
        elif nr in IPC_NR:
            fwd[IPC] += n
        elif nr in SEC_NR:
            fwd[SEC] += n
        elif nr in SOCKET_NR:
            share = INET_SHARE.get(name, 0.0)
            fwd[NET] += round(n * share)
            fwd[IPC] += n - round(n * share)
        elif nr == 16:
            fwd[DEV] += n  # ioctl without kind data: devices
        else:
            fwd[PROC] += n  # anything else unlisted: count it as forwarded somewhere
    share = INET_SHARE.get(name, 0.0)
    unix_connect_bind = round((sc.get(42, 0) + sc.get(49, 0)) * (1 - share))
    dcalls = {"execve -> vfs-server": sum(sc.get(n, 0) for n in EXEC_NR),
              "Unix connect/bind -> vfs-server (upper bound)": unix_connect_bind}
    events = sum(sc.get(n, 0) for n in FORK_NR | EXEC_NR | EXIT_NR)
    return fwd, redirects, dcalls, events, sum(sc.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dcall", type=float, default=2.5, help="direct server-to-server call, us")
    ap.add_argument("--queued", type=float, default=9.0, help="today's Queued server call, us")
    ap.add_argument("--fwd", type=float, default=2.4, help="one more forward (a redirect), us")
    ap.add_argument("--post", type=float, default=0.3, help="one more ring post per event, us")
    ap.add_argument("--extra-rings", type=int, default=2,
                    help="services that take process events besides the first")
    ap.add_argument("--table", action="store_true", help="markdown tables")
    a = ap.parse_args()

    rows_svc, rows_cost = [], []
    for title, f, key, t in WORKLOADS:
        w = json.load(open(os.path.join(DATA, f)))[key]
        fwd, redir, dcalls, events, total = classify(key, w)
        nd = sum(dcalls.values())
        # A: linux-server + vfs-server. Cross-service: dcalls + redirects. Events: 1 ring.
        a_ms = (nd * a.dcall + redir * a.fwd) / 1000
        # B: full split: as A plus process events posted to more rings.
        b_ms = a_ms + events * a.extra_rings * a.post / 1000
        # C: full split, linux-server relays every call of ipc/net/dev/tty/sec/proc.
        relayed = sum(fwd[s] for s in (NET, IPC, DEV, TTY, SEC, PROC))
        c_direct = b_ms + relayed * a.dcall / 1000
        c_queued = b_ms + relayed * a.queued / 1000
        rows_svc.append((title, total, sum(fwd.values()), [fwd[s] for s in SERVICES], redir, nd, events))
        rows_cost.append((title, t, a_ms, b_ms, c_direct, c_queued))

    def pct(ms, t):
        return f"{ms:,.1f} ms ({100 * ms / (t * 1000):.2f} %)"

    if a.table:
        print("| Workload | Calls | Forwarded | " + " | ".join(SERVICES) + " | Redirects | Calls between services | Process events |")
        print("|---|---:|---:|" + "---:|" * len(SERVICES) + "---:|---:|---:|")
        for title, total, nf, per, redir, nd, ev in rows_svc:
            print(f"| {title} | {total:,} | {nf:,} | " + " | ".join(f"{x:,}" for x in per) + f" | {redir:,} | {nd:,} | {ev:,} |")
        print()
        print(f"| Workload | Time | A: linux-server + vfs-server | B: full split, owner routing | C: full split, relay (direct {a.dcall} µs) | C: relay (Queued {a.queued} µs) |")
        print("|---|---:|---:|---:|---:|---:|")
        for title, t, am, bm, cd, cq in rows_cost:
            print(f"| {title} | {t} s | {pct(am, t)} | {pct(bm, t)} | {pct(cd, t)} | {pct(cq, t)} |")
    else:
        for (title, total, nf, per, redir, nd, ev), (_, t, am, bm, cd, cq) in zip(rows_svc, rows_cost):
            print(f"{title}: {total} calls, {nf} forwarded {dict(zip(SERVICES, per))}, redirects {redir}, dcalls {nd}, events {ev}")
            print(f"   A {pct(am, t)}   B {pct(bm, t)}   C-direct {pct(cd, t)}   C-queued {pct(cq, t)}")


if __name__ == "__main__":
    main()
