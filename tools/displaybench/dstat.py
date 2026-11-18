#!/usr/bin/env python3
"""Turns the `[dstat]` blocks of an instrumented kernel's serial log into one table row per
5-second block (rates per second), so the phases of a session (idle, pointer, keys, Firefox,
sound) can be told apart and averaged.

    python dstat.py LOG [FIRST-LAST:name ...]

Without ranges it prints every block; with ranges (block numbers, 1-based, as printed) it
also prints the averages per named phase.
"""
import re
import sys


def blocks(path):
    text = open(path, "rb").read().replace(b"\0", b"").decode("utf-8", "replace").replace("\r", "")
    cur = None
    for line in text.splitlines():
        i = line.find("[dstat] ")
        if i < 0:
            continue
        line = line[i + 8:]
        if line.startswith("dt="):
            if cur:
                yield cur
            cur = {"line": [line]}
        elif cur is not None:
            cur["line"].append(line)
    if cur:
        yield cur


def num(s, key):
    m = re.search(r"(?<![\w>])" + re.escape(key) + r"=(\d+)", s)
    return int(m.group(1)) if m else 0


def parse(b):
    sysl, drm, inp, snd = (b["line"] + ["", "", "", ""])[:4]
    dt = num(sysl, "dt") / 1000.0 or 5.0
    r = {"dt": dt}
    for k in ["sys", "ioctl", "read", "write", "epoll_wait", "epoll_pwait", "poll", "ppoll", "recvmsg", "sendmsg", "futex", "writev"]:
        r[k] = num(sysl, k) / dt
    r["drm_ioctl"] = num(drm, "ioctls") / dt
    r["drm_read"] = num(drm, "read") / dt
    r["flips"] = num(drm, "flips") / dt
    r["present_us"] = num(drm, "present_avg_us")
    r["present_max_us"] = num(drm, "present_max_us")
    r["cursors"] = num(drm, "cursors") / dt
    m = re.search(r"gaps\[[^\]]*\]=([\d,]+)", drm)
    r["gaps"] = [int(x) for x in m.group(1).strip(",").split(",")] if m else [0] * 8
    r["raw"] = num(inp, "raw") / dt
    r["ev_read"] = num(inp, "ev_read") / dt
    r["events"] = num(inp, "events") / dt
    r["ev_ioctl"] = num(inp, "ev_ioctl") / dt
    lat = {}
    for name in ["irq->read", "irq->flip", "irq->cursor"]:
        m = re.search(re.escape(name) + r" n=(\d+) avg_us=(\d+) max_us=(\d+) h\[[^\]]*\]=([\d,]+)", inp)
        if m:
            lat[name] = (int(m.group(1)), int(m.group(2)), int(m.group(3)), [int(x) for x in m.group(4).strip(",").split(",")])
    r["lat"] = lat
    r["pcm_ioctl"] = num(snd, "pcm_ioctls") / dt
    r["pcm_poll"] = num(snd, "pcm_poll") / dt
    r["ctl"] = (num(snd, "ctl_ioctl") + num(snd, "ctl_read")) / dt
    r["xruns"] = num(snd, "xruns")
    r["tty"] = num(snd, "tty_ops") / dt
    r["pty"] = num(snd, "pty_ops") / dt
    m = re.search(r"snd: pcm(.*?) pcm_ioctls", snd)
    r["pcm_detail"] = m.group(1).strip() if m else ""
    m = re.search(r"drm:(.*?) ioctls=", drm)
    r["drm_detail"] = m.group(1).strip() if m else ""
    return r


COLS = ["sys", "ioctl", "drm_ioctl", "flips", "present_us", "cursors", "raw", "ev_read", "pcm_ioctl", "pcm_poll", "tty", "pty", "epoll_wait", "epoll_pwait", "ppoll", "futex"]


def row(i, r):
    lat = " ".join(f"{k}:{v[0]}x{v[1]}us" for k, v in r["lat"].items() if v[0])
    return f"{i:3d} " + " ".join(f"{r[c]:8.1f}" for c in COLS) + f"  x{r['xruns']} {lat}"


def main():
    rs = [parse(b) for b in blocks(sys.argv[1])]
    print("blk " + " ".join(f"{c[:8]:>8}" for c in COLS))
    for i, r in enumerate(rs, 1):
        print(row(i, r))
    for spec in sys.argv[2:]:
        rng, name = spec.split(":", 1)
        a, b = (int(x) for x in rng.split("-"))
        sel = rs[a - 1:b]
        n = len(sel)
        avg = {c: sum(r[c] for r in sel) / n for c in COLS}
        print(f"\n== {name} (blocks {a}-{b}, {n * 5} s)")
        print("   " + "  ".join(f"{c}={avg[c]:.1f}" for c in COLS))
        print("   xruns=", sum(r["xruns"] for r in sel), " present max us=", max(r["present_max_us"] for r in sel))
        gaps = [sum(r["gaps"][k] for r in sel) for k in range(8)]
        print("   flip gaps [<10,<17,<20,<34,<50,<100,<1000,more ms]=", gaps)
        for k in ["irq->read", "irq->flip", "irq->cursor"]:
            ls = [r["lat"][k] for r in sel if k in r["lat"] and r["lat"][k][0]]
            if ls:
                cnt = sum(x[0] for x in ls)
                avg_us = sum(x[0] * x[1] for x in ls) / cnt
                h = [sum(x[3][j] for x in ls) for j in range(7)]
                print(f"   {k}: n={cnt} avg={avg_us:.0f}us max={max(x[2] for x in ls)}us hist[<0.1,<1,<5,<17,<34,<100,more ms]={h}")
        det = {}
        for r in sel:
            for part in (r["drm_detail"] + " " + r["pcm_detail"]).split():
                if "=" in part:
                    k, v = part.split("=")
                    det[k] = det.get(k, 0) + int(v)
        if det:
            print("   per-nr totals:", " ".join(f"{k}={v}" for k, v in sorted(det.items())))


if __name__ == "__main__":
    main()
