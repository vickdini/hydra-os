"""The pool survives a power loss: QEMU is killed outright while the pool is being written.

Usage: python tools/test_crash.py [--rounds 3] [--smp 4] [--write-secs 20]

Each round boots twice on a throwaway overlay of the pool (scratch/crash.qcow2, created
fresh for the run; never the pool itself):

  1. `zfs selftest` builds and commits its test tree; a file is written and `sync`ed
     (the durability promise: synced data survives); then a shell loop rewrites 64 small
     files and appends to a log as fast as it can. After --write-secs of writing (several
     5 s commits by txgd), QEMU is killed (taskkill /F): the guest gets no warning, as when
     the power cord is pulled.
  2. The next boot must import the pool, and then:
     - `zfs verify`: the selftest tree is intact ([zfstest] ALL PASSED);
     - `zfs fsck /`: no dangling entries, no unreadable directories in the whole pool;
     - the synced file reads back exactly;
     - the rewritten files and the log hold only digits and newlines (no torn or
       garbage blocks; empty files are allowed: a crash between truncate and write).

Rounds reuse the overlay, so later rounds also crash a pool that survived crashes.
Limitation: QEMU writes through the host's page cache (cache=writeback), so every write
QEMU had issued survives the kill; a disk losing its volatile cache is not simulated.
Exit status 0 when every round passed.
"""
import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_IMG = r"C:\Program Files\qemu\qemu-img.exe"
POOL = os.path.join(ROOT, "dist", "x86_64", "hydrapool.qcow2")
DISK = os.path.join(ROOT, "scratch", "crash.qcow2")
PROMPT = "hydra:/bin$"
CHROOT = "linux chroot /ubuntu /usr/bin/bash -c "

WRITE = [
    "zfs selftest",
    CHROOT + "'mkdir -p /tmp/crash; echo durable-OK-$((40+2)) > /tmp/crash/synced; sync; echo SYNCED-$((1+1))'",
    CHROOT + "'i=0; while :; do i=$((i+1)); echo $i > /tmp/crash/f$((i%64)); echo $i >> /tmp/crash/log; "
             "[ $((i%500)) = 0 ] && echo WROTE-$i; done'",
]
CHECK = [
    "zfs verify",
    "zfs fsck /",
    CHROOT + "'cat /tmp/crash/synced; for f in /tmp/crash/f* /tmp/crash/log; do "
             "[ $(tr -d \"0-9[:space:]\" < $f | wc -c) = 0 ] || echo TORN $f; done; "
             "echo LINES $(wc -l < /tmp/crash/log); echo CHECKED-$((1+1))'",
]


def harness(log, cmds, smp, wait):
    """Starts tools/hydra_run.py (shell boot, console login, one command per prompt)."""
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "tools", "hydra_run.py"), "--smp", str(smp), "--disk", DISK,
                             "--log", log, "--wait", str(wait), "--prompt", PROMPT, "--prompt-timeout", "1200",
                             "--until", "KERNEL PANIC|CPU EXCEPTION|CHECKED-2", *cmds],
                            # to a file: an unread pipe fills up and blocks the harness
                            stdout=open(log + ".harness.txt", "w"), stderr=subprocess.STDOUT)


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def qemu_pids(log):
    """QEMUs started for this log (their command line names it)."""
    ps = ("Get-CimInstance Win32_Process -Filter \"name='qemu-system-x86_64.exe'\" | "
          "ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout
    name = os.path.basename(log)
    return [int(l.split("\t")[0]) for l in out.splitlines() if "\t" in l and name in l and l.split("\t")[0].isdigit()]


def kill_qemu(log):
    """Kills the QEMU writing `log` outright and confirms it is gone (the process query
    can miss a process, and a kill can take a moment). True when one was found and ended."""
    found = False
    for _ in range(30):
        pids = qemu_pids(log)
        if not pids:
            if found:
                return True
        else:
            found = True
            for pid in pids:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        time.sleep(1)
    return False


def crash_round(n, smp, write_secs):
    wlog = os.path.join(ROOT, "scratch", f"crash_write_{n}.log")
    clog = os.path.join(ROOT, "scratch", f"crash_check_{n}.log")
    for p in (wlog, clog):
        if os.path.exists(p):
            os.remove(p)

    # 1. Write, then pull the plug
    h = harness(wlog, WRITE, smp, 3600)
    first, killed, wrote = None, False, 0
    deadline = time.time() + 1800
    while time.time() < deadline and h.poll() is None:
        log = read(wlog)
        if re.search(r"KERNEL PANIC|CPU EXCEPTION", log):
            break
        counts = [int(x) for x in re.findall(r"WROTE-(\d+)", log)]
        if counts and first is None:
            first = time.time()
        if first is not None and time.time() - first >= write_secs:
            wrote = max(counts)
            killed = kill_qemu(wlog)
            break
        time.sleep(1)
    try:
        h.wait(timeout=120)
    except subprocess.TimeoutExpired:
        kill_qemu(wlog)
        h.kill()
        print(f"FAIL round {n}: the harness did not end after the kill  (log {wlog})")
        return False
    log = read(wlog)
    before = [("selftest passed", "[zfstest] ALL PASSED" in log),
              ("synced", "SYNCED-2" in log),
              (f"killed while writing (~{wrote} writes)", killed)]
    if not all(ok for _, ok in before):
        print(f"FAIL round {n}: " + ", ".join(f"{w} {'yes' if ok else 'NO'}" for w, ok in before) + f"  (log {wlog})")
        return False

    # 2. Boot again and check
    h = harness(clog, CHECK, smp, 1800)
    h.wait(timeout=3600)
    log = read(clog)
    fsck = re.search(r"\[fsck\] /: (\d+) directories, (\d+) entries, (\d+) dangling, (\d+) unreadable", log)
    lines = re.search(r"LINES (\d+)", log)
    after = [("pool imported, shell up", PROMPT in log),
             ("selftest tree intact", "[zfstest] ALL PASSED" in log),
             ("fsck clean", bool(fsck) and fsck.group(3) == "0" and fsck.group(4) == "0"),
             ("synced file intact", "durable-OK-42" in log),
             ("no torn files", "CHECKED-2" in log and "TORN " not in log.replace("echo TORN", "")),
             ("no kernel crash", not re.search(r"KERNEL PANIC|CPU EXCEPTION", log))]
    ok = all(c for _, c in after)
    detail = f"fsck {fsck.group(1)} dirs/{fsck.group(2)} entries" if fsck else "fsck output missing"
    if lines:
        detail += f", {lines.group(1)} log lines kept over all rounds so far (~{wrote}+ written this round)"
    print(f"{'PASS' if ok else 'FAIL'} round {n}: " + ", ".join(f"{w} {'yes' if c else 'NO'}" for w, c in after)
          + f" ({detail})  (logs {wlog}, {clog})")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--smp", type=int, default=4)
    ap.add_argument("--write-secs", type=float, default=20)
    a = ap.parse_args()
    if os.path.exists(DISK):
        os.remove(DISK)
    subprocess.run([QEMU_IMG, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", POOL, DISK], check=True)
    passed = sum(crash_round(n, a.smp, a.write_secs) for n in range(1, a.rounds + 1))
    print(f"{passed}/{a.rounds} crash rounds passed")
    sys.exit(0 if passed == a.rounds else 1)


if __name__ == "__main__":
    main()
