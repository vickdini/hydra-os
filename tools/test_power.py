"""Shut down and restart, end to end, under QEMU.

Usage: python tools/test_power.py [--disk scratch/suite.qcow2] [--smp 4] [cases...]

Cases (all by default):
  kde-poweroff  SDDM login, tests/linux/sessionbus_test.c from the console as the desktop
                user, then plasma-shutdown's logoutAndShutdown (what the Shut Down button of
                KDE's logout dialog calls): logind must power the machine off
  kde-reboot    the same with logoutAndReboot
  shell-poweroff, shell-reboot   the Hydra shell's `shutdown` and `reboot`

A case passes when the pool is committed, the kernel announces the power-off or restart
and QEMU exits on its own (the harness runs QEMU with -no-reboot, so a restart ends it too),
and for the KDE cases when the session bus test passed. The disk must be an overlay of
the pool (default scratch/suite.qcow2, created if missing): never the pool itself, which
the user's own VM may be using. Needs esp/bin/sessionbus.elf (gcc -O1 -w, stripped) in the
boot image. Exit status 0 when every case passed. Each case takes 1-5 minutes.
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_IMG = r"C:\Program Files\qemu\qemu-img.exe"
POOL = os.path.join(ROOT, "dist", "x86_64", "hydrapool.qcow2")

# SDDM login (the greeter needs ~100 s; a key first shows its form), then the console
LOGIN = ["~100", "%ret", "~3", "@hydra", "%ret", "~120", "!sendkey ctrl-alt-f1", "~5", "hydra", "hydra", "~3"]
def kde(member):
    # One command: the shutdown request goes out only once the session bus test is done
    # (typed separately, it raced the test and lost its first characters)
    run = ("linux chroot /ubuntu /usr/bin/bash -c 'cat /tmp/sessionbus.elf > /tmp/sb; chmod 755 /tmp/sb; /tmp/sb; "
           f"dbus-send --session --print-reply --dest=org.kde.Shutdown /Shutdown org.kde.Shutdown.{member}'")
    return LOGIN + ["cp /bin/sessionbus.elf /ubuntu/tmp/sessionbus.elf", "~2", run, "~30", "!sendkey ctrl-alt-f2"]


CASES = {
    "kde-poweroff": (["--no-cancel", "--login", "", "--wait", "240"], kde("logoutAndShutdown"), "[power] Powering off."),
    "kde-reboot": (["--no-cancel", "--login", "", "--wait", "240"], kde("logoutAndReboot"), "[power] Restarting."),
    "shell-poweroff": (["--wait", "60"], ["shutdown"], "[power] Powering off."),
    "shell-reboot": (["--wait", "60"], ["reboot"], "[power] Restarting."),
}


def run_case(name, disk, smp):
    opts, cmds, announce = CASES[name]
    log = os.path.join(ROOT, "scratch", f"power_{name}.log")
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "hydra_run.py"), "--smp", str(smp), "--disk", disk,
                          "--log", log, "--until", "KERNEL PANIC|CPU EXCEPTION", *opts, *cmds],
                         capture_output=True, text=True, errors="replace").stdout
    with open(log, "rb") as f:
        serial = f.read().decode("utf-8", errors="replace")
    checks = [("pool committed", "[power] Committing the pool..." in serial),
              (announce, announce in serial),
              ("QEMU exited on its own", "QEMU exited on its own with status 0" in out)]
    if name.startswith("kde"):
        checks.insert(0, ("session bus test", "SESSIONBUS TEST PASSED" in serial))
    ok = all(c for _, c in checks)
    print(f"{'PASS' if ok else 'FAIL'} {name}: " + ", ".join(f"{w} {'yes' if c else 'NO'}" for w, c in checks) + f"  (log {log})")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--disk", default=os.path.join(ROOT, "scratch", "suite.qcow2"))
    ap.add_argument("--smp", type=int, default=4)
    ap.add_argument("cases", nargs="*", default=list(CASES))
    a = ap.parse_args()
    if os.path.abspath(a.disk) == os.path.abspath(POOL):
        sys.exit("test_power: use an overlay of the pool, not the pool itself")
    if not os.path.exists(a.disk):
        subprocess.run([QEMU_IMG, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", POOL, a.disk], check=True)
    failed = [c for c in a.cases if not run_case(c, a.disk, a.smp)]
    print(f"{len(a.cases) - len(failed)}/{len(a.cases)} power cases passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
