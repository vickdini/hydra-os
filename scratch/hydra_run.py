"""Boot Hydra headless in QEMU, type shell commands, and capture the serial log.

Usage:
    python scratch/hydra_run.py [--mem 4G] [--wait SECONDS] [--until TEXT] [--log PATH] "cmd1" "cmd2" ...

Each command is typed into the Hydra shell followed by Enter. After the last command the
script waits until TEXT appears in the serial log (or SECONDS elapse), prints the log tail
from the first command onwards, and shuts QEMU down.
"""
import argparse
import json
import os
import subprocess
import sys
import time

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
OVMF = r"C:\Program Files\qemu\share\edk2-x86_64-code.fd"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SHIFTED = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8',
    '(': '9', ')': '0', '_': 'minus', '+': 'equal', '{': 'bracket_left', '}': 'bracket_right',
    '|': 'backslash', ':': 'semicolon', '"': 'apostrophe', '<': 'comma', '>': 'dot', '?': 'slash',
    '~': 'grave_accent',
}
PLAIN = {
    ' ': 'spc', '\n': 'ret', '-': 'minus', '=': 'equal', '[': 'bracket_left', ']': 'bracket_right',
    '\\': 'backslash', ';': 'semicolon', "'": 'apostrophe', ',': 'comma', '.': 'dot', '/': 'slash',
    '`': 'grave_accent', '\t': 'tab',
}


class Qmp:
    """QMP over QEMU's stdin/stdout (no network sockets needed)."""

    def __init__(self, proc):
        self.proc = proc
        self.buf = b""
        self._read_reply()  # greeting
        self.cmd("qmp_capabilities")

    def _read_reply(self):
        while True:
            while b"\n" not in self.buf:
                chunk = self.proc.stdout.read1(65536)
                if not chunk:
                    return None
                self.buf += chunk
            line, self.buf = self.buf.split(b"\n", 1)
            msg = json.loads(line)
            if "event" not in msg:
                return msg

    def cmd(self, name, args=None):
        payload = {"execute": name}
        if args:
            payload["arguments"] = args
        self.proc.stdin.write(json.dumps(payload).encode() + b"\r\n")
        self.proc.stdin.flush()
        return self._read_reply()

    def key(self, ch):
        if ch in PLAIN:
            keys = [PLAIN[ch]]
        elif ch in SHIFTED:
            keys = ["shift", SHIFTED[ch]]
        elif ch.isalpha() and ch.isupper():
            keys = ["shift", ch.lower()]
        elif ch.isalnum():
            keys = [ch]
        else:
            return
        self.cmd("send-key", {"keys": [{"type": "qcode", "data": k} for k in keys]})
        time.sleep(0.03)

    def type(self, text):
        for ch in text:
            self.key(ch)


def read_log(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--wait", type=float, default=60)
    ap.add_argument("--until", default=None)
    ap.add_argument("--log", default=os.path.join(ROOT, "scratch", "qemu_run.log"))
    ap.add_argument("--boot-wait", type=float, default=25)
    ap.add_argument("--gap", type=float, default=1.0, help="seconds between commands")
    ap.add_argument("--prompt", default=None, help="wait for one more occurrence of this text before typing each command after the first")
    ap.add_argument("--extra-disk", default=None)
    ap.add_argument("--disk", default=os.path.join(ROOT, "dist", "x86_64", "hydrapool.qcow2"))
    ap.add_argument("commands", nargs="*")
    a = ap.parse_args()

    if os.path.exists(a.log):
        os.remove(a.log)
    args = [
        QEMU,
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF}",
        "-cdrom", os.path.join(ROOT, "dist", "x86_64", "kernel.iso"),
        "-drive", f"file={a.disk},format={'qcow2' if a.disk.endswith('.qcow2') else 'raw'},if=ide,index=0,media=disk",
        "-boot", "d", "-m", a.mem, "-vga", "std", "-display", "none",
        "-serial", f"file:{a.log}",
        "-qmp", "stdio",
        "-no-reboot",
    ]
    if a.extra_disk:
        args += ["-drive", f"file={a.extra_disk},format=raw,if=ide,index=1,media=disk"]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        qmp = Qmp(proc)
        # Wait for the shell prompt (the countdown to bare-metal mode is cancelled by a key)
        deadline = time.time() + a.boot_wait
        while time.time() < deadline and "Transitioning to bare-metal" not in read_log(a.log):
            time.sleep(0.5)
        time.sleep(1.0)
        qmp.type(" ")  # cancel auto takeover countdown
        time.sleep(2.0)
        start = len(read_log(a.log))
        prompts_seen = 0
        for i, c in enumerate(a.commands):
            no_wait = c.startswith("@")  # "@cmd": type without waiting for a prompt
            if no_wait:
                c = c[1:]
            if a.prompt and i > 0 and not no_wait:
                # Wait until the program prints a new prompt after the previous command
                deadline = time.time() + 60
                while time.time() < deadline and read_log(a.log)[start:].count(a.prompt) <= prompts_seen:
                    time.sleep(0.25)
            if a.prompt:
                prompts_seen = read_log(a.log)[start:].count(a.prompt)
            if len(c) == 2 and c[0] == "^" and c[1].isalpha():
                # Ctrl+letter, e.g. ^C, ^Z, ^D
                qmp.cmd("send-key", {"keys": [{"type": "qcode", "data": "ctrl"}, {"type": "qcode", "data": c[1].lower()}]})
            else:
                qmp.type(c + "\n")
            time.sleep(a.gap)
        deadline = time.time() + a.wait
        while time.time() < deadline:
            log = read_log(a.log)
            if a.until and a.until in log[start:]:
                time.sleep(1.0)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.5)
        log = read_log(a.log)
        sys.stdout.write(log[start:])
        sys.stdout.write("\n")
    finally:
        try:
            qmp.cmd("quit")
        except Exception:
            pass
        time.sleep(1)
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    main()
