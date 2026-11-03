import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
LOG_PATH = os.path.join(ROOT, "scratch", "check_dbus_power.log")

class Qmp:
    def __init__(self, proc):
        self.proc = proc

    def cmd(self, execute, arguments=None):
        req = {"execute": execute}
        if arguments:
            req["arguments"] = arguments
        line = json.dumps(req) + "\n"
        self.proc.stdin.write(line.encode("utf-8"))
        self.proc.stdin.flush()
        while True:
            resp_line = self.proc.stdout.readline()
            if not resp_line:
                return {}
            try:
                data = json.loads(resp_line.decode("utf-8", errors="replace"))
            except Exception:
                continue
            if "return" in data or "error" in data:
                return data

    def type_str(self, text, delay=0.08):
        plain = {
            ' ': 'spc', '\n': 'ret', '-': 'minus', '=': 'equal', '[': 'bracket_left', ']': 'bracket_right',
            '\\': 'backslash', ';': 'semicolon', "'": 'apostrophe', ',': 'comma', '.': 'dot', '/': 'slash',
            '`': 'grave_accent', '\t': 'tab',
        }
        shifted = {
            '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8',
            '(': '9', ')': '0', '_': 'minus', '+': 'equal', '{': 'bracket_left', '}': 'bracket_right',
            '|': 'backslash', ':': 'semicolon', '"': 'apostrophe', '<': 'comma', '>': 'dot', '?': 'slash',
            '~': 'grave_accent',
        }
        for ch in text:
            if ch in plain:
                self.cmd("send-key", {"keys": [{"type": "qcode", "data": plain[ch]}]})
            elif ch in shifted:
                self.cmd("send-key", {"keys": [{"type": "qcode", "data": "shift_l"}, {"type": "qcode", "data": shifted[ch]}]})
            elif ch.isalpha() and ch.isupper():
                self.cmd("send-key", {"keys": [{"type": "qcode", "data": "shift_l"}, {"type": "qcode", "data": ch.lower()}]})
            elif ch.isalnum():
                self.cmd("send-key", {"keys": [{"type": "qcode", "data": ch}]})
            time.sleep(delay)

def read_log():
    try:
        with open(LOG_PATH, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def wait_for_log(pattern, since=0, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = read_log()
        pos = text.find(pattern, since)
        if pos != -1:
            return pos + len(pattern)
        time.sleep(0.5)
    return -1

def main():
    if os.path.exists(LOG_PATH):
        try: os.remove(LOG_PATH)
        except: pass

    fw = os.path.join(ROOT, "target", "OVMF-whpx.fd")
    args = [
        QEMU,
        "-accel", "whpx,kernel-irqchip=off", "-bios", fw,
        "-cdrom", os.path.join(ROOT, "dist", "x86_64", "kernel.iso"),
        "-drive", f"file={os.path.join(ROOT, 'dist', 'x86_64', 'hydrapool.qcow2')},format=qcow2,if=ide,index=0,media=disk",
        "-boot", "d", "-m", "4G", "-vga", "std", "-display", "none",
        "-serial", f"file:{LOG_PATH}",
        "-qmp", "stdio",
        "-no-reboot",
    ]

    print("[*] Launching QEMU...")
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    qmp = Qmp(proc)
    qmp.cmd("qmp_capabilities")

    try:
        print("[*] Waiting for login prompt...")
        mark = wait_for_log("login: ", timeout=60)
        if mark < 0:
            print("[!] Timeout waiting for login prompt")
            return 1
        
        # Wait for SDDM greeter connect
        mark = wait_for_log("Message received from greeter: Connect", since=mark, timeout=60)
        print("[+] SDDM greeter connected!")
        time.sleep(2)

        # Log into console as hydra
        print("[*] Logging into console as hydra...")
        qmp.type_str("hydra\n")
        mark = wait_for_log("Password: ", since=mark, timeout=10)
        qmp.type_str("hydra\n")
        mark = wait_for_log("Logged in as 'hydra'", since=mark, timeout=15)
        print("[+] Console logged in!")
        time.sleep(1)

        print("[*] Becoming root...")
        qmp.type_str("sudo -s\n")
        mark = wait_for_log("password for hydra:", since=mark, timeout=10)
        qmp.type_str("hydra\n")
        mark = wait_for_log("Switched to superuser 'root'", since=mark, timeout=15)
        print("[+] Root acquired!")
        time.sleep(1)

        # Run checks
        commands = [
            ("Root CanPowerOff", "linux chroot /ubuntu /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanPowerOff\n"),
            ("Root CanReboot", "linux chroot /ubuntu /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanReboot\n"),
            ("Root CanSuspend", "linux chroot /ubuntu /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanSuspend\n"),
            ("ListSessions", "linux chroot /ubuntu /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.ListSessions\n"),
            ("User CanPowerOff", "linux chroot /ubuntu /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanPowerOff\n"),
            ("User CanReboot", "linux chroot /ubuntu /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanReboot\n"),
        ]

        for desc, cmd in commands:
            print(f"[*] Running: {desc}")
            qmp.type_str(cmd)
            time.sleep(4)

        print("[+] Finished tests. Reading tail of log:")
        print(read_log()[-3000:])
        return 0
    finally:
        qmp.cmd("quit")
        try: proc.wait(timeout=5)
        except: proc.kill()

if __name__ == "__main__":
    main()
