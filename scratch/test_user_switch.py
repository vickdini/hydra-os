import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
LOG_PATH = os.path.join(ROOT, "scratch", "user_switch_test.log")


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

    def key(self, k):
        self.cmd("send-key", {"keys": [{"type": "qcode", "data": k}]})
        time.sleep(0.04)

    def type_str(self, text):
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
            time.sleep(0.04)

    def send_combo(self, keys):
        self.cmd("send-key", {"keys": [{"type": "qcode", "data": k} for k in keys]})
        time.sleep(0.1)

    def screendump(self, path):
        abs_path = os.path.abspath(path).replace("\\", "/")
        return self.cmd("human-monitor-command", {"command-line": f"screendump {abs_path}"})


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
        try:
            os.remove(LOG_PATH)
        except Exception:
            pass

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

    print("[*] Launching QEMU with WHPX...")
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    qmp = Qmp(proc)
    qmp.cmd("qmp_capabilities")

    try:
        print("[*] Step 1: Waiting for SDDM greeter to load and connect...")
        mark = wait_for_log("Message received from greeter: Connect", timeout=120)
        if mark < 0:
            print("[!] Timeout waiting for SDDM greeter connect")
            return 1
        print("[+] SDDM greeter connected! Waiting 2s for UI to settle...")
        time.sleep(2)

        print("[*] Step 2: Typing password 'hydra' into greeter...")
        qmp.type_str("hydra\n")

        print("[*] Waiting for KDE Plasma session 2 to start...")
        mark = wait_for_log("session 2 controller is", since=mark, timeout=60)
        if mark < 0:
            print("[!] Timeout waiting for Plasma session 2 controller")
            # Try typing hydra\n once more in case focus took longer
            print("[*] Retrying hydra\\n...")
            qmp.type_str("hydra\n")
            mark = wait_for_log("session 2 controller is", since=max(0, mark), timeout=30)
            if mark < 0:
                return 1
        print("[+] Session 2 (KDE Plasma) controller active! Letting desktop settle 10s...")
        time.sleep(10)

        # Open Kickoff by pressing Meta (Super_L) or clicking
        print("[*] Opening Kickoff via Super_L...")
        qmp.key("meta_l")
        time.sleep(2)

        # Also click bottom-left just to be sure
        qmp.cmd("input-send-event", {"events": [
            {"type": "rel", "data": {"axis": "x", "value": -600}},
            {"type": "rel", "data": {"axis": "y", "value": 370}},
        ]})
        time.sleep(0.5)
        qmp.cmd("input-send-event", {"events": [
            {"type": "btn", "data": {"down": True, "button": "left"}},
        ]})
        time.sleep(0.1)
        qmp.cmd("input-send-event", {"events": [
            {"type": "btn", "data": {"down": False, "button": "left"}},
        ]})
        time.sleep(2)

        ppm = os.path.join(ROOT, "scratch", "kickoff_test.ppm")
        qmp.screendump(ppm)
        print(f"[+] Saved screendump to {ppm}")

        time.sleep(5)
        print("\n--- RELEVANT LOG MESSAGES ---")
        for line in read_log().splitlines():
            if any(k in line for k in ["handle_manager", "can_power", "power_action", "session 2", "polkit"]):
                print(line)
        return 0

    finally:
        print("[*] Shutting down QEMU...")
        qmp.cmd("quit")
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())