import json
import os
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "probe_power.log")
fw = os.path.join(ROOT, "target", "OVMF-whpx.fd")

if os.path.exists(LOG_PATH):
    try: os.remove(LOG_PATH)
    except: pass

proc = subprocess.Popen([
    r"C:\Program Files\qemu\qemu-system-x86_64.exe",
    "-accel", "whpx,kernel-irqchip=off", "-bios", fw,
    "-cdrom", os.path.join(ROOT, "dist", "x86_64", "kernel.iso"),
    "-drive", f"file={os.path.join(ROOT, 'dist', 'x86_64', 'hydrapool.qcow2')},format=qcow2,if=ide,index=0,media=disk",
    "-boot", "d", "-m", "4G", "-vga", "std", "-display", "none",
    "-serial", f"file:{LOG_PATH}",
    "-qmp", "stdio",
    "-no-reboot",
], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

def cmd(execute, arguments=None):
    req = {"execute": execute}
    if arguments: req["arguments"] = arguments
    proc.stdin.write((json.dumps(req) + "\n").encode("utf-8"))
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        if not line: return {}
        try:
            d = json.loads(line.decode("utf-8", errors="replace"))
            if "return" in d or "error" in d: return d
        except: pass

def type_str(s, delay=0.08):
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
    for ch in s:
        if ch in plain:
            cmd("send-key", {"keys": [{"type": "qcode", "data": plain[ch]}]})
        elif ch in shifted:
            cmd("send-key", {"keys": [{"type": "qcode", "data": "shift_l"}, {"type": "qcode", "data": shifted[ch]}]})
        elif ch.isalpha() and ch.isupper():
            cmd("send-key", {"keys": [{"type": "qcode", "data": "shift_l"}, {"type": "qcode", "data": ch.lower()}]})
        elif ch.isalnum():
            cmd("send-key", {"keys": [{"type": "qcode", "data": ch}]})
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

cmd("qmp_capabilities")

try:
    print("[*] Waiting for login prompt...")
    mark = wait_for_log("login: ", timeout=60)
    if mark < 0:
        print("[!] Timeout waiting for login prompt")
        sys.exit(1)

    print("[+] Got login prompt! Logging in as hydra...")
    type_str("hydra\n")
    mark = wait_for_log("Password: ", since=mark, timeout=10)
    type_str("hydra\n")
    mark = wait_for_log("Logged in as 'hydra'", since=mark, timeout=15)
    print("[+] Logged in as hydra!")
    time.sleep(1)

    print("[*] Becoming root (sudo -s)...")
    type_str("sudo -s\n")
    mark = wait_for_log("password for hydra:", since=mark, timeout=10)
    type_str("hydra\n")
    mark = wait_for_log("Switched to superuser 'root'", since=mark, timeout=15)
    print("[+] Root shell ready!")
    time.sleep(1)

    # Now run our test commands!
    print("[*] Starting dbus and hydra-logind...")
    type_str("linux chroot /ubuntu /bin/sh -c 'mkdir -p /run/dbus && dbus-daemon --system && /usr/libexec/hydra-logind -v &'\n")
    time.sleep(3)

    print("[*] Testing CanPowerOff...")
    type_str("linux chroot /ubuntu /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanPowerOff\n")
    time.sleep(3)

    print("[*] Testing CanReboot...")
    type_str("linux chroot /ubuntu /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanReboot\n")
    time.sleep(3)

    print("[*] Testing CanPowerOff as user hydra (uid 1000)...")
    type_str("linux chroot /ubuntu /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanPowerOff\n")
    time.sleep(3)

    print("[*] Testing CanReboot as user hydra (uid 1000)...")
    type_str("linux chroot /ubuntu /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanReboot\n")
    time.sleep(3)

    print("[*] Inspecting Kickoff QML files...")
    type_str("linux chroot /ubuntu /bin/sh -c 'find /usr/share/plasma/plasmoids/org.kde.plasma.kickoff/ -type f'\n")
    time.sleep(3)

    print("[*] Reading LeaveButtons.qml or Footer.qml in kickoff...")
    type_str("linux chroot /ubuntu /bin/sh -c 'cat /usr/share/plasma/plasmoids/org.kde.plasma.kickoff/contents/ui/LeaveButtons.qml 2>/dev/null || cat /usr/share/plasma/plasmoids/org.kde.plasma.kickoff/contents/ui/Footer.qml 2>/dev/null'\n")
    time.sleep(4)

    print("\n--- TEST COMPLETED ---")
    log_text = read_log()
    print(log_text[-3000:])

finally:
    cmd("quit")
    try: proc.wait(timeout=5)
    except: proc.kill()
