import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "tools_check.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45486

if os.path.exists(LOG_PATH):
    try: os.remove(LOG_PATH)
    except: pass

fw = os.path.join(ROOT, "target", "OVMF-whpx.fd")
args = [
    QEMU,
    "-accel", "whpx,kernel-irqchip=off", "-bios", fw,
    "-cdrom", os.path.join(ROOT, "dist", "x86_64", "kernel.iso"),
    "-drive", f"file={os.path.join(ROOT, 'dist', 'x86_64', 'hydrapool.qcow2')},format=qcow2,if=ide,index=0,media=disk",
    "-netdev", "user,id=net0",
    "-device", "e1000,netdev=net0",
    "-boot", "d", "-m", "4G", "-vga", "std", "-display", "none",
    "-serial", f"file:{LOG_PATH}",
    "-monitor", f"tcp:127.0.0.1:{MONITOR_PORT},server,nowait",
    "-no-reboot",
]

print("[*] Launching QEMU...")
proc = subprocess.Popen(args)
mon_s = None

def init_monitor():
    global mon_s
    for attempt in range(15):
        try:
            mon_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mon_s.connect(("127.0.0.1", MONITOR_PORT))
            mon_s.setblocking(False)
            time.sleep(0.2)
            try: mon_s.recv(4096)
            except: pass
            print("[+] Connected to QEMU monitor!")
            return True
        except Exception:
            time.sleep(1)
    return False

def send_monitor(cmd):
    if not mon_s: return ""
    try:
        mon_s.sendall((cmd + "\n").encode("utf-8"))
        time.sleep(0.1)
        resp = b""
        t0 = time.time()
        while time.time() - t0 < 0.4:
            try:
                chunk = mon_s.recv(4096)
                if chunk: resp += chunk
            except: time.sleep(0.02)
        return resp.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Monitor error: {e}")
        return ""

def send_keys(s):
    for ch in s:
        if ch == '\n':
            send_monitor("sendkey ret")
        elif ch == ' ':
            send_monitor("sendkey spc")
        elif ch == '-':
            send_monitor("sendkey minus")
        elif ch == '_':
            send_monitor("sendkey shift_l-minus")
        elif ch == '/':
            send_monitor("sendkey slash")
        elif ch == '.':
            send_monitor("sendkey dot")
        elif ch == ':':
            send_monitor("sendkey shift_l-semicolon")
        elif ch == '=':
            send_monitor("sendkey equal")
        elif ch == '"':
            send_monitor("sendkey shift_l-apostrophe")
        elif ch == '\'':
            send_monitor("sendkey apostrophe")
        elif ch == '$':
            send_monitor("sendkey shift_l-4")
        elif ch == '|':
            send_monitor("sendkey shift_l-backslash")
        elif ch == '>':
            send_monitor("sendkey shift_l-dot")
        elif ch == '<':
            send_monitor("sendkey shift_l-comma")
        elif ch.isupper():
            send_monitor(f"sendkey shift_l-{ch.lower()}")
        else:
            send_monitor(f"sendkey {ch}")
        time.sleep(0.04)

def read_log():
    try:
        with open(LOG_PATH, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def wait_for_log(pattern, since=0, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = read_log()
        pos = text.find(pattern, since)
        if pos != -1:
            return pos + len(pattern)
        time.sleep(0.5)
    return -1

try:
    if not init_monitor():
        print("[!] Monitor connect failed")
        sys.exit(1)

    print("[*] Waiting for SDDM greeter connect...")
    mark = wait_for_log("Message received from greeter: Connect", timeout=120)
    if mark < 0:
        print("[!] Timeout waiting for SDDM greeter connect")
        sys.exit(1)

    print("[+] SDDM greeter connected! Waiting 8s for QML...")
    time.sleep(8)

    # Switch to VT 1 console
    print("[*] Switching to VT 1 console...")
    send_monitor("sendkey ctrl-alt-f1")
    time.sleep(3)

    # Log in as vick
    print("[*] Logging in as user 'vick'...")
    send_keys("vick\n")
    time.sleep(2)
    send_keys("vick\n")
    time.sleep(3)

    # Check installed tools in chroot
    print("[*] Checking package tools in /ubuntu...")
    send_keys("linux chroot /ubuntu /bin/sh -c 'which apt apt-get curl wget dpkg python3 falkon chromium firefox brave-browser'\n")
    time.sleep(5)

    # Test curl HTTPS support
    print("[*] Testing curl / python HTTPS...")
    send_keys("linux chroot /ubuntu /bin/sh -c 'curl -V; python3 -c \"import ssl; print(ssl.OPENSSL_VERSION)\"'\n")
    time.sleep(5)

    print("\n--- DONE ---")

finally:
    print("[*] Terminating QEMU...")
    try: send_monitor("quit")
    except: pass
    if mon_s:
        try: mon_s.close()
        except: pass
    proc.terminate()
    try: proc.wait(timeout=5)
    except: proc.kill()

