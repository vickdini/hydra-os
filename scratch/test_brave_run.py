import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "brave_run_test.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45499

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
    for _ in range(15):
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
        time.sleep(0.01)
        resp = b""
        t0 = time.time()
        while time.time() - t0 < 0.05:
            try:
                chunk = mon_s.recv(4096)
                if chunk: resp += chunk
            except: time.sleep(0.005)
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
        else:
            send_monitor(f"sendkey {ch}")
        time.sleep(0.02)

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

try:
    if not init_monitor():
        print("[!] Monitor connect failed")
        sys.exit(1)

    print("[*] Waiting for countdown...")
    mark = wait_for_log("Starting KDE Plasma in 3 seconds", timeout=60)
    if mark < 0:
        print("[!] Timeout waiting for countdown")
        sys.exit(1)

    print("[*] Aborting countdown...")
    send_monitor("sendkey ret")

    mark = wait_for_log("login:", since=mark, timeout=15)
    if mark < 0:
        print("[!] Timeout waiting for login prompt")
        sys.exit(1)

    print("[+] Logging in as hydra...")
    send_keys("hydra\n")
    time.sleep(1)
    send_keys("hydra\n")

    mark = wait_for_log("hydra:/bin$", since=mark, timeout=15)
    if mark < 0:
        print("[!] Timeout waiting for hydra prompt")
        sys.exit(1)

    print("[*] Running brave-browser --version via /bin/sh...")
    send_keys("linux chroot /ubuntu /bin/sh /usr/bin/brave-browser --version\n")
    time.sleep(6)

    print("[*] Running brave-browser test...")
    send_keys("linux chroot /ubuntu /bin/sh /usr/bin/brave-browser --headless --dump-dom https://example.com\n")
    time.sleep(12)

    print("\n--- LOG TAIL ---")
    log_text = read_log()
    print(log_text[-3000:])

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
