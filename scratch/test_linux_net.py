import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "linux_net.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45484

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

print("[*] Launching QEMU with e1000 NIC...")
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
        elif ch == '(':
            send_monitor("sendkey shift_l-9")
        elif ch == ')':
            send_monitor("sendkey shift_l-0")
        elif ch == ';':
            send_monitor("sendkey semicolon")
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

def dump_screen(name):
    ppm = os.path.join(ROOT, "scratch", f"{name}.ppm")
    png = os.path.join(ROOT, "scratch", f"{name}.png")
    send_monitor(f"screendump {ppm.replace('\\', '/')}")
    time.sleep(0.5)
    if os.path.exists(ppm):
        try:
            with Image.open(ppm) as im:
                im.save(png, format="PNG")
                print(f"[+] Saved screenshot: {png}")
            os.remove(ppm)
        except Exception as e:
            print(f"[!] Error saving screenshot: {e}")

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

    # Log in as hydra into KDE Plasma on VT 2
    print("[*] Logging into KDE Plasma as 'hydra'...")
    send_monitor("mouse_move -140 190")
    time.sleep(0.3)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(0.5)
    send_keys("hydra\n")

    mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=mark, timeout=30)
    if mark < 0:
        print("[!] Retrying password...")
        send_monitor("mouse_button 1")
        time.sleep(0.1)
        send_monitor("mouse_button 0")
        time.sleep(0.5)
        send_keys("hydra\n")
        mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=0, timeout=30)

    print("[+] Waiting for session 2 controller...")
    mark = wait_for_log("hydra-logind: session 2 controller is", since=max(0, mark), timeout=40)
    print("[+] Desktop active! Waiting 15s...")
    time.sleep(15)
    dump_screen("net_1_desktop")

    # Switch to VT 1 console
    print("[*] Switching to VT 1 console...")
    send_monitor("sendkey ctrl-alt-f1")
    time.sleep(3)
    dump_screen("net_2_vt1_login")

    # Log in as vick
    print("[*] Logging in as user 'vick'...")
    send_keys("vick\n")
    time.sleep(2)
    send_keys("vick\n")
    time.sleep(3)
    dump_screen("net_3_vick_shell")

    # Check network interface in Hydra
    print("[*] Running 'ifconfig' in Hydra shell...")
    send_keys("ifconfig\n")
    time.sleep(3)
    dump_screen("net_4_ifconfig")

    # Check DNS in Hydra
    print("[*] Running 'dns google.com' in Hydra shell...")
    send_keys("dns google.com\n")
    time.sleep(4)
    dump_screen("net_5_hydra_dns")

    # Run hydra-net-check script in chroot
    print("[*] Running /usr/bin/hydra-net-check in chroot...")
    send_keys("linux chroot /ubuntu /bin/sh /usr/bin/hydra-net-check\n")
    time.sleep(15)
    dump_screen("net_6_chroot_net_check")

    # Switch back to desktop on VT 2
    send_monitor("sendkey ctrl-alt-f2")
    time.sleep(3)
    dump_screen("net_10_desktop_after")

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
