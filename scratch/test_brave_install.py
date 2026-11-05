import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "brave_install.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45492

if os.path.exists(LOG_PATH):
    try: os.remove(LOG_PATH)
    except: pass

fw = os.path.join(ROOT, "target", "OVMF-whpx.fd")
args = [
    QEMU,
    "-accel", "whpx,kernel-irqchip=off", "-bios", fw,
    "-cdrom", os.path.join(ROOT, "dist", "x86_64", "kernel.iso"),
    "-drive", f"file={os.path.join(ROOT, 'dist', 'x86_64', 'hydrapool.qcow2')},format=qcow2,if=ide,index=0,media=disk",
    "-drive", f"file={os.path.join(ROOT, 'dist', 'x86_64', 'brave-media.img')},format=raw,if=ide,index=1,media=disk",
    "-netdev", "user,id=net0",
    "-device", "e1000,netdev=net0",
    "-boot", "d", "-m", "4G", "-vga", "std", "-display", "none",
    "-serial", f"file:{LOG_PATH}",
    "-monitor", f"tcp:127.0.0.1:{MONITOR_PORT},server,nowait",
    "-no-reboot",
]

print("[*] Launching QEMU with Brave media attached...")
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

def wait_for_log(pattern, since=0, timeout=180):
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

    print("[*] Waiting for package install or SDDM greeter connect (archive extraction may take up to 40s)...")
    mark = wait_for_log("Message received from greeter: Connect", timeout=180)
    if mark < 0:
        print("[!] Timeout waiting for SDDM greeter connect")
        # Check if install succeeded in log
        text = read_log()
        for l in text.splitlines():
            if "Brave" in l or "rootfs" in l or "archive" in l:
                print("  log:", l)
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
    dump_screen("brave_1_desktop")

    # Click Kickoff launcher (bottom-left corner at x=15, y=755 in 1024x768)
    print("[*] Clicking Kickoff application menu button...")
    send_monitor("mouse_move -600 360")
    time.sleep(0.5)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(3)
    dump_screen("brave_2_kickoff_menu")

    # Switch to VT 1 console
    print("[*] Switching to VT 1 console...")
    send_monitor("sendkey ctrl-alt-f1")
    time.sleep(3)
    dump_screen("brave_3_vt1")

    # Log in as vick
    print("[*] Logging in as user 'vick'...")
    send_keys("vick\n")
    time.sleep(2)
    send_keys("vick\n")
    time.sleep(3)

    # Inspect Brave files in /ubuntu
    print("[*] Checking Brave binary and desktop files...")
    send_keys("ls -la /ubuntu/opt/brave.com/brave/brave /ubuntu/usr/bin/brave-browser\n")
    time.sleep(3)
    dump_screen("brave_4_ls")

    # Run brave-browser --version in chroot
    print("[*] Checking brave-browser version in chroot...")
    send_keys("linux chroot /ubuntu /bin/sh /usr/bin/brave-browser --version\n")
    time.sleep(6)
    dump_screen("brave_5_version")

    # Check desktop entry in /ubuntu/usr/share/applications
    print("[*] Checking desktop entry in applications directory...")
    send_keys("cat /ubuntu/usr/share/applications/brave-browser.desktop | grep -E 'Name=|Exec=|Categories='\n")
    time.sleep(3)
    dump_screen("brave_6_desktop_entry")

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

