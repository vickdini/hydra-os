import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "kde_shutdown.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45456

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
    "-monitor", f"tcp:127.0.0.1:{MONITOR_PORT},server,nowait",
    "-no-reboot",
]

print("[*] Launching QEMU...")
proc = subprocess.Popen(args)

mon_s = None

def init_monitor():
    global mon_s
    for attempt in range(10):
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
    try:
        while True:
            data = mon_s.recv(4096)
            if not data: break
    except: pass
    mon_s.sendall((cmd + "\n").encode())
    time.sleep(0.15)
    resp = b""
    t0 = time.time()
    while time.time() - t0 < 0.4:
        try:
            chunk = mon_s.recv(4096)
            if chunk: resp += chunk
        except:
            time.sleep(0.02)
    return resp.decode("utf-8", errors="ignore")

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
        else:
            send_monitor(f"sendkey {ch}")
        time.sleep(0.05)

def read_log():
    try:
        with open(LOG_PATH, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def wait_for_log(pattern, since=0, timeout=90):
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
        except Exception as e:
            print(f"[!] Error saving screenshot: {e}")

try:
    if not init_monitor():
        print("[!] Failed to connect to monitor")
        sys.exit(1)

    print("[*] Waiting for SDDM greeter connect...")
    mark = wait_for_log("Message received from greeter: Connect", timeout=90)
    if mark < 0:
        print("[!] Timeout waiting for SDDM greeter connect")
        sys.exit(1)

    print("[+] SDDM greeter connected! Waiting 8s for QML breeze theme to fully render...")
    time.sleep(8)
    dump_screen("sddm_greeter_ready")

    print("[*] Clicking password input box at (500, 590)...")
    send_monitor("mouse_move -140 190")
    time.sleep(0.3)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(0.5)

    print("[*] Typing password 'hydra' and pressing Enter...")
    send_keys("hydra\n")

    print("[*] Waiting for authentication success...")
    mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=mark, timeout=25)
    if mark < 0:
        print("[!] Auth timed out, trying click + hydra\\n once more...")
        dump_screen("sddm_auth_failed")
        send_monitor("mouse_move 0 0")
        send_monitor("mouse_button 1")
        time.sleep(0.1)
        send_monitor("mouse_button 0")
        time.sleep(0.5)
        send_keys("hydra\n")
        mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=max(0, mark), timeout=25)
        if mark < 0:
            print("[!] Auth failed completely!")
            sys.exit(1)

    print("[+] Auth successful! Waiting for Plasma session 2 to become active...")
    mark = wait_for_log("hydra-logind: session 2 controller is", since=max(0, mark), timeout=40)
    print("[+] Session 2 controller is active! Letting Plasma settle 12s...")
    time.sleep(12)

    dump_screen("plasma_desktop_settled")

    print("[*] Clicking Kickoff launcher (bottom-left at 20, 780)...")
    # Move mouse relative from center (640, 400) to (20, 780): dx = -620, dy = 380
    send_monitor("mouse_move -620 380")
    time.sleep(0.3)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(2)

    dump_screen("plasma_kickoff_clicked")

    # In Kickoff, let's see what is shown!
    # Wait another 5s to capture any D-Bus queries from Kickoff
    time.sleep(5)

    print("\n--- HYDRA-LOGIND D-BUS CALLS ---")
    log_text = read_log()
    for line in log_text.splitlines():
        if any(k in line for k in ["handle_manager", "can_power", "power_action", "polkit"]):
            print(line)

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
