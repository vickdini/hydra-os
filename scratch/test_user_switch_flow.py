import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "user_switch_flow.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45458

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
    if not mon_s:
        return ""
    try:
        mon_s.sendall((cmd + "\n").encode("utf-8"))
        time.sleep(0.1)
        resp = b""
        t0 = time.time()
        while time.time() - t0 < 0.4:
            try:
                chunk = mon_s.recv(4096)
                if chunk:
                    resp += chunk
            except:
                time.sleep(0.02)
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
        else:
            send_monitor(f"sendkey {ch}")
        time.sleep(0.05)

def smooth_move(dx, dy, steps=12):
    step_x = dx // steps
    step_y = dy // steps
    rem_x = dx - step_x * steps
    rem_y = dy - step_y * steps
    for _ in range(steps):
        send_monitor(f"mouse_move {step_x} {step_y}")
        time.sleep(0.03)
    if rem_x or rem_y:
        send_monitor(f"mouse_move {rem_x} {rem_y}")
        time.sleep(0.03)

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
            os.remove(ppm)
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
    print("[+] Session 2 controller is active! Waiting for plasmashell to initialize power actions...")
    mark = wait_for_log("CanSuspendThenHibernate", since=max(0, mark), timeout=60)
    print("[+] plasmashell initialized! Waiting for desktop and panel to render...")

    for i in range(30):
        dump_screen("flow_desktop_poll")
        check_path = os.path.join(ROOT, "scratch", "flow_desktop_poll.png")
        if os.path.exists(check_path):
            with Image.open(check_path) as im:
                p_wall = im.getpixel((100, 100))
                p_panel = im.getpixel((30, 776))
                print(f"[{i*2}s] Wallpaper (100,100)={p_wall}, Panel (30,776)={p_panel}")
                if p_wall != (0, 0, 0) and p_panel != (0, 0, 0):
                    print("[+] Desktop and panel are fully rendered!")
                    time.sleep(3)
                    break
        time.sleep(2)

    dump_screen("flow_plasma_desktop")

    print("[*] Opening Kickoff via click on launcher icon...")
    for _ in range(12):
        send_monitor("mouse_move -120 120")
        time.sleep(0.03)
    send_monitor("mouse_move 30 -24")
    time.sleep(0.3)
    send_monitor("mouse_button 1")
    time.sleep(0.2)
    send_monitor("mouse_button 0")
    time.sleep(3)

    # If not open, also press Alt+F1
    dump_screen("flow_kickoff_opened")
    with Image.open(os.path.join(ROOT, "scratch", "flow_kickoff_opened.png")) as im:
        pix = im.getpixel((100, 500))
        if pix[0] < 200:
            print("[*] Trying Alt+F1 to open Kickoff...")
            send_monitor("sendkey alt-f1")
            time.sleep(3)
            dump_screen("flow_kickoff_opened")

    print("[*] Navigating directly to 'Session v' button (590, 715)...")
    smooth_move(582, -66, steps=12)
    time.sleep(0.5)
    dump_screen("flow_session_hover")

    print("[*] Clicking 'Session v' button...")
    send_monitor("mouse_button 1")
    time.sleep(0.2)
    send_monitor("mouse_button 0")
    time.sleep(2)
    dump_screen("flow_session_clicked")

    print("[*] Testing VT switch to VT 1 via Ctrl+Alt+F1...")
    send_monitor("sendkey ctrl-alt-f1")
    time.sleep(3)
    dump_screen("flow_vt1")

    print("[*] Testing VT switch back to VT 2 via Ctrl+Alt+F2...")
    send_monitor("sendkey ctrl-alt-f2")
    time.sleep(3)
    dump_screen("flow_vt2")

    time.sleep(5)

    print("\n--- RELEVANT LOG MESSAGES ---")
    log_text = read_log()
    for line in log_text.splitlines():
        if any(k in line for k in ["handle_manager", "handle_seat", "handle_session", "activate", "pause_devices", "resume_devices", "DisplayManager", "Switch", "greeter", "session"]):
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
