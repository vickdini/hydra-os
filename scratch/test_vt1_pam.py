import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "vt1_pam.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45474

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
        print("[!] Monitor connect failed")
        sys.exit(1)

    print("[*] Waiting for SDDM greeter connect...")
    mark = wait_for_log("Message received from greeter: Connect", timeout=90)
    if mark < 0:
        print("[!] Timeout waiting for SDDM greeter connect")
        sys.exit(1)

    print("[+] SDDM greeter connected! Waiting 8s for QML...")
    time.sleep(8)

    print("[*] Clicking password box (500, 590) and typing 'hydra'...")
    send_monitor("mouse_move -140 190")
    time.sleep(0.3)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(0.5)
    send_keys("hydra\n")

    mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=mark, timeout=25)
    if mark < 0:
        print("[!] Retrying password...")
        send_monitor("mouse_button 1")
        time.sleep(0.1)
        send_monitor("mouse_button 0")
        time.sleep(0.5)
        send_keys("hydra\n")
        mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=0, timeout=25)

    print("[+] Authenticated! Waiting for Session 2 controller...")
    mark = wait_for_log("hydra-logind: session 2 controller is", since=max(0, mark), timeout=40)
    print("[+] Session 2 controller ready! Waiting for desktop & panel...")

    for i in range(25):
        dump_screen("pam_test_poll")
        check_path = os.path.join(ROOT, "scratch", "pam_test_poll.png")
        if os.path.exists(check_path):
            with Image.open(check_path) as im:
                p_wall = im.getpixel((100, 100))
                p_panel = im.getpixel((30, 776))
                if p_wall != (0, 0, 0) and p_panel != (0, 0, 0):
                    print(f"[+] Desktop ready at step {i}!")
                    break
        time.sleep(2)

    # Now switch to VT 1!
    print("[*] Switching to VT 1 via Ctrl+Alt+F1...")
    send_monitor("sendkey ctrl-alt-f1")
    time.sleep(3)
    dump_screen("pam_1_console_login")

    # Log in as hydra on VT 1
    print("[*] Logging in as 'hydra' on VT 1...")
    send_keys("hydra\n")
    time.sleep(2)
    send_keys("hydra\n")
    time.sleep(3)
    dump_screen("pam_2_shell_logged_in")

    # Run whoami and loginctl
    print("[*] Running whoami & loginctl list-sessions...")
    send_keys("whoami; loginctl list-sessions\n")
    time.sleep(3)
    dump_screen("pam_3_list_sessions")

    # Check D-Bus names
    print("[*] Checking D-Bus services...")
    send_keys("dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -i display\n")
    time.sleep(3)
    dump_screen("pam_4_dbus_display")

    # Check SDDM processes
    print("[*] Checking SDDM processes...")
    send_keys("ps -ef | grep sddm\n")
    time.sleep(3)
    dump_screen("pam_5_ps_sddm")

    # Check if SwitchToGreeter works
    print("[*] Invoking SwitchToGreeter...")
    send_keys("dbus-send --system --print-reply --dest=org.freedesktop.DisplayManager /org/freedesktop/DisplayManager/Seat0 org.freedesktop.DisplayManager.Seat.SwitchToGreeter\n")
    time.sleep(4)
    dump_screen("pam_6_after_switch_greeter")

    # Check active VT and logind session
    send_keys("loginctl list-sessions\n")
    time.sleep(2)
    dump_screen("pam_7_sessions_after")

    # Switch back to VT 2
    print("[*] Switching back to VT 2...")
    send_monitor("sendkey ctrl-alt-f2")
    time.sleep(3)
    dump_screen("pam_8_vt2_desktop")

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

