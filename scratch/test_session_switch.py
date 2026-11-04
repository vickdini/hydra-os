import json
import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "switch_test.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45460
SERIAL_PORT = 45461

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
    "-chardev", f"socket,id=ser0,host=127.0.0.1,port={SERIAL_PORT},server=on,wait=off",
    "-serial", "chardev:ser0",
    "-monitor", f"tcp:127.0.0.1:{MONITOR_PORT},server,nowait",
    "-no-reboot",
]

print("[*] Launching QEMU...")
proc = subprocess.Popen(args)

mon_s = None
ser_s = None

def init_connections():
    global mon_s, ser_s
    for attempt in range(15):
        try:
            if not mon_s:
                mon_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                mon_s.connect(("127.0.0.1", MONITOR_PORT))
                mon_s.setblocking(False)
            if not ser_s:
                ser_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ser_s.connect(("127.0.0.1", SERIAL_PORT))
                ser_s.setblocking(False)
            print("[+] Connected to QEMU monitor and serial!")
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
                if chunk: resp += chunk
            except:
                time.sleep(0.02)
        return resp.decode("utf-8", errors="replace")
    except Exception as e:
        return ""

def read_serial_all():
    if not ser_s: return ""
    buf = b""
    while True:
        try:
            chunk = ser_s.recv(4096)
            if not chunk: break
            buf += chunk
        except:
            break
    return buf.decode("utf-8", errors="replace")

def wait_serial(pattern, timeout=60):
    deadline = time.time() + timeout
    accum = ""
    while time.time() < deadline:
        s = read_serial_all()
        if s:
            accum += s
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(s)
            if pattern in accum:
                return accum
        time.sleep(0.3)
    return accum

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
    if not init_connections():
        print("[!] Connection failed")
        sys.exit(1)

    print("[*] Waiting for SDDM greeter connect...")
    out = wait_serial("Message received from greeter: Connect", timeout=90)
    if "Message received from greeter: Connect" not in out:
        print("[!] Timeout waiting for SDDM greeter")
        sys.exit(1)

    print("[+] SDDM greeter connected! Waiting 8s...")
    time.sleep(8)
    dump_screen("switch_test_1_greeter")

    print("[*] Authenticating as hydra...")
    # Click password box at (500, 590) from center (640, 400): dx = -140, dy = 190
    send_monitor("mouse_move -140 190")
    time.sleep(0.2)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(0.5)

    for ch in "hydra\n":
        if ch == '\n': send_monitor("sendkey ret")
        else: send_monitor(f"sendkey {ch}")
        time.sleep(0.05)

    print("[*] Waiting for session 2 controller...")
    out = wait_serial("session 2 controller is", timeout=40)
    if "session 2 controller is" not in out:
        print("[*] Retrying password...")
        for ch in "hydra\n":
            if ch == '\n': send_monitor("sendkey ret")
            else: send_monitor(f"sendkey {ch}")
            time.sleep(0.05)
        out = wait_serial("session 2 controller is", timeout=30)

    print("[+] Session 2 controller active! Waiting for desktop to render...")
    for i in range(30):
        dump_screen("switch_test_poll")
        check_path = os.path.join(ROOT, "scratch", "switch_test_poll.png")
        if os.path.exists(check_path):
            with Image.open(check_path) as im:
                p_wall = im.getpixel((100, 100))
                p_panel = im.getpixel((30, 776))
                if p_wall != (0, 0, 0) and p_panel != (0, 0, 0):
                    print(f"[+] Desktop settled in {i*2}s!")
                    break
        time.sleep(2)

    time.sleep(3)
    dump_screen("switch_test_2_desktop")

    # Now serial has the login prompt: "login: "
    print("[*] Logging in on serial root console...")
    ser_s.sendall(b"root\n")
    time.sleep(1.5)
    ser_s.sendall(b"hydra\n")
    time.sleep(2)
    out = read_serial_all()
    print("Serial prompt after login:\n", out)

    # Run loginctl list-sessions
    print("[*] Querying loginctl list-sessions...")
    ser_s.sendall(b"loginctl list-sessions\n")
    time.sleep(1.5)
    print("List-sessions:\n", read_serial_all())

    # Now let's test SwitchToGreeter over D-Bus!
    print("[*] Testing SwitchToGreeter on org.freedesktop.DisplayManager...")
    ser_s.sendall(b"dbus-send --system --print-reply --dest=org.freedesktop.DisplayManager /org/freedesktop/DisplayManager/Seat0 org.freedesktop.DisplayManager.Seat.SwitchToGreeter\n")
    time.sleep(4)
    print("SwitchToGreeter reply:\n", read_serial_all())

    dump_screen("switch_test_3_after_switch_to_greeter")

    # Also test SwitchTo(1) on logind Seat
    print("[*] Testing Seat.SwitchTo(1) on org.freedesktop.login1...")
    ser_s.sendall(b"dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1/seat/seat0 org.freedesktop.login1.Seat.SwitchTo uint32:1\n")
    time.sleep(3)
    print("SwitchTo(1) reply:\n", read_serial_all())

    dump_screen("switch_test_4_after_switch_to_1")

    # Now test switching back to Session 2!
    print("[*] Testing Session.Activate on Session 2...")
    ser_s.sendall(b"dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1/session/_32 org.freedesktop.login1.Session.Activate\n")
    time.sleep(3)
    print("Activate(2) reply:\n", read_serial_all())

    dump_screen("switch_test_5_back_to_session_2")

    time.sleep(2)

finally:
    print("[*] Terminating QEMU...")
    try: send_monitor("quit")
    except: pass
    if mon_s: mon_s.close()
    if ser_s: ser_s.close()
    proc.terminate()
    try: proc.wait(timeout=5)
    except: proc.kill()

