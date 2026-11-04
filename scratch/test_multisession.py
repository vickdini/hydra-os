import json
import os
import socket
import subprocess
import sys
import threading
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "multisession_serial.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45470
SERIAL_PORT = 45471

if os.path.exists(LOG_PATH):
    try: os.remove(LOG_PATH)
    except: pass

log_file = open(LOG_PATH, "wb", buffering=0)

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
serial_buffer = bytearray()
serial_lock = threading.Lock()
running = True

def serial_reader_thread():
    global serial_buffer
    while running:
        try:
            data = ser_s.recv(4096)
            if data:
                log_file.write(data)
                with serial_lock:
                    serial_buffer.extend(data)
            else:
                time.sleep(0.02)
        except (BlockingIOError, socket.error):
            time.sleep(0.02)
        except Exception:
            break

def read_serial_snapshot():
    with serial_lock:
        return bytes(serial_buffer).decode("latin1", errors="replace")

def send_serial(cmd):
    ser_s.sendall(cmd.encode("latin1"))

def send_serial_cmd(cmd, wait_time=2.0):
    start_pos = len(read_serial_snapshot())
    send_serial(cmd + "\n")
    time.sleep(wait_time)
    full = read_serial_snapshot()
    return full[start_pos:]

def init_connections():
    global mon_s, ser_s
    for attempt in range(20):
        try:
            if not mon_s:
                mon_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                mon_s.connect(("127.0.0.1", MONITOR_PORT))
                mon_s.setblocking(False)
            if not ser_s:
                ser_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ser_s.connect(("127.0.0.1", SERIAL_PORT))
                ser_s.setblocking(False)
            print("[+] Connected to QEMU monitor and serial socket!")
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

def wait_for_serial(pattern, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = read_serial_snapshot()
        if pattern in text:
            return True
        time.sleep(0.5)
    return False

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
        print("[!] Could not connect to QEMU")
        sys.exit(1)

    t = threading.Thread(target=serial_reader_thread, daemon=True)
    t.start()

    print("[*] Waiting for SDDM greeter connect...")
    if not wait_for_serial("Message received from greeter: Connect", timeout=90):
        print("[!] Timeout waiting for SDDM greeter")
        sys.exit(1)

    print("[+] SDDM greeter connected! Waiting 8s for QML breeze theme to render...")
    time.sleep(8)
    dump_screen("multi_1_greeter")

    # Log in on serial root console
    print("[*] Logging in on serial root console...")
    send_serial("root\n")
    time.sleep(1.5)
    send_serial("hydra\n")
    time.sleep(2)
    resp = send_serial_cmd("id")
    print(f"[+] Serial login status:\n{resp}")

    # Now log into KDE Plasma on graphical display
    print("[*] Clicking password input box at (500, 590)...")
    send_monitor("mouse_move -140 190")
    time.sleep(0.3)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(0.5)

    print("[*] Typing password 'hydra' and pressing Enter...")
    send_keys("hydra\n")

    print("[*] Waiting for auth success...")
    if not wait_for_serial("Authentication for user  \"hydra\"  successful", timeout=30):
        print("[!] Retrying password entry...")
        send_monitor("mouse_button 1")
        time.sleep(0.1)
        send_monitor("mouse_button 0")
        time.sleep(0.5)
        send_keys("hydra\n")
        if not wait_for_serial("Authentication for user  \"hydra\"  successful", timeout=30):
            print("[!] Auth failed completely!")
            sys.exit(1)

    print("[+] Authentication successful! Waiting for Plasma session 2 controller...")
    wait_for_serial("hydra-logind: session 2 controller is", timeout=40)
    print("[+] Session 2 controller ready! Waiting for desktop & panel...")

    for i in range(25):
        dump_screen("multi_desktop_poll")
        check_path = os.path.join(ROOT, "scratch", "multi_desktop_poll.png")
        if os.path.exists(check_path):
            with Image.open(check_path) as im:
                p_wall = im.getpixel((100, 100))
                p_panel = im.getpixel((30, 776))
                if p_wall != (0, 0, 0) and p_panel != (0, 0, 0):
                    print(f"[+] Desktop ready at step {i}!")
                    break
        time.sleep(2)

    dump_screen("multi_2_plasma_desktop")

    # Check sessions via loginctl on serial
    print("\n--- SESSIONS STATUS ---")
    out = send_serial_cmd("loginctl list-sessions", wait_time=1.5)
    print(out)

    out = send_serial_cmd("loginctl list-seats", wait_time=1.5)
    print(out)

    # Check D-Bus names
    print("\n--- DBUS DISPLAY MANAGER CHECK ---")
    out = send_serial_cmd("dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames", wait_time=2.0)
    print("Has DisplayManager:", "org.freedesktop.DisplayManager" in out)

    # Introspect DisplayManager Seat
    out = send_serial_cmd("dbus-send --system --print-reply --dest=org.freedesktop.DisplayManager /org/freedesktop/DisplayManager/Seat0 org.freedesktop.DBus.Introspectable.Introspect", wait_time=2.5)
    print("Introspect Seat0 snippet:")
    for line in out.splitlines()[:20]:
        print("  ", line)

    # Now test SwitchToGreeter!
    print("\n--- TESTING SwitchToGreeter ---")
    out = send_serial_cmd("dbus-send --system --print-reply --dest=org.freedesktop.DisplayManager /org/freedesktop/DisplayManager/Seat0 org.freedesktop.DisplayManager.Seat.SwitchToGreeter", wait_time=4.0)
    print("SwitchToGreeter reply:\n", out)

    time.sleep(4)
    dump_screen("multi_3_after_switch_to_greeter")

    # Check sessions again
    print("\n--- SESSIONS AFTER SwitchToGreeter ---")
    out = send_serial_cmd("loginctl list-sessions", wait_time=1.5)
    print(out)

    # Check VT state
    out = send_serial_cmd("cat /sys/class/tty/tty0/active", wait_time=1.0)
    print("Active VT:", out.strip())

    # Check SDDM processes
    out = send_serial_cmd("ps aux | grep -E 'sddm|kwin|plasma'", wait_time=2.0)
    print("Active DM/KDE processes:\n", out)

    # If greeter is active, test switching back to Session 2 via loginctl
    print("\n--- TESTING SWITCH BACK TO SESSION 2 ---")
    out = send_serial_cmd("loginctl activate 2", wait_time=3.0)
    print("loginctl activate 2 reply:\n", out)

    time.sleep(3)
    dump_screen("multi_4_back_to_session_2")

    print("\n--- LOGIND MESSAGES ---")
    log_text = read_serial_snapshot()
    for line in log_text.splitlines():
        if "hydra-logind" in line:
            print("  ", line)

finally:
    print("[*] Terminating QEMU...")
    running = False
    try: send_monitor("quit")
    except: pass
    if mon_s:
        try: mon_s.close()
        except: pass
    if ser_s:
        try: ser_s.close()
        except: pass
    log_file.close()
    proc.terminate()
    try: proc.wait(timeout=5)
    except: proc.kill()

