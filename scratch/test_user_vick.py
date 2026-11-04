import os
import socket
import subprocess
import sys
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "user_vick.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
MONITOR_PORT = 45480

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

print("[*] Launching QEMU with WHPX...")
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
    dump_screen("vick_1_greeter")

    # Log in as hydra into KDE Plasma on VT 2
    print("[*] Clicking password box (500, 590) and typing 'hydra'...")
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

    print("[+] Hydra authenticated! Waiting for Session 2 controller...")
    mark = wait_for_log("hydra-logind: session 2 controller is", since=max(0, mark), timeout=40)
    print("[+] Session 2 controller ready! Waiting for desktop & panel...")

    for i in range(25):
        dump_screen("vick_poll")
        check_path = os.path.join(ROOT, "scratch", "vick_poll.png")
        if os.path.exists(check_path):
            with Image.open(check_path) as im:
                p_wall = im.getpixel((100, 100))
                p_panel = im.getpixel((30, 776))
                if p_wall != (0, 0, 0) and p_panel != (0, 0, 0):
                    print(f"[+] Desktop ready at step {i}!")
                    break
        time.sleep(2)

    dump_screen("vick_2_hydra_desktop")

    # Now switch to VT 1 console!
    print("[*] Switching to VT 1 via Ctrl+Alt+F1...")
    send_monitor("sendkey ctrl-alt-f1")
    time.sleep(3)
    dump_screen("vick_3_vt1_login")

    # Log into VT 1 as user 'vick' with password 'vick'!
    print("[*] Logging in as user 'vick' (password: vick)...")
    send_keys("vick\n")
    time.sleep(2)
    send_keys("vick\n")
    time.sleep(3)
    dump_screen("vick_4_vick_shell")

    # Run whoami, id, and pwd
    print("[*] Running 'whoami; id; pwd'...")
    send_keys("whoami; id; pwd\n")
    time.sleep(3)
    dump_screen("vick_5_vick_identity")

    # Check /ubuntu/etc/passwd and /ubuntu/etc/shadow for vick
    print("[*] Inspecting user vick entry in /ubuntu/etc/passwd...")
    send_keys("cat /ubuntu/etc/passwd\n")
    time.sleep(3)
    dump_screen("vick_6_passwd")

    # Check multi-session in hydra-logind via loginctl
    print("[*] Running loginctl list-sessions from chroot...")
    send_keys("linux chroot /ubuntu /bin/loginctl list-sessions\n")
    time.sleep(4)
    dump_screen("vick_7_loginctl")

    # Test multi-session Polkit power action evaluation:
    # When vick checks CanPowerOff / PowerOff on login1:
    print("[*] Running hydra-power-check from chroot via /bin/sh...")
    send_keys("linux chroot /ubuntu /bin/sh /usr/bin/hydra-power-check\n")
    time.sleep(5)
    dump_screen("vick_8_can_power")

    # Switch back to VT 2 (Hydra's desktop)
    print("[*] Switching back to VT 2 (Hydra desktop)...")
    send_monitor("sendkey ctrl-alt-f2")
    time.sleep(3)
    dump_screen("vick_9_hydra_desktop_restored")

    print("\n--- RELEVANT LOGIND LOGS ---")
    log_text = read_log()
    for line in log_text.splitlines():
        if any(k in line for k in ["hydra-logind", "vick", "session", "power-off", "polkit"]):
            print("  ", line)

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

