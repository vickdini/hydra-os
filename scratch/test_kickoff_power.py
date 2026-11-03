import json
import os
import subprocess
import time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(ROOT, "scratch", "kickoff_power.log")
QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
PPM_PATH = os.path.join(ROOT, "scratch", "kickoff_opened.ppm")
PNG_PATH = os.path.join(ROOT, "scratch", "kickoff_opened.png")

if os.path.exists(LOG_PATH):
    try: os.remove(LOG_PATH)
    except: pass
if os.path.exists(PPM_PATH):
    try: os.remove(PPM_PATH)
    except: pass
if os.path.exists(PNG_PATH):
    try: os.remove(PNG_PATH)
    except: pass

fw = os.path.join(ROOT, "target", "OVMF-whpx.fd")
args = [
    QEMU,
    "-accel", "whpx,kernel-irqchip=off", "-bios", fw,
    "-cdrom", os.path.join(ROOT, "dist", "x86_64", "kernel.iso"),
    "-drive", f"file={os.path.join(ROOT, 'dist', 'x86_64', 'hydrapool.qcow2')},format=qcow2,if=ide,index=0,media=disk",
    "-boot", "d", "-m", "4G", "-vga", "std", "-display", "none",
    "-serial", f"file:{LOG_PATH}",
    "-qmp", "stdio",
    "-no-reboot",
]

proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

def qmp_cmd(execute, arguments=None):
    req = {"execute": execute}
    if arguments: req["arguments"] = arguments
    proc.stdin.write((json.dumps(req) + "\n").encode("utf-8"))
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        if not line: return {}
        try:
            d = json.loads(line.decode("utf-8", errors="replace"))
            if "return" in d or "error" in d: return d
        except: pass

def type_str(s, delay=0.08):
    plain = {
        ' ': 'spc', '\n': 'ret', '-': 'minus', '=': 'equal', '[': 'bracket_left', ']': 'bracket_right',
        '\\': 'backslash', ';': 'semicolon', "'": 'apostrophe', ',': 'comma', '.': 'dot', '/': 'slash',
        '`': 'grave_accent', '\t': 'tab',
    }
    for ch in s:
        if ch in plain:
            qmp_cmd("send-key", {"keys": [{"type": "qcode", "data": plain[ch]}]})
        elif ch.isalnum():
            qmp_cmd("send-key", {"keys": [{"type": "qcode", "data": ch}]})
        time.sleep(delay)

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

try:
    qmp_cmd("qmp_capabilities")
    print("[*] Waiting for SDDM greeter connect...")
    mark = wait_for_log("Message received from greeter: Connect", timeout=90)
    if mark < 0:
        print("[!] Timeout waiting for SDDM greeter")
        sys.exit(1)

    print("[+] SDDM greeter is ready! Typing password 'hydra'...")
    time.sleep(3)
    type_str("hydra\n")

    print("[*] Waiting for user session to start...")
    mark = wait_for_log("Authentication for user  \"hydra\"  successful", since=mark, timeout=30)
    if mark < 0:
        print("[!] Auth failed or timed out")
    else:
        print("[+] Logged into KDE Plasma!")

    mark = wait_for_log("hydra-logind: session 2 controller is", since=mark, timeout=30)
    print("[+] KWin is controller!")

    print("[*] Waiting 15s for Plasma shell to fully start up and query capabilities...")
    time.sleep(15)

    # Click Kickoff at bottom-left corner:
    # Screen is 1280x800. Kickoff icon is at bottom left, around x=20, y=780.
    # Relative mouse move from center (640, 400):
    # dx = 20 - 640 = -620, dy = 780 - 400 = 380
    print("[*] Opening Kickoff launcher (mouse click at bottom-left)...")
    qmp_cmd("input-send-event", {"events": [
        {"type": "rel", "data": {"axis": "x", "value": -620}},
        {"type": "rel", "data": {"axis": "y", "value": 380}},
    ]})
    time.sleep(0.5)
    qmp_cmd("input-send-event", {"events": [
        {"type": "btn", "data": {"down": True, "button": "left"}},
    ]})
    time.sleep(0.1)
    qmp_cmd("input-send-event", {"events": [
        {"type": "btn", "data": {"down": False, "button": "left"}},
    ]})
    time.sleep(2)

    print("[*] Capturing screendump...")
    qmp_cmd("screendump", {"filename": PPM_PATH})
    time.sleep(1)

    if os.path.exists(PPM_PATH):
        try:
            with Image.open(PPM_PATH) as img:
                img.save(PNG_PATH, format="PNG")
                print(f"[+] Saved screenshot to {PNG_PATH}")
        except Exception as e:
            print(f"[!] Error converting image: {e}")

    print("\n--- HYDRA-LOGIND LOG OUTPUT ---")
    log_text = read_log()
    for line in log_text.splitlines():
        if "hydra-logind" in line or "handle_manager" in line or "can_power" in line or "power_action" in line or "polkit" in line:
            print(line)

finally:
    qmp_cmd("quit")
    try: proc.wait(timeout=5)
    except: proc.kill()

