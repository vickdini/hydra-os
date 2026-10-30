import subprocess
import time
import socket
import os
import shutil

MONITOR_PORT = 45455
SERIAL_LOG = r"D:\os\scratch\qemu_plasma68.log"
ARTIFACT_DIR = r"C:\Users\Vick\.gemini\antigravity-ide\brain\1260e660-5468-4135-9234-e911d5b58dd9"
SCREENSHOT_CLEAN = os.path.join(ARTIFACT_DIR, "plasma68_authentic_desktop.png")
SCREENSHOT_KICKOFF = os.path.join(ARTIFACT_DIR, "plasma68_authentic_kickoff.png")
SCREENSHOT_CLI = os.path.join(ARTIFACT_DIR, "plasma68_authentic_cli.png")

if os.path.exists(SERIAL_LOG):
    os.remove(SERIAL_LOG)

qemu_cmd = [
    r"C:\Program Files\qemu\qemu-system-x86_64.exe",
    "-drive", r"if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd",
    "-drive", r"file=D:\os\dist\x86_64\storage.img,format=raw,if=ide,index=0,media=disk",
    "-cdrom", r"D:\os\dist\x86_64\kernel.iso",
    "-boot", "d",
    "-m", "512M",
    "-vga", "std",
    "-display", "none",
    "-monitor", f"tcp:127.0.0.1:{MONITOR_PORT},server,nowait",
    "-serial", f"file:{SERIAL_LOG}"
]

print("[*] Launching QEMU for authentic KDE Plasma 6.8 test...")
proc = subprocess.Popen(qemu_cmd)

mon_s = None

def init_monitor():
    global mon_s
    mon_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mon_s.connect(("127.0.0.1", MONITOR_PORT))
    mon_s.setblocking(False)
    time.sleep(0.2)
    try:
        mon_s.recv(4096)
    except Exception:
        pass

def send_monitor(cmd):
    try:
        while True:
            data = mon_s.recv(4096)
            if not data:
                break
    except Exception:
        pass

    mon_s.sendall((cmd + "\n").encode())
    time.sleep(0.15)
    resp = b""
    t0 = time.time()
    while time.time() - t0 < 0.4:
        try:
            chunk = mon_s.recv(4096)
            if chunk:
                resp += chunk
        except Exception:
            time.sleep(0.02)
    return resp.decode("utf-8", errors="ignore")

def send_keys(keys_str):
    for ch in keys_str:
        if ch == '\n':
            send_monitor("sendkey ret")
        elif ch == ' ':
            send_monitor("sendkey spc")
        elif ch == '-':
            send_monitor("sendkey minus")
        elif ch == '/':
            send_monitor("sendkey slash")
        elif ch == '.':
            send_monitor("sendkey dot")
        elif ch == '_':
            send_monitor("sendkey shift-minus")
        elif ch == '\x1b':
            send_monitor("sendkey esc")
        else:
            send_monitor(f"sendkey {ch}")
        time.sleep(0.04)

try:
    print("[*] Waiting 10s for boot...")
    time.sleep(10)
    init_monitor()

    # Cancel auto-takeover proactively by sending space (Enter proceeds early, space cancels)
    print("[*] Proactively sending Space to cancel auto-takeover countdown...")
    for _ in range(5):
        send_keys(" ")
        time.sleep(1)

    time.sleep(2)

    # Launch authentic KDE Plasma 6.8 desktop
    print("[*] Launching authentic KDE Plasma 6.8 desktop shell via 'plasma'...")
    send_keys("plasma\n")
    time.sleep(4)

    # Capture pristine KDE Plasma 6.8 desktop
    print("[*] Capturing pristine KDE Plasma 6.8 desktop screenshot...")
    resp = send_monitor(f"screendump {SCREENSHOT_CLEAN}")
    print("  Monitor screendump clean resp:", resp.strip())
    time.sleep(1)

    # Toggle Kickoff Application Menu: Move mouse to (35, 765) from (640, 400)
    print("[*] Moving mouse to Kickoff button and clicking...")
    send_monitor("mouse_move -605 365")
    time.sleep(0.5)
    send_monitor("mouse_button 1")
    time.sleep(0.1)
    send_monitor("mouse_button 0")
    time.sleep(1)

    # Capture Kickoff menu screenshot
    print("[*] Capturing KDE Plasma 6.8 Kickoff menu screenshot...")
    resp = send_monitor(f"screendump {SCREENSHOT_KICKOFF}")
    print("  Monitor screendump kickoff resp:", resp.strip())
    time.sleep(1)

    # Exit back to CLI using Escape
    print("[*] Pressing Escape to exit Plasma desktop and return to CLI...")
    send_keys("\x1b")
    time.sleep(2)

    # Run genuine plasmashell binary in Linux compat layer!
    print("[*] Running genuine KDE Plasma binary: 'linux run plasmashell.elf'...")
    send_keys("linux run plasmashell.elf\n")
    time.sleep(4)

    print("[*] Capturing CLI status screenshot...")
    resp = send_monitor(f"screendump {SCREENSHOT_CLI}")
    print("  Monitor screendump CLI resp:", resp.strip())
    time.sleep(1)

finally:
    print("[*] Terminating QEMU...")
    try:
        send_monitor("quit")
    except Exception:
        pass
    if mon_s:
        try:
            mon_s.close()
        except Exception:
            pass
    proc.terminate()
    proc.wait()

# Convert raw PPM to real PNG
from PIL import Image
for shot in [SCREENSHOT_CLEAN, SCREENSHOT_KICKOFF, SCREENSHOT_CLI]:
    if os.path.exists(shot):
        try:
            with Image.open(shot) as im:
                im.save(shot, format="PNG")
                print(f"[+] Converted {shot} to PNG ({im.size})")
        except Exception as e:
            print(f"[!] Error converting {shot}: {e}")

print("[+] KDE Plasma 6.8 authentic integration test finished!")
