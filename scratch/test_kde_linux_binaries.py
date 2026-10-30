import subprocess
import time
import socket
import os

MONITOR_PORT = 45456
SERIAL_LOG = r"D:\os\scratch\qemu_kde_linux.log"
SHOT_PLASMASHELL = r"D:\os\scratch\shot_plasmashell_elf.ppm"
SHOT_KRUNNER = r"D:\os\scratch\shot_krunner_elf.ppm"
SHOT_STATUS = r"D:\os\scratch\shot_linux_status.ppm"

for p in [SERIAL_LOG, SHOT_PLASMASHELL, SHOT_KRUNNER, SHOT_STATUS]:
    if os.path.exists(p):
        try:
            os.remove(p)
        except Exception:
            pass

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

print("[*] Launching QEMU for KDE Plasma 6.8 Linux ELF binary execution test...")
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
    print("[*] Waiting 12s for UEFI boot + ZFS sync...")
    time.sleep(12)
    init_monitor()

    # Wait until serial log shows the shell banner
    for _ in range(40):
        if os.path.exists(SERIAL_LOG):
            with open(SERIAL_LOG, "rb") as f:
                txt = f.read().decode("utf-8", errors="ignore")
            if "Initiating ExitBootServices" in txt:
                break
        time.sleep(0.5)

    # Wait 6 seconds for bare-metal hardware takeover and DHCP to finish cleanly
    print("[*] Waiting 6s for bare-metal takeover to complete...")
    time.sleep(6)

    # 1. Run genuine plasmashell.elf directly
    print("[*] Running 'linux run plasmashell.elf'...")
    send_keys("linux run plasmashell.elf\n")
    time.sleep(5)

    print("[*] Capturing plasmashell.elf Wayland desktop screenshot...")
    send_monitor(f"screendump {SHOT_PLASMASHELL}")
    time.sleep(1)

    # 2. Run genuine krunner.elf directly
    print("[*] Running 'linux run krunner.elf'...")
    send_keys("linux run krunner.elf\n")
    time.sleep(4)

    print("[*] Capturing krunner.elf Wayland overlay screenshot...")
    send_monitor(f"screendump {SHOT_KRUNNER}")
    time.sleep(1)

    # 3. Check linux status
    print("[*] Running 'linux status'...")
    send_keys("linux status\n")
    time.sleep(2)
    send_monitor(f"screendump {SHOT_STATUS}")
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

from PIL import Image
for ppm in [SHOT_PLASMASHELL, SHOT_KRUNNER, SHOT_STATUS]:
    if os.path.exists(ppm):
        png = ppm.replace(".ppm", ".png")
        with Image.open(ppm) as im:
            im.save(png, format="PNG")
            print(f"[+] Saved {png} ({im.size})")

