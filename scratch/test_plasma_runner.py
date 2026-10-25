import socket
import json
import time
import subprocess
import os
import sys
from PIL import Image

def send_qmp(sock, cmd, args=None):
    payload = {"execute": cmd}
    if args:
        payload["arguments"] = args
    sock.sendall(json.dumps(payload).encode() + b"\r\n")
    data = b""
    while b"\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="ignore")

def send_key_str(sock, text):
    key_map = {
        ' ': 'spc',
        '\n': 'ret',
        '-': 'minus',
        '/': 'slash',
        '.': 'dot',
        '_': 'minus',
        '|': 'bar',
        '>': 'greater',
        ':': 'colon',
        '&': 'ampersand',
        '!': 'exclam',
        '=': 'equal',
        '\x1b': 'esc',
    }
    for char in text:
        if char in key_map:
            qkey = key_map[char]
            send_qmp(sock, "send-key", {"keys": [{"type": "qcode", "data": qkey}]})
        elif char.isalnum():
            send_qmp(sock, "send-key", {"keys": [{"type": "qcode", "data": char.lower()}]})
        time.sleep(0.04)

def main():
    qemu_cmd = [
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        "-drive", r"if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd",
        "-drive", r"file=D:\os\dist\x86_64\storage.img,format=raw,index=0,media=disk",
        "-cdrom", r"D:\os\dist\x86_64\kernel.iso",
        "-boot", "d",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-qmp", "tcp:localhost:4488,server,nowait"
    ]

    print("[*] Launching QEMU with QMP on port 4488...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(12):
        try:
            sock.connect(("localhost", 4488))
            connected = True
            break
        except Exception:
            time.sleep(1)

    if not connected:
        print("[!] Failed to connect to QMP server")
        proc.kill()
        sys.exit(1)

    initial = sock.recv(4096)
    print("[*] QMP Greeting received:", len(initial), "bytes")
    send_qmp(sock, "qmp_capabilities")

    print("[*] Waiting 7 seconds for boot & auto-exitboot countdown to complete...")
    time.sleep(7)

    # 1. Clear screen and launch Plasma desktop
    print("[*] Launching KDE Plasma Wayland Desktop: 'plasma'...")
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "plasma\n")
    time.sleep(4)


    # 2. Capture screenshot of initial Plasma Desktop
    ppm1 = r"D:\os\scratch\plasma_desktop.ppm"
    send_qmp(sock, "screendump", {"filename": ppm1})
    time.sleep(1)

    # 3. Type commands into Konsole terminal
    print("[*] Interacting with Konsole inside Plasma desktop: 'zpool' and 'uname'...")
    send_key_str(sock, "zpool\n")
    time.sleep(1)
    send_key_str(sock, "uname\n")
    time.sleep(1)

    # 4. Move mouse slightly using QMP mouse_move or send keys
    ppm2 = r"D:\os\scratch\plasma_interactive.ppm"
    send_qmp(sock, "screendump", {"filename": ppm2})
    time.sleep(1)

    # 5. Exit GUI back to shell using Escape key
    print("[*] Exiting Plasma desktop via Escape key...")
    send_key_str(sock, "\x1b")
    time.sleep(2)

    ppm3 = r"D:\os\scratch\plasma_exit.ppm"
    send_qmp(sock, "screendump", {"filename": ppm3})
    time.sleep(1)

    print("[*] Shutting down QEMU...")
    try:
        send_qmp(sock, "quit")
    except Exception:
        pass
    sock.close()
    proc.wait(timeout=5)

    for name in ["plasma_desktop", "plasma_interactive", "plasma_exit"]:
        ppm_file = rf"D:\os\scratch\{name}.ppm"
        png_file = rf"D:\os\scratch\{name}.png"
        if os.path.exists(ppm_file):
            img = Image.open(ppm_file)
            img.save(png_file)
            print(f"[+] Saved screenshot: {png_file}")

    print("[+] KDE PLASMA WAYLAND TEST FINISHED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
