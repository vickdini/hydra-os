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

def send_key_name(sock, keyname):
    send_qmp(sock, "send-key", {"keys": [{"type": "qcode", "data": keyname}]})
    time.sleep(0.05)

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
            send_key_name(sock, qkey)
        elif char.isalnum():
            send_key_name(sock, char.lower())
        time.sleep(0.04)

def convert_ppm_to_png(ppm_path, png_path):
    if os.path.exists(ppm_path):
        img = Image.open(ppm_path)
        img.save(png_path)
        print(f"[+] Saved screenshot: {png_path} ({img.size[0]}x{img.size[1]})")

def main():
    qemu_cmd = [
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        "-drive", r"if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd",
        "-drive", r"file=D:\os\dist\x86_64\storage.img,format=raw,index=0,media=disk",
        "-netdev", "user,id=net0",
        "-device", "e1000,netdev=net0",
        "-cdrom", r"D:\os\dist\x86_64\kernel.iso",
        "-boot", "d",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-qmp", "tcp:localhost:4494,server,nowait"
    ]

    print("[*] Launching QEMU with QMP on port 4494...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(12):
        try:
            sock.connect(("localhost", 4494))
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

    print("[*] Waiting 10 seconds for boot into shell...")
    time.sleep(10)

    # 1. Clear screen to get a clean shell prompt
    print("[*] Clearing screen for cursor test...")
    send_key_str(sock, "clear\n")
    time.sleep(1)

    ppm1 = r"D:\os\scratch\cursor_prompt.ppm"
    png1 = r"D:\os\scratch\cursor_prompt.png"
    send_qmp(sock, "screendump", {"filename": ppm1})
    time.sleep(0.5)
    convert_ppm_to_png(ppm1, png1)

    # 2. Type some text, then navigate left with arrow keys
    print("[*] Typing 'echo testing cursor' and moving cursor left...")
    send_key_str(sock, "echo testing cursor")
    time.sleep(0.5)

    ppm2 = r"D:\os\scratch\cursor_typed.ppm"
    png2 = r"D:\os\scratch\cursor_typed.png"
    send_qmp(sock, "screendump", {"filename": ppm2})
    time.sleep(0.5)
    convert_ppm_to_png(ppm2, png2)

    # Move left 6 times
    for _ in range(6):
        send_key_name(sock, "left")
        time.sleep(0.08)

    ppm3 = r"D:\os\scratch\cursor_mid_line.ppm"
    png3 = r"D:\os\scratch\cursor_mid_line.png"
    send_qmp(sock, "screendump", {"filename": ppm3})
    time.sleep(0.5)
    convert_ppm_to_png(ppm3, png3)

    # Press Enter to execute
    send_key_str(sock, "\n")
    time.sleep(1)

    # 3. Test cursor command
    print("[*] Testing 'cursor' status command...")
    send_key_str(sock, "cursor\n")
    time.sleep(1)

    # 4. Test switching cursor shape to block
    print("[*] Testing 'cursor block'...")
    send_key_str(sock, "cursor block\n")
    time.sleep(1)
    send_key_str(sock, "block_cursor_active")
    time.sleep(0.5)

    ppm4 = r"D:\os\scratch\cursor_block.ppm"
    png4 = r"D:\os\scratch\cursor_block.png"
    send_qmp(sock, "screendump", {"filename": ppm4})
    time.sleep(0.5)
    convert_ppm_to_png(ppm4, png4)

    send_key_str(sock, "\n")
    time.sleep(0.5)

    print("[*] Shutting down QEMU test instance...")
    send_qmp(sock, "quit")
    sock.close()
    proc.wait(timeout=5)
    print("[+] All cursor tests completed successfully!")

if __name__ == "__main__":
    main()
