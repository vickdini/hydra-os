import socket
import json
import time
import subprocess
import os
import sys
import http.server
import threading
from PIL import Image

class QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=r"D:\os\scratch\repo", **kwargs)
    def log_message(self, format, *args):
        pass

def run_http_server():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8000), QuietHTTPHandler)
    server.serve_forever()

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
    time.sleep(0.06)

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
        '0': '0', '1': '1', '2': '2', '3': '3', '4': '4',
        '5': '5', '6': '6', '7': '7', '8': '8', '9': '9',
    }
    for char in text:
        if char in key_map:
            send_key_name(sock, key_map[char])
        elif char.isalpha():
            send_key_name(sock, char.lower())
        time.sleep(0.05)

def convert_ppm_to_png(ppm_path, png_path):
    if os.path.exists(ppm_path):
        img = Image.open(ppm_path)
        img.save(png_path)
        print(f"[+] Saved screenshot: {png_path} ({img.size[0]}x{img.size[1]})")

def main():
    print("[*] Starting local HTTP repository server on port 8000...")
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()

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
        "-qmp", "tcp:localhost:4497,server,nowait"
    ]

    print("[*] Launching QEMU test instance on port 4497...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(12):
        try:
            sock.connect(("localhost", 4497))
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

    print("[*] Waiting 14 seconds for complete bare-metal transition and prompt...")
    time.sleep(14)

    # 1. First test: run 'apt list' immediately before running apt update!
    print("[*] Step 1: Running 'apt list' (pre-seeded package index)...")
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "apt list\n")
    time.sleep(3)

    ppm1 = r"D:\os\scratch\apt_fix_initial_list.ppm"
    png1 = r"D:\os\scratch\apt_fix_initial_list.png"
    send_qmp(sock, "screendump", {"filename": ppm1})
    time.sleep(0.5)
    convert_ppm_to_png(ppm1, png1)

    # 2. Second test: run 'apt update' (defaults to 10.0.2.2:8000)
    print("[*] Step 2: Running 'apt update' ...")
    send_key_str(sock, "apt update\n")
    time.sleep(5)

    ppm2 = r"D:\os\scratch\apt_fix_update.ppm"
    png2 = r"D:\os\scratch\apt_fix_update.png"
    send_qmp(sock, "screendump", {"filename": ppm2})
    time.sleep(0.5)
    convert_ppm_to_png(ppm2, png2)

    # 3. Third test: run 'apt list' again to verify updated index
    print("[*] Step 3: Running 'apt list' after update...")
    send_key_str(sock, "apt list\n")
    time.sleep(3)

    ppm3 = r"D:\os\scratch\apt_fix_list_after.ppm"
    png3 = r"D:\os\scratch\apt_fix_list_after.png"
    send_qmp(sock, "screendump", {"filename": ppm3})
    time.sleep(0.5)
    convert_ppm_to_png(ppm3, png3)

    print("[*] Shutting down QEMU test instance...")
    send_qmp(sock, "quit")
    sock.close()
    proc.wait(timeout=5)
    print("[+] Verification complete!")

if __name__ == "__main__":
    main()
