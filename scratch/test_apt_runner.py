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
        pass # suppress logs

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
        "-qmp", "tcp:localhost:4496,server,nowait"
    ]

    print("[*] Launching QEMU with Intel e1000 NIC on port 4496...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(12):
        try:
            sock.connect(("localhost", 4496))
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

    print("[*] Waiting 10 seconds for boot and auto-DHCP...")
    time.sleep(10)

    # 1. Clear screen and check apt help
    print("[*] Running 'apt' help command...")
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "apt\n")
    time.sleep(1.5)

    ppm1 = r"D:\os\scratch\apt_help.ppm"
    png1 = r"D:\os\scratch\apt_help.png"
    send_qmp(sock, "screendump", {"filename": ppm1})
    time.sleep(0.5)
    convert_ppm_to_png(ppm1, png1)

    # 2. Run apt update against our repository
    print("[*] Running 'apt update 10.0.2.2:8000' ...")
    send_key_str(sock, "apt update 10.0.2.2:8000\n")
    time.sleep(4)

    ppm2 = r"D:\os\scratch\apt_update.ppm"
    png2 = r"D:\os\scratch\apt_update.png"
    send_qmp(sock, "screendump", {"filename": ppm2})
    time.sleep(0.5)
    convert_ppm_to_png(ppm2, png2)

    # 3. Run apt list
    print("[*] Running 'apt list'...")
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "apt list\n")
    time.sleep(1.5)

    ppm3 = r"D:\os\scratch\apt_list.ppm"
    png3 = r"D:\os\scratch\apt_list.png"
    send_qmp(sock, "screendump", {"filename": ppm3})
    time.sleep(0.5)
    convert_ppm_to_png(ppm3, png3)

    # 4. Run apt search plasma
    print("[*] Running 'apt search plasma'...")
    send_key_str(sock, "apt search plasma\n")
    time.sleep(1.5)

    ppm4 = r"D:\os\scratch\apt_search.ppm"
    png4 = r"D:\os\scratch\apt_search.png"
    send_qmp(sock, "screendump", {"filename": ppm4})
    time.sleep(0.5)
    convert_ppm_to_png(ppm4, png4)

    # 5. Run apt show busybox-static
    print("[*] Running 'apt show busybox-static'...")
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "apt show busybox-static\n")
    time.sleep(1.5)

    ppm5 = r"D:\os\scratch\apt_show.ppm"
    png5 = r"D:\os\scratch\apt_show.png"
    send_qmp(sock, "screendump", {"filename": ppm5})
    time.sleep(0.5)
    convert_ppm_to_png(ppm5, png5)

    print("[*] Shutting down QEMU test instance...")
    send_qmp(sock, "quit")
    sock.close()
    proc.wait(timeout=5)
    print("[+] All APT tests completed successfully!")

if __name__ == "__main__":
    main()
