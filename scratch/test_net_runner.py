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
        "-netdev", "user,id=net0",
        "-device", "e1000,netdev=net0",
        "-cdrom", r"D:\os\dist\x86_64\kernel.iso",
        "-boot", "d",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-qmp", "tcp:localhost:4493,server,nowait"
    ]

    print("[*] Launching QEMU with Intel 82540EM (e1000) NIC and QMP on port 4493...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(12):
        try:
            sock.connect(("localhost", 4493))
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

    print("[*] Waiting 12 seconds for boot & auto-DHCP dynamic lease acquisition...")
    time.sleep(12)

    # 1. Clear screen and run ifconfig (verifying IP is ALREADY acquired on boot)
    print("[*] Executing 'ifconfig' command to verify auto-acquired DHCP IP...")
    send_key_str(sock, "\n")
    time.sleep(1)
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "ifconfig\n")
    time.sleep(2)

    ppm1 = r"D:\os\scratch\net_auto_dhcp_ifconfig.ppm"
    send_qmp(sock, "screendump", {"filename": ppm1})
    time.sleep(1)

    # 2. Run dns query command for a URL / domain name
    print("[*] Executing 'dns google.com' to test DNS resolution...")
    send_key_str(sock, "dns google.com\n")
    time.sleep(4)

    ppm2 = r"D:\os\scratch\net_dns_resolve.ppm"
    send_qmp(sock, "screendump", {"filename": ppm2})
    time.sleep(1)

    # 3. Run ping with a URL/domain name instead of an IP!
    print("[*] Executing 'ping google.com' (URL/domain ping)...")
    send_key_str(sock, "ping google.com\n")
    time.sleep(6)

    ppm3 = r"D:\os\scratch\net_ping_url.ppm"
    send_qmp(sock, "screendump", {"filename": ppm3})
    time.sleep(1)

    print("[*] Shutting down QEMU...")
    try:
        send_qmp(sock, "quit")
    except Exception:
        pass
    sock.close()
    proc.wait(timeout=5)

    for name in ["net_auto_dhcp_ifconfig", "net_dns_resolve", "net_ping_url"]:
        ppm_file = rf"D:\os\scratch\{name}.ppm"
        png_file = rf"D:\os\scratch\{name}.png"
        if os.path.exists(ppm_file):
            img = Image.open(ppm_file)
            img.save(png_file)
            print(f"[+] Saved screenshot: {png_file}")

    print("[+] URL PING & AUTO-DHCP TEST COMPLETED!")

if __name__ == "__main__":
    main()
