import socket
import json
import time
import subprocess
import os
import sys

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
        "-cdrom", r"D:\os\dist\x86_64\kernel.iso",
        "-drive", r"file=D:\os\dist\x86_64\storage.img,format=raw,if=ide,index=0,media=disk",
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
    for attempt in range(10):
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

    print("[*] Waiting 16 seconds for UEFI boot and auto bare-metal hardware takeover...")
    time.sleep(16)

    # 1. Test: Run Linux Multi-Threaded binary
    print("[*] Executing 'linux run threadtest.elf'...")
    send_key_str(sock, "\n")
    time.sleep(1)
    send_key_str(sock, "clear\n")
    time.sleep(1)
    send_key_str(sock, "linux run threadtest.elf\n")
    time.sleep(6)
    send_qmp(sock, "screendump", {"filename": r"D:\os\scratch\test_thread_exec.ppm"})

    # 2. Test: Check 'linux status' to verify syscall counters
    print("[*] Executing 'linux status'...")
    send_key_str(sock, "linux status\n")
    time.sleep(2)
    send_qmp(sock, "screendump", {"filename": r"D:\os\scratch\test_thread_status.ppm"})

    print("[*] Quitting QEMU...")
    try:
        send_qmp(sock, "quit")
    except Exception:
        pass
    sock.close()
    proc.wait(timeout=5)

    from PIL import Image
    for name in ["test_thread_exec", "test_thread_status"]:
        ppm_path = rf"D:\os\scratch\{name}.ppm"
        png_path = rf"D:\os\scratch\{name}.png"
        if os.path.exists(ppm_path):
            img = Image.open(ppm_path)
            img.save(png_path)
            print(f"[+] Saved screenshot: {png_path}")

    print("[+] Linux compatibility testing completed!")

if __name__ == "__main__":
    main()
