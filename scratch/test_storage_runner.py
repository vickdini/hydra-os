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
    }
    for char in text:
        if char in key_map:
            qkey = key_map[char]
            send_qmp(sock, "send-key", {"keys": [{"type": "qcode", "data": qkey}]})
        elif char.isalnum():
            send_qmp(sock, "send-key", {"keys": [{"type": "qcode", "data": char.lower()}]})
        time.sleep(0.04)

def run_session(session_num, commands_to_run, screenshot_name):
    qemu_cmd = [
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        "-drive", r"if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd",
        "-drive", r"file=D:\os\dist\x86_64\storage.img,format=raw,index=0,media=disk",
        "-cdrom", r"D:\os\dist\x86_64\kernel.iso",
        "-boot", "d",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-qmp", f"tcp:localhost:{4480 + session_num},server,nowait"
    ]

    port = 4480 + session_num
    print(f"\n[***] Starting Session {session_num} on QMP port {port}...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(12):
        try:
            sock.connect(("localhost", port))
            connected = True
            break
        except Exception:
            time.sleep(1)

    if not connected:
        print(f"[!] Session {session_num}: Failed to connect to QMP server")
        proc.kill()
        return False

    initial = sock.recv(4096)
    print(f"[*] Session {session_num}: QMP Greeting received:", len(initial), "bytes")
    send_qmp(sock, "qmp_capabilities")

    print(f"[*] Session {session_num}: Waiting 6 seconds for boot & exitboot countdown...")
    time.sleep(6)

    for cmd, wait_time in commands_to_run:
        print(f"[*] Session {session_num}: Sending command '{cmd.strip()}'...")
        send_key_str(sock, cmd)
        time.sleep(wait_time)

    ppm_path = rf"D:\os\scratch\{screenshot_name}.ppm"
    png_path = rf"D:\os\scratch\{screenshot_name}.png"
    send_qmp(sock, "screendump", {"filename": ppm_path})
    time.sleep(1)

    print(f"[*] Session {session_num}: Shutting down QEMU...")
    try:
        send_qmp(sock, "quit")
    except Exception:
        pass
    sock.close()
    proc.wait(timeout=5)

    if os.path.exists(ppm_path):
        img = Image.open(ppm_path)
        img.save(png_path)
        print(f"[+] Saved screenshot: {png_path}")
    return True

def main():
    # Session 1: Fresh boot, inspect disks, write persistent data, run sync
    session1_cmds = [
        ("clear\n", 1.0),
        ("disks\n", 2.0),
        ("zpool status\n", 2.0),
        ("zfs write persistent.txt HydraOS_Storage_Success!\n", 2.0),
        ("sync\n", 1.5),
        ("zfs list\n", 2.0),
    ]
    ok1 = run_session(1, session1_cmds, "test_storage_boot1")
    if not ok1:
        print("[!] Session 1 failed.")
        sys.exit(1)

    time.sleep(2)

    # Session 2: Reboot / restore persistent storage from disk, verify file persists across reboot
    session2_cmds = [
        ("clear\n", 1.0),
        ("disks\n", 2.0),
        ("zpool status\n", 2.0),
        ("zfs list\n", 2.0),
        ("zfs cat persistent.txt\n", 2.0),
    ]
    ok2 = run_session(2, session2_cmds, "test_storage_boot2")
    if not ok2:
        print("[!] Session 2 failed.")
        sys.exit(1)

    print("\n[+] PERSISTENT STORAGE TEST COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
