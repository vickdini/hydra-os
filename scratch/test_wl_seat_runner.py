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

def convert_ppm_to_png(ppm_path, png_path):
    try:
        from PIL import Image
        with Image.open(ppm_path) as im:
            im.save(png_path)
            print(f"[+] Successfully converted {ppm_path} -> {png_path} ({im.size})")
    except Exception as e:
        print(f"[!] Warning: Failed to convert PPM with PIL: {e}")

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
        "-serial", r"file:D:\os\scratch\qemu_test.log",
        "-qmp", "tcp:localhost:4498,server,nowait"
    ]

    print("[*] Launching QEMU with QMP on port 4498...")
    proc = subprocess.Popen(qemu_cmd)
    time.sleep(2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for attempt in range(15):
        try:
            sock.connect(("localhost", 4498))
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

    print("[*] Waiting 16 seconds for UEFI boot, then sending enter to cancel countdown...")
    time.sleep(16)
    send_key_str(sock, "\n")
    time.sleep(2)
    send_key_str(sock, "\n")
    time.sleep(2)

    # 1. Inject simulated mouse click onto the button coordinates (538, 344)
    print("[*] Executing 'linux click 538 344'...")
    send_key_str(sock, "linux click 538 344\n")
    time.sleep(1)

    # 2. Execute interactive Wayland seat test binary
    print("[*] Executing 'linux run wlseat.elf'...")
    send_key_str(sock, "linux run wlseat.elf\n")
    time.sleep(2)

    # Capture active UI during display hold
    send_qmp(sock, "screendump", {"filename": r"D:\os\scratch\test_wl_seat_exec.ppm"})
    time.sleep(3)

    # 3. Check 'linux status'
    print("[*] Executing 'linux status'...")
    send_key_str(sock, "linux status\n")
    time.sleep(2)
    send_qmp(sock, "screendump", {"filename": r"D:\os\scratch\test_wl_seat_status.ppm"})

    print("[*] Quitting QEMU...")
    try:
        send_qmp(sock, "quit")
    except Exception:
        pass
    proc.wait(timeout=5)
    sock.close()

    # Convert screenshots
    artifact_dir = r"C:\Users\Vick\.gemini\antigravity-ide\brain\1260e660-5468-4135-9234-e911d5b58dd9"
    convert_ppm_to_png(r"D:\os\scratch\test_wl_seat_exec.ppm", os.path.join(artifact_dir, "test_wl_seat_exec.png"))
    convert_ppm_to_png(r"D:\os\scratch\test_wl_seat_status.ppm", os.path.join(artifact_dir, "test_wl_seat_status.png"))

    # Also generate cropped version of the Wayland window
    try:
        from PIL import Image
        with Image.open(os.path.join(artifact_dir, "test_wl_seat_exec.png")) as im:
            # Crop around window (approx 380 to 900 X, 220 to 600 Y)
            crop = im.crop((380, 220, 900, 600))
            crop.save(os.path.join(artifact_dir, "test_wl_seat_crop.png"))
            print("[+] Saved test_wl_seat_crop.png")
    except Exception as e:
        print("[!] Crop error:", e)

    print("[+] Wayland Interactive Seat & Pointer Routing test run completed!")

if __name__ == "__main__":
    main()
