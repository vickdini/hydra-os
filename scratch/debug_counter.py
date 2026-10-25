import subprocess
import time
import socket
import json
import os

qemu_cmd = [
    r'C:\Program Files\qemu\qemu-system-x86_64.exe',
    '-drive', r'if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd',
    '-cdrom', r'D:\os\dist\x86_64\kernel.iso',
    '-boot', 'd',
    '-m', '512M',
    '-vga', 'std',
    '-display', 'none',
    '-qmp', 'tcp:localhost:4488,server,nowait',
    '-d', 'cpu_reset',
    '-D', r'D:\os\scratch\qemu_debug.log'
]

print('[*] Starting QEMU...')
proc = subprocess.Popen(qemu_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
time.sleep(2)

sock = socket.socket()
sock.connect(('localhost', 4488))
sock.recv(1024)
sock.sendall(json.dumps({'execute': 'qmp_capabilities'}).encode() + b'\r\n')
sock.recv(1024)

print('[*] Waiting 6 seconds for boot...')
time.sleep(6)

def send_key(k):
    payload = json.dumps({'execute': 'send-key', 'arguments': {'keys': [{'type': 'qcode', 'data': k}]}}).encode() + b'\r\n'
    sock.sendall(payload)
    sock.recv(1024)
    time.sleep(0.05)

print('[*] Typing counter.elf...')
for c in 'counter.elf\n':
    send_key('ret' if c == '\n' else ('dot' if c == '.' else c))

time.sleep(3)
payload = json.dumps({'execute': 'screendump', 'arguments': {'filename': r'D:\os\scratch\debug_counter.ppm'}}).encode() + b'\r\n'
sock.sendall(payload)
sock.recv(1024)

sock.sendall(json.dumps({'execute': 'quit'}).encode() + b'\r\n')
sock.close()

stdout, stderr = proc.communicate(timeout=5)
print('STDOUT:', stdout.decode(errors='ignore'))
print('STDERR:', stderr.decode(errors='ignore'))

if os.path.exists(r'D:\os\scratch\qemu_debug.log'):
    with open(r'D:\os\scratch\qemu_debug.log', 'r') as f:
        log = f.read()
    print('DEBUG LOG LEN:', len(log))
    if len(log) > 0:
        print('DEBUG LOG TAIL:', log[-500:])

from PIL import Image
if os.path.exists(r'D:\os\scratch\debug_counter.ppm'):
    img = Image.open(r'D:\os\scratch\debug_counter.ppm')
    img.save(r'D:\os\scratch\debug_counter.png')
    print('[+] Saved debug_counter.png')
