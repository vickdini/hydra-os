#!/usr/bin/env python3
"""mbr-message.py IMAGE: puts a tiny legacy (BIOS/CSM) boot program into the first 440 bytes of
a GPT disk image (the protective MBR's code area, which UEFI ignores): started in legacy mode,
it prints that the stick needs UEFI boot, instead of leaving a black screen. The partition
entries (byte 446 on) and the 55 AA signature are not touched."""
import sys

MSG = (b"\r\n  This Hydra stick needs UEFI boot.\r\n\r\n"
       b"  Restart, press F10 and choose the entry that starts with \"UEFI\".\r\n"
       b"  (In F2 setup: Boot > Boot Priority, untick Legacy Boot.)\r\n\x00")

# 16-bit real-mode code, loaded at 0x7C00:
#   cli; xor ax,ax; mov ds,ax; mov ss,ax; mov sp,0x7C00; sti; cld; mov si,msg
#   next: lodsb; test al,al; jz hang; mov bx,7; mov ah,0x0E; int 0x10; jmp next
#   hang: hlt; jmp hang
CODE = bytes([
    0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFB, 0xFC,
    0xBE, 0x20, 0x7C,             # mov si, 0x7C20 (MSG follows the code at offset 32)
    0xAC, 0x84, 0xC0, 0x74, 0x09, 0xBB, 0x07, 0x00, 0xB4, 0x0E, 0xCD, 0x10, 0xEB, 0xF2,
    0xF4, 0xEB, 0xFD,
])
assert len(CODE) == 32
blob = CODE + MSG
assert len(blob) <= 440, len(blob)

with open(sys.argv[1], "r+b") as f:
    mbr = bytearray(f.read(512))
    if mbr[510:512] != b"\x55\xAA" or mbr[450] != 0xEE:
        sys.exit("not a GPT disk with a protective MBR: left alone")
    mbr[0:len(blob)] = blob
    mbr[len(blob):440] = bytes(440 - len(blob))
    f.seek(0)
    f.write(mbr)
print("legacy boot message written (%d bytes)" % len(blob))
