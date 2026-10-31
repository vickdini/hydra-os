"""Converts a QEMU screendump (binary PPM) to PNG without third-party modules.

Usage: python scratch/ppm2png.py in.ppm out.png [scale]
(the harness takes a screendump with the token "!screendump D:/os/scratch/screen.ppm")
"""
import struct
import sys
import zlib


def read_ppm(path):
    data = open(path, "rb").read()
    fields = []
    i = 0
    while len(fields) < 4:
        while data[i:i + 1].isspace():
            i += 1
        if data[i:i + 1] == b"#":
            while data[i:i + 1] != b"\n":
                i += 1
            continue
        j = i
        while not data[j:j + 1].isspace():
            j += 1
        fields.append(data[i:j])
        i = j
    i += 1
    assert fields[0] == b"P6", "not a binary PPM"
    w, h = int(fields[1]), int(fields[2])
    return w, h, data[i:i + w * h * 3]


def write_png(path, w, h, rgb, scale=1):
    if scale != 1:
        nw, nh = w // scale, h // scale
        out = bytearray()
        for y in range(nh):
            row = rgb[(y * scale) * w * 3:(y * scale + 1) * w * 3]
            for x in range(nw):
                out += row[x * scale * 3:x * scale * 3 + 3]
        w, h, rgb = nw, nh, bytes(out)
    raw = b"".join(b"\x00" + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")
    open(path, "wb").write(png)


if __name__ == "__main__":
    w, h, rgb = read_ppm(sys.argv[1])
    write_png(sys.argv[2], w, h, rgb, int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    print(f"{w}x{h} -> {sys.argv[2]}")
