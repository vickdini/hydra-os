"""Turns the Hydra logo (assets/boot/hydra-logo.png, transparent background) into the
boot splash image the kernel embeds (src/video/hydra_logo.bin).

    py tools/boot-logo/make_logo.py [height]

Format: b"HLG1", width and height (u16 little-endian), then the pixels as raw DEFLATE
(RFC 1951) of RGB rows, already composited on black (the splash background).
"""
import os
import sys
import zlib

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "assets", "boot", "hydra-logo.png")
DST = os.path.join(ROOT, "src", "video", "hydra_logo.bin")

height = int(sys.argv[1]) if len(sys.argv) > 1 else 512
img = Image.open(SRC).convert("RGBA")
bbox = img.getchannel("A").getbbox()  # trim the transparent margin
img = img.crop(bbox)
width = round(img.width * height / img.height)
img = img.resize((width, height), Image.LANCZOS)
black = Image.new("RGBA", img.size, (0, 0, 0, 255))
rgb = Image.alpha_composite(black, img).convert("RGB")
comp = zlib.compressobj(9, zlib.DEFLATED, -15)
data = comp.compress(rgb.tobytes()) + comp.flush()
with open(DST, "wb") as f:
    f.write(b"HLG1" + width.to_bytes(2, "little") + height.to_bytes(2, "little") + data)
print(f"{DST}: {width}x{height}, {len(data)} bytes")
