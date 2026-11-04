import re
from PIL import Image

font_glyphs = {}
with open('src/video/font.rs', 'r') as f:
    text = f.read()

# Match static FONT_DATA
data_match = re.search(r'static FONT_DATA:\s*\[\[u8;\s*16\];\s*95\]\s*=\s*\[(.*?)\];', text, re.DOTALL)
if data_match:
    raw_array = data_match.group(1)
    glyphs_raw = re.findall(r'\[([0-9a-fA-Fx,\s]+)\]', raw_array)
    for idx, g in enumerate(glyphs_raw):
        ascii_code = 32 + idx
        bytes_val = [int(b.strip(), 16) for b in g.split(',') if b.strip()]
        if len(bytes_val) == 16:
            font_glyphs[chr(ascii_code)] = bytes_val

print(f"Loaded {len(font_glyphs)} font glyphs")

def decode_char(cell_pixels):
    cell_bytes = []
    for r in range(16):
        b = 0
        for c in range(8):
            if cell_pixels[r][c]:
                b |= (1 << (7 - c))
        cell_bytes.append(b)
    
    if all(b == 0 for b in cell_bytes):
        return ' '
    
    for ch, glyph in font_glyphs.items():
        if glyph == cell_bytes:
            return ch
            
    best_ch = '?'
    best_dist = 999
    for ch, glyph in font_glyphs.items():
        dist = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(cell_bytes, glyph))
        if dist < best_dist:
            best_dist = dist
            best_ch = ch
    if best_dist <= 12:
        return best_ch
    return '?'

def decode_screen(path):
    im = Image.open(path)
    w, h = im.size
    cols = w // 8
    rows = h // 16
    lines = []
    for r in range(rows):
        line = []
        for c in range(cols):
            cell = []
            for y in range(16):
                row_px = [im.getpixel((c * 8 + x, r * 16 + y)) != (0, 0, 0) for x in range(8)]
                cell.append(row_px)
            line.append(decode_char(cell))
        s = "".join(line).rstrip()
        if s:
            lines.append(f"{r:2d}: {s}")
    return lines

for img_name in ['vt1_test_list_sessions', 'vt1_test_dbus_names', 'vt1_test_ps', 'vt1_test_switch_to_greeter']:
    print(f"\n=== DECODING {img_name}.png ===")
    for l in decode_screen(f'scratch/{img_name}.png')[-25:]:
        print(l)
