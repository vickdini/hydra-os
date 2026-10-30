import subprocess
import os
from PIL import Image

OUT_DIR = r"D:\os\esp\plasma68"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not os.path.exists(EDGE):
    EDGE = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"

svgs = [f for f in os.listdir(OUT_DIR) if f.endswith(".svg")]
print(f"[*] Found {len(svgs)} SVG icons to rasterize: {svgs}")

for svg_name in svgs:
    svg_path = os.path.join(OUT_DIR, svg_name)
    base_name = os.path.splitext(svg_name)[0]
    out_png = os.path.join(OUT_DIR, f"{base_name}_32x32.png")
    out_raw = os.path.join(OUT_DIR, f"{base_name}_32x32.raw")

    # Render at 128x128 then downsample to 32x32 with anti-aliasing
    html_content = f"""<!DOCTYPE html>
<html>
<head><style>body {{ margin:0; padding:0; background:transparent; overflow:hidden; }}</style></head>
<body><img src="{svg_path.replace(os.sep, '/')}" width="128" height="128" /></body>
</html>"""
    html_path = os.path.join(OUT_DIR, "render_tmp.html")
    with open(html_path, "w", encoding="utf-8") as hf:
        hf.write(html_content)

    tmp_shot = os.path.join(OUT_DIR, "tmp_shot.png")
    cmd = [
        EDGE,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        "--default-background-color=00000000",
        "--window-size=128,128",
        f"--screenshot={tmp_shot}",
        f"file:///{html_path.replace(os.sep, '/')}"
    ]
    subprocess.run(cmd, check=True)

    if os.path.exists(tmp_shot):
        with Image.open(tmp_shot) as im:
            # Crop to 128x128
            im_cropped = im.crop((0, 0, 128, 128))
            im_resized = im_cropped.resize((32, 32), Image.Resampling.LANCZOS)
            im_resized.save(out_png)

            # Convert to 32x32 BGRA raw buffer
            bgra_data = bytearray()
            rgba = im_resized.convert("RGBA")
            for y in range(32):
                for x in range(32):
                    r, g, b, a = rgba.getpixel((x, y))
                    bgra_data.extend([b, g, r, a])
            with open(out_raw, "wb") as rf:
                rf.write(bgra_data)
            print(f"  [+] Generated Breeze icon: {out_png} and {out_raw} (4096 bytes)")

if os.path.exists(os.path.join(OUT_DIR, "render_tmp.html")):
    os.remove(os.path.join(OUT_DIR, "render_tmp.html"))
if os.path.exists(os.path.join(OUT_DIR, "tmp_shot.png")):
    os.remove(os.path.join(OUT_DIR, "tmp_shot.png"))

print("[+] All Breeze icons successfully rasterized!")
