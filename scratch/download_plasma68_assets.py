import urllib.request
import zstandard
import tarfile
import os
import io
from PIL import Image

OUT_DIR = r"D:\os\esp\plasma68"
os.makedirs(OUT_DIR, exist_ok=True)

HEADERS = {'User-Agent': 'Mozilla/5.0'}

def stream_package(url):
    print(f"[*] Downloading {url}...")
    req = urllib.request.Request(url, headers=HEADERS)
    resp = urllib.request.urlopen(req)
    dctx = zstandard.ZstdDecompressor()
    stream = dctx.stream_reader(resp)
    return tarfile.open(fileobj=stream, mode='r|')

def extract_wallpapers():
    raw_path = os.path.join(OUT_DIR, "scarlettree_1280x800.raw")
    contents_path = os.path.join(OUT_DIR, "contents_1280x800.raw")
    if os.path.exists(contents_path):
        import shutil
        shutil.copyfile(contents_path, raw_path)
        print(f"  [+] Wallpaper already exists: {raw_path}")
        return

    url = "https://geo.mirror.pkgbuild.com/extra/os/x86_64/plasma-workspace-wallpapers-6.8.1-1-any.pkg.tar.zst"
    tar = stream_package(url)
    target_wallpapers = [
        "usr/share/wallpapers/ScarletTree/contents/images_dark/5120x2880.png"
    ]
    for member in tar:
        if member.name in target_wallpapers and member.isfile():
            print(f"  [+] Extracting wallpaper: {member.name} ({member.size} bytes)")
            f = tar.extractfile(member)
            if f:
                img_data = f.read()
                with Image.open(io.BytesIO(img_data)) as im:
                    im_resized = im.resize((1280, 800), Image.Resampling.LANCZOS)
                    out_png = os.path.join(OUT_DIR, "scarlettree_1280x800.png")
                    im_resized.save(out_png)
                    bgra_data = bytearray()
                    rgb_im = im_resized.convert("RGBA")
                    for y in range(800):
                        for x in range(1280):
                            r, g, b, a = rgb_im.getpixel((x, y))
                            bgra_data.extend([b, g, r, a])
                    with open(raw_path, "wb") as rf:
                        rf.write(bgra_data)
                    print(f"  [+] Saved {raw_path} ({len(bgra_data)} bytes)")
                break

def extract_icons():
    url = "https://geo.mirror.pkgbuild.com/extra/os/x86_64/breeze-icons-6.31.0-1-x86_64.pkg.tar.zst"
    tar = stream_package(url)
    icon_targets = [
        "distributor-logo-plasma.svg",
        "kde.svg",
        "utilities-terminal.svg",
        "utilities-system-monitor.svg",
        "preferences-system.svg",
        "system-file-manager.svg"
    ]
    found = set()
    for member in tar:
        base = os.path.basename(member.name)
        if base in icon_targets and member.isfile():
            if base not in found:
                f = tar.extractfile(member)
                if f:
                    content = f.read()
                    out_svg = os.path.join(OUT_DIR, base)
                    with open(out_svg, "wb") as out_f:
                        out_f.write(content)
                    print(f"  [+] Extracted icon: {base} ({len(content)} bytes)")
                    found.add(base)
                    if len(found) >= len(icon_targets):
                        break

def extract_binaries():
    url = "https://geo.mirror.pkgbuild.com/extra/os/x86_64/plasma-workspace-6.8.1-1-x86_64.pkg.tar.zst"
    tar = stream_package(url)
    bin_targets = ["usr/bin/plasmashell", "usr/bin/krunner"]
    found = set()
    for member in tar:
        if member.name in bin_targets and member.isfile():
            f = tar.extractfile(member)
            if f:
                content = f.read()
                out_bin = os.path.join(OUT_DIR, os.path.basename(member.name) + ".elf")
                with open(out_bin, "wb") as out_f:
                    out_f.write(content)
                print(f"  [+] Extracted genuine binary: {os.path.basename(member.name)}.elf ({len(content)} bytes)")
                found.add(member.name)
                if len(found) >= len(bin_targets):
                    break

if __name__ == "__main__":
    print("[*] Starting KDE Plasma 6.8 Upstream Asset & Binary Downloader...")
    extract_wallpapers()
    extract_icons()
    extract_binaries()
    print("[+] Upstream KDE Plasma 6.8 download complete!")
