import os
import tarfile
import io
import gzip
import hashlib

def make_ar_header(name, size):
    # Header is 60 bytes:
    # 0..16: filename (padded with space or ending with /)
    # 16..28: mtime (12 bytes)
    # 28..34: uid (6 bytes)
    # 34..40: gid (6 bytes)
    # 40..48: mode (8 bytes octal)
    # 48..58: size (10 bytes decimal)
    # 58..60: trailer `\n
    file_id = (name + "/").ljust(16)
    mtime = "1700000000".ljust(12)
    uid = "0".ljust(6)
    gid = "0".ljust(6)
    mode = "100644".ljust(8)
    size_str = str(size).ljust(10)
    trailer = "`\n"
    header = (file_id + mtime + uid + gid + mode + size_str + trailer).encode('ascii')
    assert len(header) == 60
    return header

def create_deb(out_deb_path, pkg_name, version, arch, files):
    # 1. debian-binary
    deb_binary = b"2.0\n"

    # 2. control.tar.gz
    control_content = f"""Package: {pkg_name}
Version: {version}
Architecture: {arch}
Maintainer: Hydra OS Maintainers <admin@hydra-os.org>
Installed-Size: 120
Section: utils
Priority: optional
Description: {pkg_name} package for Hydra OS
""".encode('utf-8')

    ctl_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=ctl_buf, mode='wb') as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            ti = tarfile.TarInfo(name="./control")
            ti.size = len(control_content)
            ti.mode = 0o644
            tar.addfile(ti, io.BytesIO(control_content))
    control_tar_gz = ctl_buf.getvalue()

    # 3. data.tar.gz
    data_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=data_buf, mode='wb') as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            for filepath, content in files.items():
                ti = tarfile.TarInfo(name=filepath)
                ti.size = len(content)
                ti.mode = 0o755 if "/bin/" in filepath else 0o644
                tar.addfile(ti, io.BytesIO(content))
    data_tar_gz = data_buf.getvalue()

    # Combine into AR format
    ar_data = bytearray(b"!<arch>\n")

    # Member 1: debian-binary
    ar_data.extend(make_ar_header("debian-binary", len(deb_binary)))
    ar_data.extend(deb_binary)
    if len(deb_binary) % 2 != 0:
        ar_data.extend(b"\n")

    # Member 2: control.tar.gz
    ar_data.extend(make_ar_header("control.tar.gz", len(control_tar_gz)))
    ar_data.extend(control_tar_gz)
    if len(control_tar_gz) % 2 != 0:
        ar_data.extend(b"\n")

    # Member 3: data.tar.gz
    ar_data.extend(make_ar_header("data.tar.gz", len(data_tar_gz)))
    ar_data.extend(data_tar_gz)
    if len(data_tar_gz) % 2 != 0:
        ar_data.extend(b"\n")

    os.makedirs(os.path.dirname(out_deb_path), exist_ok=True)
    with open(out_deb_path, "wb") as f:
        f.write(ar_data)

    print(f"[+] Created {out_deb_path} ({len(ar_data)} bytes)")
    return len(ar_data), hashlib.sha256(ar_data).hexdigest()

if __name__ == "__main__":
    repo_base = "scratch/repo/debian"

    # Neofetch
    neofetch_files = {
        "./usr/bin/neofetch": b"#!/bin/sh\necho 'Hydra OS 6.8 (x86_64)'\necho 'Kernel: Hydra Microkernel 0.1.0'\necho 'Uptime: 42s'\n",
        "./etc/neofetch/config.conf": b"# Hydra OS Neofetch Configuration\nprint_info() {\n    info title\n    info underline\n    info 'OS' distro\n}\n",
    }
    neofetch_path = f"{repo_base}/pool/main/n/neofetch/neofetch_7.1.0-4_all.deb"
    n_size, n_sha = create_deb(neofetch_path, "neofetch", "7.1.0-4", "all", neofetch_files)

    # Busybox
    busybox_files = {
        "./bin/busybox": b"\x7fELF\x02\x01\x01\x00HydraBusyboxBinaryPayload",
        "./bin/sh": b"#!/bin/busybox sh\necho 'Hydra Shell Active'\n",
        "./usr/share/doc/busybox/README": b"BusyBox for Hydra OS 6.8\n",
    }
    busybox_path = f"{repo_base}/pool/main/b/busybox/busybox-static_1.36.1-6_amd64.deb"
    b_size, b_sha = create_deb(busybox_path, "busybox-static", "1:1.36.1-6", "amd64", busybox_files)

    # Update Packages file
    packages_content = f"""Package: busybox-static
Version: 1:1.36.1-6
Architecture: amd64
Installed-Size: 2156
Filename: pool/main/b/busybox/busybox-static_1.36.1-6_amd64.deb
Size: {b_size}
SHA256: {b_sha}
Section: utils
Depends: 
Description: Standalone rescue shell and core utilities
 BusyBox combines tiny versions of many common UNIX utilities into a
 single multi-call binary.

Package: neofetch
Version: 7.1.0-4
Architecture: all
Installed-Size: 340
Filename: pool/main/n/neofetch/neofetch_7.1.0-4_all.deb
Size: {n_size}
SHA256: {n_sha}
Section: utils
Depends: bash (>= 4.0)
Description: Fast, highly customizable system info script
 Neofetch displays information about your operating system, software, and hardware
 in an aesthetic and visually pleasing ASCII art format.

Package: plasma-desktop
Version: 6.8.0-1
Architecture: amd64
Installed-Size: 14500
Filename: pool/main/p/plasma-desktop/plasma-desktop_6.8.0-1_amd64.deb
Size: 5894120
SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Section: kde
Depends: kf6-kcoreaddons, libwayland-client0, qt6-base
Description: KDE Plasma Desktop Workspace 6.8
 Tools and session management for the modern KDE Plasma 6.8 desktop,
 providing Wayland compositing, panel, application launcher, and widgets.

Package: wayland-utils
Version: 1.2.0-1
Architecture: amd64
Installed-Size: 120
Filename: pool/main/w/wayland-utils/wayland-utils_1.2.0-1_amd64.deb
Size: 45000
SHA256: 4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5
Section: x11
Depends: libwayland-client0 (>= 1.20)
Description: Wayland diagnostic and inspection utilities
 Contains wayland-info diagnostic tool for inspecting active Wayland displays.
"""
    pkg_file = f"{repo_base}/dists/bookworm/main/binary-amd64/Packages"
    with open(pkg_file, "w", encoding="utf-8") as f:
        f.write(packages_content)

    pkg_gz_file = f"{pkg_file}.gz"
    with gzip.open(pkg_gz_file, "wb") as f:
        f.write(packages_content.encode('utf-8'))

    print(f"[+] Updated {pkg_file} and {pkg_gz_file} ({os.path.getsize(pkg_gz_file)} bytes)")
