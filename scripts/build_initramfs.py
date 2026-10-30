#!/usr/bin/env python3
"""Builds Hydra's Linux initramfs (esp/rootfs.tar) from an Ubuntu Base rootfs tarball.

The archive is a plain GNU tar that the kernel unpacks into its in-memory root
filesystem (tmpfs) at boot, exactly like a Linux initramfs.  Directories that are
not needed at runtime (docs, man pages, locales, dpkg metadata) are dropped to keep
the image small.  Hydra-specific files (e.g. /etc/hostname, /etc/profile.d) are
injected from rootfs/overlay/.
"""
import io
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "rootfs", "ubuntu-base-26.04.1-base-amd64.tar.gz")
OVERLAY = os.path.join(ROOT, "rootfs", "overlay")
DST = os.path.join(ROOT, "esp", "rootfs.tar")

EXCLUDE_PREFIXES = (
    "usr/share/doc/",
    "usr/share/man/",
    "usr/share/info/",
    "usr/share/locale/",
    "usr/share/i18n/",
    "usr/share/zsh/",
    "usr/share/lintian/",
    "usr/share/bash-completion/",
    "usr/share/common-licenses/",
    "var/lib/dpkg/info/",
    "var/cache/",
    "var/lib/apt/lists/",
    "usr/lib/x86_64-linux-gnu/gconv/",
    "usr/lib/x86_64-linux-gnu/perl",
    "usr/share/perl",
)


def norm(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else SRC
    total = 0
    kept = 0
    with tarfile.open(src, "r:gz") as tin, tarfile.open(DST, "w", format=tarfile.GNU_FORMAT) as tout:
        for m in tin:
            name = norm(m.name)
            if not name or any(name.startswith(p) for p in EXCLUDE_PREFIXES):
                continue
            if m.islnk():
                m.linkname = norm(m.linkname)
            m.name = name
            if m.isfile():
                data = tin.extractfile(m)
                tout.addfile(m, data)
                total += m.size
            elif m.isdir() or m.issym() or m.islnk():
                tout.addfile(m)
            else:
                continue  # device nodes / fifos are synthesized by the kernel (/dev)
            kept += 1

        # Hydra overlay files (override anything from the base image)
        if os.path.isdir(OVERLAY):
            for dirpath, _dirs, files in os.walk(OVERLAY):
                for fn in files:
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, OVERLAY).replace(os.sep, "/")
                    with open(full, "rb") as f:
                        payload = f.read()
                    ti = tarfile.TarInfo(rel)
                    ti.size = len(payload)
                    ti.mode = 0o755 if rel.startswith(("usr/bin/", "usr/sbin/")) else 0o644
                    tout.addfile(ti, io.BytesIO(payload))
                    total += len(payload)
                    kept += 1

    print(f"[+] Wrote {DST}: {kept} entries, {total / 1048576:.1f} MiB file data, "
          f"{os.path.getsize(DST) / 1048576:.1f} MiB archive")
    return 0


if __name__ == "__main__":
    sys.exit(main())

