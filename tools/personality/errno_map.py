"""Errno maps from Hydra's internal (Linux) numbers to FreeBSD's and macOS's (Group 11).

    python3 -I errno_map.py LINUX_ERRNO_H FREEBSD_ERRNO_H XNU_ERRNO_H

Prints a Markdown table: every Linux errno with the FreeBSD and macOS number of the same
name (or of the closest meaning, listed in ALIAS), and the BSD-only errnos that need an
internal number above 512 (design section 2.4). Only reads the headers.
"""
import re
import sys

def parse(path):
    d = {}
    for m in re.finditer(r"#define\s+(E[A-Z0-9]+)\s+(\d+|E[A-Z0-9]+)", open(path, errors="replace").read()):
        name, val = m.group(1), m.group(2)
        if name in ("ELAST", "EDOM_", "ERANGE_"):
            continue
        d[name] = int(val) if val.isdigit() else val
    for k, v in list(d.items()):
        if isinstance(v, str):
            d[k] = d.get(v, None)
    return {k: v for k, v in d.items() if isinstance(v, int)}

# Linux names without a same-named BSD errno: the closest BSD meaning
ALIAS = {"ENOTSUPP": "EOPNOTSUPP", "EDEADLOCK": "EDEADLK", "EWOULDBLOCK": "EAGAIN",
         "ECHRNG": "EINVAL", "EL2NSYNC": "EIO", "EL3HLT": "EIO", "EL3RST": "EIO", "ELNRNG": "EINVAL",
         "EUNATCH": "ENXIO", "ENOCSI": "EIO", "EL2HLT": "EIO", "EBADE": "EINVAL", "EBADR": "EINVAL",
         "EXFULL": "ENOSPC", "ENOANO": "ENOENT", "EBADRQC": "EINVAL", "EBADSLT": "EINVAL",
         "EBFONT": "EINVAL", "ENOSTR": "EINVAL", "ENODATA": "ENOATTR", "ETIME": "ETIMEDOUT",
         "ENOSR": "ENOBUFS", "ENONET": "ENETDOWN", "ENOPKG": "ENOENT", "EADV": "EIO", "ESRMNT": "EIO",
         "ECOMM": "EIO", "EDOTDOT": "EIO", "ENOTUNIQ": "EINVAL", "EBADFD": "EBADF", "EREMCHG": "EIO",
         "ELIBACC": "ENOEXEC", "ELIBBAD": "ENOEXEC", "ELIBSCN": "ENOEXEC", "ELIBMAX": "ENOEXEC",
         "ELIBEXEC": "ENOEXEC", "ERESTART": "EINTR", "ESTRPIPE": "EPIPE", "EUCLEAN": "EIO",
         "ENOTNAM": "EINVAL", "ENAVAIL": "EINVAL", "EISNAM": "EINVAL", "EREMOTEIO": "EIO",
         "ENOMEDIUM": "ENXIO", "EMEDIUMTYPE": "ENXIO", "ENOKEY": "ENOENT", "EKEYEXPIRED": "EACCES",
         "EKEYREVOKED": "EACCES", "EKEYREJECTED": "EACCES", "ERFKILL": "ENETDOWN", "EHWPOISON": "EIO",
         "EMULTIHOP": "EMULTIHOP", "EOWNERDEAD": "EOWNERDEAD", "ENOTRECOVERABLE": "ENOTRECOVERABLE"}

def main():
    lx, fb, mac = (parse(p) for p in sys.argv[1:4])
    print("| Internal (Linux) | Name | FreeBSD | macOS |")
    print("|---:|---|---:|---:|")
    by_num = {}
    for name, n in lx.items():
        by_num.setdefault(n, name)
    for n in sorted(by_num):
        name = by_num[n]
        tgt = name if name in fb else ALIAS.get(name, None)
        f = fb.get(tgt, fb["EINVAL"]) if tgt else fb["EIO"]
        tgtm = name if name in mac else ALIAS.get(name, None)
        m = mac.get(tgtm, mac["EINVAL"]) if tgtm else mac["EIO"]
        note = "" if (tgt == name and tgtm == name) else " (as %s)" % (tgt or "EIO")
        print("| %d | `%s`%s | %d | %d |" % (n, name, note, f, m))
    print()
    only = sorted(set(fb) - set(lx)) 
    onlym = sorted(set(mac) - set(lx))
    print("BSD-only errnos (internal number 512 + the personality's number, returned only by BSD front ends):")
    print()
    print("- FreeBSD: " + ", ".join("`%s` %d" % (k, fb[k]) for k in only if k not in ("ELAST",)))
    print("- macOS: " + ", ".join("`%s` %d" % (k, mac[k]) for k in onlym if k not in ("ELAST",)))

if __name__ == "__main__":
    main()
