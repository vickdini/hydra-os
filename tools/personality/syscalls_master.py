"""Parses a FreeBSD or XNU syscalls.master into (number, audit, type, name, args).

Used by fbsd_syscalls.py and xnu_syscalls.py (Group 11, step 0 of the personality work).
Only reads the file it is given; run with python3 -I.
"""
import re

def parse(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    # Drop comments (';' lines) and preprocessor lines (XNU uses #if/#else).
    lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith(";"):
            continue
        lines.append(ln)
    text = "\n".join(lines)
    out = []
    # An entry starts with a number at the beginning of a line.
    starts = [m.start() for m in re.finditer(r"(?m)^\d+", text)]
    starts.append(len(text))
    for a, b in zip(starts, starts[1:]):
        ent = text[a:b]
        ent = re.sub(r"(?m)^#.*$", "", ent)
        m = re.match(r"(\d+)\s+(\S+)\s+(\S+)\s*(.*)", ent, re.S)
        if not m:
            continue
        num, audit, typ, rest = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        name, args = None, ""
        body = rest
        fm = re.search(r"\{\s*(.*?)\s*\}", body, re.S)
        decl = fm.group(1) if fm else body.split("\n")[0]
        nm = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)", decl, re.S)
        if nm:
            name = nm.group(1)
            args = " ".join(nm.group(2).split())
        else:
            name = decl.split()[0] if decl.split() else "?"
        out.append((num, audit, typ, name, args))
    return out
