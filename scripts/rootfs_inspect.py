import sys, tarfile
src = sys.argv[1]
names = sys.argv[2:]
with tarfile.open(src, "r:gz") as t:
    total = 0
    count = 0
    for m in t:
        total += m.size
        count += 1
        for n in names:
            if n in m.name:
                kind = "L->" + m.linkname if m.issym() else ("H->" + m.linkname if m.islnk() else "")
                print(f"{m.size:>10} {oct(m.mode)} {m.name} {kind}")
    print("entries", count, "bytes", total)

