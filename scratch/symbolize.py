"""Maps kernel watchdog addresses to functions using the linker map.

Build the map with:
  cargo rustc --release --target x86_64-unknown-uefi -- -C link-arg=/MAP:D:/os/target/hydra.map
Then:
  python scratch/symbolize.py scratch/qemu_run.log
prints a histogram of the functions the watchdog caught the kernel in.
"""
import bisect
import collections
import re
import sys

MAP = r"D:\os\target\hydra.map"
ANCHOR = "hydra_syscall_dispatcher"


def load_map(path):
    syms = []
    anchor = None
    pat = re.compile(r"^\s*0001:[0-9a-f]+\s+(\S+)\s+([0-9a-f]{16})\s")
    for line in open(path, encoding="latin1"):
        m = pat.match(line)
        if m:
            name, addr = m.group(1), int(m.group(2), 16)
            syms.append((addr, name))
            if name == ANCHOR:
                anchor = addr
    syms.sort()
    return syms, anchor


def demangle(name):
    # Rough v0 demangling: keep the readable identifier runs (crate::module::fn)
    parts = re.findall(r"\d+([A-Za-z_][A-Za-z0-9_]*)", name)
    seen = []
    for p in parts:
        if p not in ("hydra",) and not p.startswith("Cs"):
            seen.append(p)
    return "::".join(seen[-4:]) if seen else name


def main():
    syms, anchor_map = load_map(MAP)
    addrs = [a for a, _ in syms]
    hits = collections.Counter()
    for line in open(sys.argv[1], encoding="latin1"):
        m = re.search(r"rip=0x([0-9a-f]+).*anchor=0x([0-9a-f]+)", line)
        if not m:
            continue
        rip, anchor = int(m.group(1), 16), int(m.group(2), 16)
        addr = rip - anchor + anchor_map
        i = bisect.bisect_right(addrs, addr) - 1
        if i >= 0:
            hits[(demangle(syms[i][1]), addr - syms[i][0])] += 1
    by_fn = collections.Counter()
    for (fn, _), n in hits.items():
        by_fn[fn] += n
    for fn, n in by_fn.most_common(20):
        print(f"{n:5}  {fn}")


if __name__ == "__main__":
    main()
