"""Line coverage of the kernel (src/) by the host unit tests (tests/host).

Builds every host test crate (tests/host, tests/host-*) with `-C instrument-coverage` into
<crate>/target/cov (its own target directory, so the normal test build is not disturbed),
runs every test binary, merges the profiles with
llvm-profdata and asks llvm-cov for per-file line counts. Kernel files the host tests do not
compile at all count as 0 %.

    python tools/host_coverage.py [--json out.json] [--files] [--filter SUBSTR]

Prints the total, a table per subsystem (src/<dir>), and with --files one line per file.
Needs the rustup component llvm-tools (`rustup component add llvm-tools`).
Run from anywhere; it finds the repository from its own location.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def llvm_tool(name):
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    hits = glob.glob(os.path.join(sysroot, "lib", "rustlib", "*", "bin", name + "*"))
    if not hits:
        sys.exit(f"{name} not found: run `rustup component add llvm-tools`")
    return hits[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write the per-file numbers here")
    ap.add_argument("--files", action="store_true", help="one line per kernel file")
    ap.add_argument("--filter", default="", help="only files whose path contains this")
    ap.add_argument("--no-build", action="store_true", help="reuse the last instrumented run")
    ap.add_argument("--crates", default="", help="only these crates (comma list of name parts, e.g. host-t26)")
    ap.add_argument("--quiet", action="store_true", help="hide the test output")
    a = ap.parse_args()

    # Every host test crate: tests/host and the per-group tests/host-*
    crates = sorted(os.path.dirname(c) for c in glob.glob(os.path.join(ROOT, "tests", "host*", "Cargo.toml")))
    if a.crates:
        crates = [c for c in crates if any(k in os.path.basename(c) for k in a.crates.split(","))]
    seen = {}
    for crate in crates:
        cov = os.path.join(crate, "target", "cov")
        profdir = os.path.join(cov, "profraw")
        merged = os.path.join(cov, "merged.profdata")
        env = dict(os.environ)
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
        env["CARGO_TARGET_DIR"] = cov
        if not a.no_build:
            os.makedirs(profdir, exist_ok=True)
            for f in glob.glob(os.path.join(profdir, "*.profraw")):
                os.remove(f)
            env["LLVM_PROFILE_FILE"] = os.path.join(profdir, "t-%p-%m.profraw")
            # (tests must run from the crate: cargo reads its .cargo/config from the cwd)
            r = subprocess.run(["cargo", "test", "--offline", "--no-fail-fast", "-q"], cwd=crate, env=env,
                               stdout=subprocess.DEVNULL if a.quiet else None)
            if r.returncode != 0:
                print(f"note: {os.path.basename(crate)}: some tests failed; coverage is still reported", file=sys.stderr)
            raws = glob.glob(os.path.join(profdir, "*.profraw"))
            if not raws:
                print(f"note: {os.path.basename(crate)}: no profiles", file=sys.stderr)
                continue
            subprocess.check_call([llvm_tool("llvm-profdata"), "merge", "-sparse", "-o", merged] + raws)
        if not os.path.exists(merged):
            continue
        out = subprocess.check_output(
            ["cargo", "test", "--offline", "--no-run", "--message-format=json", "-q"], cwd=crate, env=env, text=True
        )
        bins = []
        for line in out.splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
                bins.append(m["executable"])
        if not bins:
            continue
        args = [llvm_tool("llvm-cov"), "export", "-summary-only", "-instr-profile", merged, bins[0]]
        for b in bins[1:]:
            args += ["-object", b]
        data = json.loads(subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL))
        # Per kernel file (paths normalised to src/...); a file several crates compile counts
        # with its best coverage
        root = os.path.normcase(os.path.join(ROOT, "src")) + os.sep
        for f in data["data"][0]["files"]:
            p = f["filename"]
            if not os.path.isabs(p):
                p = os.path.join(crate, p)
            p = os.path.normcase(os.path.normpath(p))
            if not p.startswith(root):
                continue
            rel = "src/" + p[len(root):].replace(os.sep, "/")
            lines = f["summary"]["lines"]
            prev = seen.get(rel)
            if prev is None or lines["covered"] > prev[1]:
                seen[rel] = (lines["count"], lines["covered"])
    rows = []
    for path in glob.glob(os.path.join(ROOT, "src", "**", "*.rs"), recursive=True):
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        key = os.path.normcase(rel).replace("\\", "/")
        if a.filter and a.filter not in rel:
            continue
        if key in seen:
            count, covered = seen[key]
            compiled = True
        else:
            # Not compiled into the host tests: its code lines count as uncovered (estimate:
            # lines that are not blank and not comments)
            count = sum(
                1
                for l in open(path, encoding="utf-8", errors="ignore")
                if l.strip() and not l.strip().startswith("//")
            )
            covered = 0
            compiled = False
        rows.append((rel, count, covered, compiled))

    tot = sum(r[1] for r in rows)
    cov = sum(r[2] for r in rows)
    comp = sum(1 for r in rows if r[3])
    print(f"kernel: {len(rows)} files, {comp} compiled into the host tests; lines {cov}/{tot} covered = {100 * cov / max(tot, 1):.1f}%")
    groups = {}
    for rel, count, covered, compiled in rows:
        parts = rel.split("/")
        key = "/".join(parts[1:3]) if len(parts) > 3 else parts[1]
        g = groups.setdefault(key, [0, 0, 0, 0])
        g[0] += count
        g[1] += covered
        g[2] += 1
        g[3] += compiled
    for k, (count, covered, n, c) in sorted(groups.items(), key=lambda kv: -kv[1][0]):
        print(f"  {k:28} {covered:6}/{count:6} {100 * covered / max(count, 1):5.1f}%   {c}/{n} files compiled")
    if a.files:
        for rel, count, covered, compiled in sorted(rows):
            mark = "" if compiled else "   (not compiled)"
            print(f"  {rel:48} {covered:6}/{count:6} {100 * covered / max(count, 1):5.1f}%{mark}")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({r[0]: {"lines": r[1], "covered": r[2], "compiled": r[3]} for r in rows}, fh, indent=1)


if __name__ == "__main__":
    main()
