"""Runs every host unit-test crate (tests/host and tests/host-*) and prints one line per crate
plus the total: passed, failed, ignored.

    python tools/host_tests_all.py [-j N]

Each crate is run from its own directory (cargo reads its .cargo/config.toml from there).
"""
import argparse
import concurrent.futures
import glob
import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(crate):
    p = subprocess.run(["cargo", "test", "--offline", "--no-fail-fast", "-q"], cwd=crate, capture_output=True, text=True)
    out = p.stdout + p.stderr
    passed = sum(int(m) for m in re.findall(r"test result: \w+\. (\d+) passed", out))
    failed = sum(int(m) for m in re.findall(r"(\d+) failed", out.split("test result")[-1] if False else out) if False) if False else sum(
        int(m) for m in re.findall(r"test result: \w+\. \d+ passed; (\d+) failed", out)
    )
    ignored = sum(int(m) for m in re.findall(r"test result: \w+\. \d+ passed; \d+ failed; (\d+) ignored", out))
    errors = [l for l in out.splitlines() if l.startswith("error")][:5]
    fails = [l for l in out.splitlines() if l.strip().startswith("---- ") or "FAILED" in l][:10]
    return os.path.basename(crate), p.returncode, passed, failed, ignored, errors, fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=3, help="crates built at once")
    a = ap.parse_args()
    crates = sorted(os.path.dirname(c) for c in glob.glob(os.path.join(ROOT, "tests", "host*", "Cargo.toml")))
    tot = [0, 0, 0]
    bad = False
    with concurrent.futures.ThreadPoolExecutor(a.j) as ex:
        for name, rc, p, f, i, errors, fails in ex.map(run, crates):
            tot[0] += p
            tot[1] += f
            tot[2] += i
            mark = "" if rc == 0 else "   <-- rc %d" % rc
            print(f"{name:12} passed {p:5}  failed {f:3}  ignored {i:3}{mark}")
            for l in errors + fails:
                print("    " + l)
            bad |= rc != 0
    print(f"{'total':12} passed {tot[0]:5}  failed {tot[1]:3}  ignored {tot[2]:3}")
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
