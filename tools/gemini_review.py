"""Second-opinion code review by Gemini (Google's Antigravity CLI, `agy`), read-only.

    python tools/gemini_review.py --base 7b31b39 --head mk-vfs-core [--path src] [--focus "locking in walk.rs"]
    python tools/gemini_review.py --diff-file some.diff
    python tools/gemini_review.py --files scratch/hang.log src/task/scheduler.rs --question "..."

What it does:
  1. Puts the material (a git diff, or the given files) INTO THE PROMPT, in chunks of about
     24,000 characters (a Windows command line holds 32,767), split at file boundaries, so
     Gemini needs no tools at all.
  2. Runs `agy -p` from an EMPTY work folder (%LOCALAPPDATA%\\hydra-gemini-review), in plan
     mode, sandboxed; print mode denies every tool that would need a confirmation.
  3. Prints Gemini's answer per chunk.

Gemini sends what it reads to Google (the user agreed to this for Hydra on 2026-11-21).
Its findings are suggestions: check each one against the code before acting on it.
Needs Antigravity's CLI (C:\\Users\\<you>\\.gemini\\bin\\agy.exe), signed in.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "hydra-gemini-review")
AGY = os.path.join(os.path.expanduser("~"), ".gemini", "bin", "agy.exe" if os.name == "nt" else "agy")
GIT = r"C:\Program Files\Git\cmd\git.exe" if os.name == "nt" and os.path.exists(r"C:\Program Files\Git\cmd\git.exe") else "git"

# Session-only settings: no extra permissions (the material is in the prompt)
SESSION = {"permissions": {"allow": []}}
CHUNK = 24000

REVIEW_PROMPT = """You are reviewing a change to Hydra OS, a Rust microkernel (x86_64, UEFI) with a Linux
compatibility layer partly in ring-3 services. Below is part {part} of {parts} of the unified diff
(8 lines of context). Do not use any tools: everything you need is in this message.
List correctness problems the change introduces or leaves: wrong logic, off-by-one, integer
overflow, races and lost wake-ups, lock ordering, use after free, double free, missing error
handling, unsafe code without a sound reason, broken invariants between kernel and server.
For each: `path:line - severity (high/medium/low) - the problem in one or two sentences`.
Ignore style and naming. If you find nothing substantial, say so. Do not plan, write or change
anything; answer only.{focus}

=== DIFF PART {part}/{parts} ===
{body}"""

QUESTION_PROMPT = """You are helping investigate Hydra OS, a Rust microkernel (x86_64, UEFI). Below is part
{part} of {parts} of the material (files, each headed by its path). Do not use any tools. Answer:
{question}
Be specific (file, function, line) and say how sure you are; if this part does not bear on the
question, say so in one line. Do not plan, write or change anything; answer only.

=== MATERIAL PART {part}/{parts} ===
{body}"""


def chunks_of(sections):
    """Groups text sections into chunks of at most CHUNK characters (a longer section is cut)."""
    out, cur = [], ""
    for sec in sections:
        while len(sec) > CHUNK:
            if cur:
                out.append(cur)
                cur = ""
            out.append(sec[:CHUNK])
            sec = sec[CHUNK:]
        if cur and len(cur) + len(sec) > CHUNK:
            out.append(cur)
            cur = ""
        cur += sec
    if cur:
        out.append(cur)
    return out


def split_diff(diff):
    """The diff's per-file sections (each starts with `diff --git`)."""
    parts, cur = [], []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git") and cur:
            parts.append("".join(cur))
            cur = []
        cur.append(line)
    if cur:
        parts.append("".join(cur))
    return parts


def fresh_workdir():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)
    with open(os.path.join(WORK, "session.json"), "w") as f:
        json.dump(SESSION, f)


def run_agy(prompt, model, timeout):
    if not os.path.exists(AGY):
        sys.exit(f"Antigravity CLI not found at {AGY}")
    args = [AGY, "-p", prompt, "--mode", "plan", "--sandbox",
            "--settings", os.path.join(WORK, "session.json"), "--print-timeout", f"{timeout}s"]
    if model:
        args += ["--model", model]
    p = subprocess.run(args, cwd=WORK, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if "auto-denied" in out + err:
        print("note: Gemini tried to use a tool (denied); the answer may be missing or incomplete", file=sys.stderr)
    print(out if out else err, flush=True)
    return p.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="diff base (commit or branch)")
    ap.add_argument("--head", help="diff head (commit or branch), default HEAD")
    ap.add_argument("--diff-file", help="review this diff file instead")
    ap.add_argument("--path", nargs="*", default=[], help="limit the diff to these paths")
    ap.add_argument("--focus", default="", help="extra things to look at")
    ap.add_argument("--files", nargs="*", default=[], help="question mode: give Gemini these files")
    ap.add_argument("--question", default="", help="question mode: what to ask about --files")
    ap.add_argument("--model", default="", help="Gemini model id (`agy models`); default: agy's")
    ap.add_argument("--timeout", type=int, default=900, help="seconds Gemini may take per part")
    a = ap.parse_args()

    fresh_workdir()
    if a.files:
        sections = []
        for f in a.files:
            src = f if os.path.isabs(f) else os.path.join(ROOT, f)
            text = open(src, encoding="utf-8", errors="replace").read()
            sections.append("\n----- FILE " + os.path.relpath(src, ROOT) + " -----\n" + text + "\n")
        parts = chunks_of(sections)
        rc = 0
        for n, body in enumerate(parts, 1):
            print(f"===== Gemini, part {n}/{len(parts)} =====", flush=True)
            q = a.question or "What is wrong here?"
            rc |= run_agy(QUESTION_PROMPT.format(part=n, parts=len(parts), question=q, body=body), a.model, a.timeout)
        sys.exit(rc)

    if a.diff_file:
        diff = open(a.diff_file, encoding="utf-8", errors="replace").read()
    else:
        if not a.base:
            sys.exit("give --base (and --head) or --diff-file")
        rng = f"{a.base}..{a.head or 'HEAD'}"
        diff = subprocess.check_output([GIT, "-C", ROOT, "diff", "-U8", rng, "--"] + a.path,
                                       text=True, encoding="utf-8", errors="replace")
    if not diff.strip():
        sys.exit("empty diff")
    focus = ("\nAlso look in particular at: " + a.focus) if a.focus else ""
    parts = chunks_of(split_diff(diff))
    rc = 0
    for n, body in enumerate(parts, 1):
        print(f"===== Gemini, part {n}/{len(parts)} =====", flush=True)
        rc |= run_agy(REVIEW_PROMPT.format(part=n, parts=len(parts), focus=focus, body=body), a.model, a.timeout)
    sys.exit(rc)


if __name__ == "__main__":
    main()
