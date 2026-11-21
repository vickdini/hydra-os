"""Second-opinion code review by Gemini (Google's Antigravity CLI, `agy`), read-only.

    python tools/gemini_review.py --base 7b31b39 --head mk-vfs-core [--path src] [--focus "locking in walk.rs"]
    python tools/gemini_review.py --diff-file some.diff
    python tools/gemini_review.py --files scratch/hang.log src/task/scheduler.rs --question "..."
    (add --who NAME to label the caller on the status page)

What it does:
  1. Puts the material (a git diff, or the given files) INTO THE PROMPT, in chunks of about
     24,000 characters (a Windows command line holds 32,767), split at file boundaries, so
     Gemini needs no tools at all.
  2. Runs `agy -p` from an empty work folder of its own (%LOCALAPPDATA%/hydra-gemini-review/<pid>),
     in plan mode, sandboxed; print mode denies every tool that would need a confirmation.
  3. Prints Gemini's answer per chunk, and appends what it is doing (start, each part, end) to
     %LOCALAPPDATA%/hydra-gemini-review/activity.jsonl, which the agents status page shows.

The diff and the files are taken from the git repository you run it in (a worktree reviews
its own branch). `--who` names the caller (default: that repository's folder name).

Gemini sends what it reads to Google (the user agreed to this for Hydra on 2026-11-21).
Its findings are suggestions: check each one against the code before acting on it.
Needs Antigravity's CLI (C:/Users/<you>/.gemini/bin/agy.exe), signed in.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "hydra-gemini-review")
WORK = os.path.join(BASE_DIR, str(os.getpid()))
ACTIVITY = os.path.join(BASE_DIR, "activity.jsonl")
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


def log(**ev):
    """Appends one event to the activity log (best effort; the status page reads it)."""
    ev["ts"] = time.time()
    ev["pid"] = os.getpid()
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(ACTIVITY, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
    except OSError:
        pass


def repo_root():
    """The git repository the caller is in (falls back to this script's repository)."""
    try:
        out = subprocess.check_output([GIT, "rev-parse", "--show-toplevel"], text=True,
                                      stderr=subprocess.DEVNULL).strip()
        if out:
            return os.path.normpath(out)
    except (OSError, subprocess.CalledProcessError):
        pass
    return ROOT


def chunks_of(sections):
    """Groups text sections into chunks of at most CHUNK characters (a longer section is cut)."""
    out, cur = [], ""
    for sec in sections:
        # a section cut in pieces: every later piece repeats its first line (the file header)
        first = sec.lstrip("\n").split("\n", 1)[0]
        while len(sec) > CHUNK:
            if cur:
                out.append(cur)
                cur = ""
            cut = sec.rfind("\n", 0, CHUNK) + 1 or CHUNK
            out.append(sec[:cut])
            sec = first + "  (continued)\n" + sec[cut:]
        if cur and len(cur) + len(sec) > CHUNK:
            out.append(cur)
            cur = ""
        cur += sec
    if cur:
        out.append(cur)
    return out


def file_chunks(files, repo):
    """The files as numbered lines, packed into chunks of at most CHUNK characters. A file that
    does not fit in one chunk is cut at line boundaries, and every piece starts with its path and
    line range, so each part can be read on its own; small files stay whole."""
    pieces = []
    for f in files:
        src = f if os.path.isabs(f) else os.path.join(repo, f)
        rel = os.path.relpath(src, repo)
        lines = open(src, encoding="utf-8", errors="replace").read().splitlines()
        numbered = [f"{i:5} {l}\n" for i, l in enumerate(lines, 1)]
        if not numbered:
            pieces.append(f"\n----- FILE {rel} (empty) -----\n")
            continue
        start = 0
        while start < len(numbered):
            size, end = 0, start
            while end < len(numbered) and size + len(numbered[end]) < CHUNK - 200:
                size += len(numbered[end])
                end += 1
            end = max(end, start + 1)
            head = f"\n----- FILE {rel} (lines {start + 1}-{end} of {len(lines)}) -----\n"
            pieces.append(head + "".join(numbered[start:end]))
            start = end
    return chunks_of(pieces)


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


def run_agy(prompt, model, timeout, part, parts):
    if not os.path.exists(AGY):
        print(f"Antigravity CLI not found at {AGY}", file=sys.stderr)
        return 3
    args = [AGY, "-p", prompt, "--mode", "plan", "--sandbox",
            "--settings", os.path.join(WORK, "session.json"), "--print-timeout", f"{timeout}s"]
    if model:
        args += ["--model", model]
    log(event="part", part=part, parts=parts)
    t0 = time.time()
    try:
        p = subprocess.run(args, cwd=WORK, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout + 120)
        out, err, rc = (p.stdout or "").strip(), (p.stderr or "").strip(), p.returncode
    except subprocess.TimeoutExpired:
        out, err, rc = "", f"Gemini did not finish within {timeout + 120} s (stopped)", 124
    # agy's own message when a tool was refused (not Gemini's answer text)
    denied = out.startswith("jetski: no output produced") or "auto-denied" in err
    log(event="part_done", part=part, parts=parts, rc=rc, seconds=round(time.time() - t0),
        answer=(out or err)[:600], denied=denied)
    if denied:
        print("note: Gemini tried to use a tool (denied); the answer may be missing or incomplete", file=sys.stderr)
    print(out if out else err, flush=True)
    if out and err:
        print(err, file=sys.stderr)
    return rc


def work(a, repo, who):
    if a.files:
        parts = file_chunks(a.files, repo)
        log(event="start", who=who, mode="question", repo=repo, what=", ".join(a.files)[:300],
            question=(a.question or "")[:300], parts=len(parts))
        rc = 0
        for n, body in enumerate(parts, 1):
            print(f"===== Gemini, part {n}/{len(parts)} =====", flush=True)
            q = a.question or "What is wrong here?"
            rc |= run_agy(QUESTION_PROMPT.format(part=n, parts=len(parts), question=q, body=body),
                          a.model, a.timeout, n, len(parts))
        return rc

    if a.diff_file:
        diff = open(a.diff_file, encoding="utf-8", errors="replace").read()
        what = a.diff_file
    else:
        if not a.base:
            print("give --base (and --head) or --diff-file", file=sys.stderr)
            return 2
        rng = f"{a.base}..{a.head or 'HEAD'}"
        diff = subprocess.check_output([GIT, "-C", repo, "diff", "-U8", rng, "--"] + a.path,
                                       text=True, encoding="utf-8", errors="replace")
        what = rng + (" -- " + " ".join(a.path) if a.path else "")
    if not diff.strip():
        print("empty diff", file=sys.stderr)
        return 2
    focus = ("\nAlso look in particular at: " + a.focus) if a.focus else ""
    parts = chunks_of(split_diff(diff))
    log(event="start", who=who, mode="review", repo=repo, what=what[:300], focus=a.focus[:200], parts=len(parts))
    rc = 0
    for n, body in enumerate(parts, 1):
        print(f"===== Gemini, part {n}/{len(parts)} =====", flush=True)
        rc |= run_agy(REVIEW_PROMPT.format(part=n, parts=len(parts), focus=focus, body=body),
                      a.model, a.timeout, n, len(parts))
    return rc


def main():
    # Gemini's answers contain characters the Windows console code page cannot print
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
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
    ap.add_argument("--who", default="", help="who is asking (shown on the status page)")
    a = ap.parse_args()

    repo = repo_root()
    who = a.who or os.path.basename(repo)
    fresh_workdir()
    t_start = time.time()
    rc = 1
    try:
        rc = work(a, repo, who)
    finally:
        log(event="end", who=who, rc=rc, seconds=round(time.time() - t_start))
        shutil.rmtree(WORK, ignore_errors=True)
    sys.exit(rc)


if __name__ == "__main__":
    main()
