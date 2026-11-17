"""frames.py DIR: when did the screen settle after the password (f001 -> Enter)?
Prints, per frame, seconds since the Enter key (mtime of f001) and the mean difference
to the final frame and to the previous frame (sampled pixels)."""
import os, sys
d = sys.argv[1]
def load(p):
    b = open(p, 'rb').read()
    # P6\nW H\n255\n
    parts = b.split(b'\n', 3)
    return parts[3][::97]
fs = sorted(f for f in os.listdir(d) if f.startswith('f') and f.endswith('.ppm'))
t0 = os.path.getmtime(os.path.join(d, 'f001.ppm'))
final = load(os.path.join(d, fs[-1]))
prev = None
rows = []
for f in fs:
    px = load(os.path.join(d, f))
    t = os.path.getmtime(os.path.join(d, f)) - t0
    n = min(len(px), len(final))
    dfin = sum(abs(px[i] - final[i]) for i in range(n)) / n
    dprev = sum(abs(px[i] - prev[i]) for i in range(n)) / n if prev else 0
    rows.append((f, t, dfin, dprev))
    prev = px
for r in rows:
    print(f"{r[0]} t={r[1]:7.2f}s  to-final {r[2]:6.2f}  to-prev {r[3]:6.2f}")
# settled: the first frame from which every later frame is within 1.0 of the final one
for i in range(len(rows)):
    if all(r[2] < 1.0 for r in rows[i:]):
        print(f"SETTLED at {rows[i][0]} t={rows[i][1]:.2f}s after Enter")
        break
