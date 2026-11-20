"""wavgaps.py WAV [FREQ]: finds gaps/glitches in a recorded sine (Group 25 sound test).
Prints the sound's start/end, runs of silence inside it, and sample-level discontinuities
(residual of the sine recurrence x[n] = 2cos(w) x[n-1] - x[n-2])."""
import math, struct, sys
data = open(sys.argv[1], 'rb').read()
freq = float(sys.argv[2]) if len(sys.argv) > 2 else 440.0
i = 12; rate = 44100; ch = 2; pcm = b''
while i < len(data) - 8:
    cid, sz = data[i:i+4], struct.unpack('<I', data[i+4:i+8])[0]
    if cid == b'fmt ':
        ch, rate = struct.unpack('<HI', data[i+10:i+16])
    if cid == b'data':
        pcm = data[i+8:]  # size may be wrong if QEMU was killed
        break
    i += 8 + sz
n = len(pcm) // (2 * ch)
x = struct.unpack('<%dh' % (n * ch), pcm[:n * ch * 2])[::ch]
nz = [k for k in range(n) if abs(x[k]) > 200]
if not nz:
    print("rate", rate, "frames", n, "no sound"); sys.exit()
a, b = nz[0], nz[-1]
print("rate %d frames %d sound %.2f s .. %.2f s (%.2f s)" % (rate, n, a / rate, b / rate, (b - a) / rate))
c = 2 * math.cos(2 * math.pi * freq / rate)
amp = max(abs(v) for v in x[a:b])
# silence runs (|x| < 50 for > 2 ms) inside the sound
gaps = []; k = a
while k < b:
    if abs(x[k]) < 50:
        j = k
        while j < b and abs(x[j]) < 50:
            j += 1
        if j - k > rate // 500:
            gaps.append((k, j))
        k = j
    else:
        k += 1
glitch = []
last = -10**9
for k in range(a + 2, b):
    r = x[k] - (c * x[k-1] - x[k-2])
    if abs(r) > 0.08 * amp and k - last > rate // 200:
        glitch.append(k); last = k
print("amplitude", amp, "silence gaps (>2 ms):", len(gaps), "glitches:", len(glitch))
for g in gaps[:30]:
    print("  gap at %.3f s, %.1f ms" % (g[0] / rate, (g[1] - g[0]) * 1000 / rate))
print("  glitch times:", " ".join("%.3f" % (g / rate) for g in glitch[:60]))
