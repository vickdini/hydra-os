"""agg.py LOG...: per test, the median of each run (5 loops each) and the overall spread."""
import re,sys,statistics
runs={}
for f in sys.argv[1:]:
    txt=open(f,encoding='utf-8',errors='replace').read().replace('\x00','').replace('\r','')
    ep=None
    for l in txt.split('\n'):
        m=re.match(r'lxbench: probe \S+, endpoint (\S+)',l)
        if m: ep=m.group(1)
        m=re.match(r'BENCH (\S+)\s+min\s+(\d+) med\s+(\d+) max\s+(\d+)',l)
        if m:
            name=m.group(1)+('@'+ep if m.group(1).startswith('probe_') and m.group(1)!='probe_null' else '')
            runs.setdefault(name,[]).append((int(m.group(2)),int(m.group(3)),int(m.group(4)),f))
print('| Test | runs | median (us) | run medians (us) | lowest..highest loop (us) |')
for n,v in runs.items():
    meds=[x[1] for x in v]
    print(f"| {n} | {len(v)} | {statistics.median(meds)/1000:.2f} | {', '.join(f'{m/1000:.2f}' for m in meds)} | {min(x[0] for x in v)/1000:.2f}..{max(x[2] for x in v)/1000:.2f} |")
