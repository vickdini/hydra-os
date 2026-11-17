"""profparse.py LOG: the `linux prof show` blocks of a serial log -> per-block summary, and LOG.json
for estimate.py (Linux-server design, wave 2 group 6)."""
import os,re,sys,json
# syscall names from the kernel's table
names={}
for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','src','compat','linux','syscalls.rs'),encoding='utf-8'):
    m=re.match(r'\s*pub const SYS_([A-Z0-9_]+):\s*u64\s*=\s*(\d+)',l)
    if m: names[int(m.group(2))]=m.group(1).lower()
txt=open(sys.argv[1],encoding='utf-8',errors='replace').read().replace('\r','')
blocks=re.split(r'\[prof\] page faults:',txt)[1:]
out=[]
for b in blocks:
    lines=[l for l in b.split('\n') if l.startswith('[prof]')]
    faults={}; fs={}; sc={}
    sect='faults'
    for l in lines:
        if 'file-server requests' in l: sect='fs'; continue
        if 'system calls by total time' in l: sect='sc'; continue
        if sect=='faults':
            m=re.match(r'\[prof\]\s+(\d+)\s+(\d+) ms\s+(\d+) \S+/each\s+(.*)',l)
            if m: faults[m.group(4)]=(int(m.group(1)),int(m.group(2)))
        elif sect=='fs':
            m=re.match(r'\[prof\]\s+(\d+)\s+(\d+) ms\s+(\d+) us/each\s+(\S+)',l)
            if m: fs[m.group(4)]=(int(m.group(1)),int(m.group(2)),int(m.group(3)))
        else:
            m=re.match(r'\[prof\]\s+nr\s+(\d+)\s+(\d+) calls\s+(\d+) ms\s+(\d+) us/each',l)
            if m: sc[int(m.group(1))]=(int(m.group(2)),int(m.group(3)))
            else: break
    out.append({'faults':faults,'fs':fs,'sc':sc})
for i,o in enumerate(out):
    tot=sum(c for c,_ in o['sc'].values())
    print(f"=== block {i}: {tot} system calls (normal path), {len(o['sc'])} kinds")
    for k,(n,ms) in o['faults'].items(): print(f"   {n:>9} {ms:>7} ms  {k}")
    print("   file-server requests:", sum(v[0] for v in o['fs'].values()), {k:v[0] for k,v in o['fs'].items()})
    top=sorted(o['sc'].items(),key=lambda kv:-kv[1][0])[:25]
    print("   top by count:", ', '.join(f"{names.get(nr,nr)}={n}" for nr,(n,ms) in top))
json.dump([{**o,'sc':{str(k):v for k,v in o['sc'].items()}} for o in out],open(sys.argv[1]+'.json','w'))
