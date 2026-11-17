"""estimate.py NAME=LOG:BLOCK:SECONDS ...: forwarded system calls per workload (from profparse.py JSON files)
times the added cost per forwarded call (docs/linux-server-design.md, section 6.5).
Example: estimate.py "KDE start=kde1.txt:0:50.9" "apt-get update=work.txt:3:27.9"
"""
import os,json,sys,re
names={}
for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','src','compat','linux','syscalls.rs'),encoding='utf-8'):
    m=re.match(r'\s*pub const SYS_([A-Z0-9_]+):\s*u64\s*=\s*(\d+)',l)
    if m: names[int(m.group(2))]=m.group(1).lower()
# Calls that stay in the kernel in the recommended design (Design C): memory, futex,
# thread-local signal state, identity, clocks and sleeps, thread exit, CPU/affinity.
LOCAL={9:'mmap(anon)',10:'mprotect',11:'munmap',12:'brk',13:'rt_sigaction',14:'rt_sigprocmask',15:'rt_sigreturn',
 24:'sched_yield',25:'mremap',27:'mincore',28:'madvise',35:'nanosleep',39:'getpid',60:'exit',102:'getuid',104:'getgid',
 107:'geteuid',108:'getegid',110:'getppid',131:'sigaltstack',158:'arch_prctl',186:'gettid',202:'futex',203:'sched_setaffinity',
 204:'sched_getaffinity',218:'set_tid_address',228:'clock_gettime',229:'clock_getres',230:'clock_nanosleep',231:'exit_group',
 273:'set_robust_list',309:'getcpu',318:'getrandom',324:'membarrier',334:'rseq',96:'gettimeofday',201:'time',149:'mlock',150:'munlock'}
# AF_INET traffic would take a second hop (Linux server -> net-server); the profile cannot tell
# socket families apart, so this is reported, not added.
SOCK={41,42,43,44,45,46,47,288,299,307}
# Arguments: "NAME=LOG:BLOCK:SECONDS" (LOG.json from profparse.py, BLOCK the prof block's index,
# SECONDS the workload's wall time)
work=[]
for arg in sys.argv[1:]:
    name,spec=arg.split('=',1)
    log,blk,wall=spec.rsplit(':',2)
    work.append((name,log,int(blk),float(wall)))
F={'Handoff today (7.0 us)':7.0,'Queued today (18.5 us)':18.5,'Queued, server awake (9.3 us)':9.3,'Direct switch (2.5 us)':2.5}
print('| Workload | wall s | normal-path calls | stay in kernel | forwarded | '+' | '.join(F)+' |')
for name,f,bi,wall in work:
    b=json.load(open(f+'.json'))[bi]['sc']
    tot=sum(v[0] for v in b.values()); loc=sum(v[0] for k,v in b.items() if int(k) in LOCAL)
    fwd=tot-loc; sock=sum(v[0] for k,v in b.items() if int(k) in SOCK)
    cells=[f"{fwd*c/1e6:.2f} s ({100*fwd*c/1e6/wall:.0f}%)" for c in F.values()]
    print(f"| {name} | {wall} | {tot} | {loc} | {fwd} (sockets {sock}) | "+' | '.join(cells)+' |')
    allf=[f"{tot*c/1e6:.2f}" for c in F.values()]
    print(f"|   (if every call were forwarded) | | | | {tot} | "+' | '.join(allf)+' |')
