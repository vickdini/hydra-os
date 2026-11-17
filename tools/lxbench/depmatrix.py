# depmatrix.py DIR: per file of DIR (src/compat/linux), lines, keyword counts per kernel area
# (memory maps, faults, signals, scheduling, wait queues, futex, descriptors, VFS, IPC,
# credentials, namespaces, timers, network, user copies) and the crate:: modules it names.
import os,re,sys
root=sys.argv[1]
cats={
 'mm':r'memory::(vm|paging|frame_allocator)|AddressSpace|map_page|unmap|page_table|Vma\b|vm::',
 'fault':r'page_fault|handle_fault|fault\(',
 'sig':r'proc::(post|send|kill|signal_pending|deliver|take_signal)|signal_pending|post_signal|SIG[A-Z]{2,}',
 'sched':r'scheduler|SCHEDULER|current_task|block_on|yield_now|wake\(|\.sleep|task::',
 'wq':r'WaitQueue|wait_event|wake_all|wake_one|QueueRef',
 'futex':r'futex',
 'fd':r'fs::fd|FileDescriptor|fd_table|get_fd|alloc_fd|OpenFile',
 'vfs':r'fs::client|fs::zfs|zfs::|vfs::|ZfsClient|fs::pipe',
 'ipc':r'ipc::service|ipc::|svc_call|service::call',
 'cred':r'\buid\b|\bgid\b|euid|capab|cred',
 'ns':r'\bns::|namespace|mnt_ns|pid_ns',
 'timer':r'pit::|now_ns|Timer|deadline|ticks',
 'net':r'crate::net|net::',
 'copy':r'copy_in|copy_out|copy_from_user|copy_to_user|user_ptr',
}
rows=[]
for f in sorted(os.listdir(root)):
    if not f.endswith('.rs'): continue
    s=open(os.path.join(root,f),encoding='utf-8',errors='replace').read()
    code='\n'.join(l for l in s.splitlines() if not l.strip().startswith('//'))
    n=len(s.splitlines())
    hits={k:len(re.findall(v,code)) for k,v in cats.items()}
    uses=sorted(set(re.findall(r'crate::([a-z_]+(?:::[a-z_]+)?)',code)))
    rows.append((n,f,hits,uses))
rows.sort(reverse=True)
print('lines file '+' '.join(cats))
for n,f,h,u in rows:
    print(f"{n:5} {f:16} "+' '.join(f"{h[k]:>{len(k)}}" for k in cats)+"  | "+','.join(x for x in u if not x.startswith('compat')))
