# The Linux server: forwarding Linux system calls out of the kernel

Since microkernel wave 3 (Group 7, branch `mk-lxfwd`) part of the Linux personality runs in
a ring-3 program, `linux-server`. This is **step 1** of the plan in
[linux-server-design.md](../linux-server-design.md) (section 7): the forwarding machinery,
with one harmless tenant, the key retention service (`add_key`, `request_key`, `keyctl`,
`/proc/keys`). Every later step moves more of `src/compat/linux` into the same server over
the same machinery. **Step 2** (wave 4, Group 9, branch `mk-lxobj`) added server-object
descriptors with readiness words, `sig_post`, blocking calls that do not tie up the workers,
and moved the POSIX message queues, System V semaphores and message queues, and `bpf`
(section "Server-object descriptors" below).

```text
 Linux program                                        linux-server (ring 3, userland/drivers/linux-server)
   | syscall                                            main thread: endpoint 0x29 (heartbeats,
   v                                                      /proc/keys, notification ring)
 arch/syscall.rs -> compat/linux dispatch_linux_syscall   worker threads (4): each loops in
   | seccomp, then the forwarding table (src/lx)            SYS_LX_REPLY_RECV on its syscall page
   |-- kernel: dispatch_checked (as before)                     ^ call in the page        | answer
   '-- server: src/lx::call ---- direct switch ------------------'                        |
          ^                      (int 0x82: the caller blocks, the worker runs next       |
          '--------------------- on this CPU; the answer comes back the same way) <-------'
```

## Who does what

| Piece | Where | Job |
|---|---|---|
| Forwarding table | `src/lx/mod.rs` (`forward`, `route`, `init`) | Per Linux system call number: the kernel answers it, or the server does |
| Requests and workers | `src/lx/mod.rs` | The calls in flight, the idle workers, queueing when none is idle, `-EIO` when the server dies |
| Direct switch | `Scheduler::direct_handover` / `direct_switch_core` (`src/task/scheduler.rs`), vector 0x82 (`src/arch/idt.rs`) | Hands the CPU from the caller to the worker and back without the run-queue pass |
| Client memory | `src/lx/mod.rs` (`client_mem`, `proc_info`) | The server reads and writes the caller's memory, faulting pages in as the caller would |
| Notifications | `src/lx/mod.rs` (`note`), ring in the server's window | Fork, exec, process exit, a signal for a pending call |
| Crash policy | `src/lx/mod.rs` (`on_signal`, `recover_task`, `watch`) | The server died: calls fail, every Linux program ends, the login screen comes back |
| The server | `userland/drivers/linux-server` | Workers, the main thread, the ring, and the moved `keys` code |
| Native threads | `SYS_THREAD_CREATE` (50), `Scheduler::spawn_native_thread` | The server's worker threads (native programs had one thread before) |

## The forwarding table and the switch back

`crate::lx::forward(frame)` runs for every Linux system call, after `seccomp` and before the
kernel's dispatcher, holding no locks. For a number the table gives to the server it forwards
the call; otherwise the kernel answers as before (one atomic load per call).

Step 1 forwards `add_key` (248), `request_key` (249), `keyctl` (250) and Hydra's test call
`0x6710` (`LX_NULL_NR`). Step 2 (wave 4, Group 9) adds the POSIX message queues
(`mq_open` .. `mq_getsetattr`, 240–245), System V semaphores and message queues (`semget`,
`semop`, `semctl`, `semtimedop`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`; shared memory followed in
wave 10, below) and `bpf` (321), listed in `lx::MOVED_STEP2`. While linux-server is not online the
forwarded calls fail with `ENOSYS`.

**System V shared memory (wave 10, Group 8-2)** is lx-ipc's too: `shmget`, `shmat` and `shmctl`
are routed there (`T_IPC`); `shmdt` stays a kernel call. Each segment's pages are a kept memory
object of lx-ipc (key `lx_shm_key(id)`, sparse, up to `SHMMAX` = 1 TiB with `LX_MEM_BIG`), so
they survive an lx-ipc restart and attached programs never notice one. lx-ipc answers `shmat`
(permission, IPC namespace, `shm_atime`/`shm_lpid`) with a redirect to `LX_REDIR_SHM` naming
that object; the kernel takes the object from the kept registry and maps it (`lx::shm`). The
kernel keeps the attachments (`lx::shm_table`: `shmat`, `shmdt`, `fork`, exit, `execve`),
lx-ipc asks it for `shm_nattch` (`SYS_LX_OBJ` op `LX_OBJ_SHM`) and is told when one goes
(`LX_NOTE_SHM`: `shm_dtime`, `shm_lpid`, a removed segment's last detach). `/proc/sysvipc/{shm,sem,msg}`
are linux-server's pseudo files, made with lx-ipc's info call (direct call op
`LX_IPC_OP_SYSVIPC`, which lx-proc can call the same way). `lx=kernel` and `lx.ipc=kernel` keep
the in-kernel copy (`compat/linux/sysv.rs`) until 10-C.

Each table entry was a byte of flags (wave 6 widened it to a u32 that also names the service, below): the server answers the call (`T_SERVER`), `args[0]` is a
descriptor whose server object the call carries (`T_FD0`: `LxCall::obj`), and the call
carries the caller's IPC namespace and umask (`T_IPC`).

**No switch back since wave 10 (10-C, decision 32).** Until wave 10, QEMU's
`-fw_cfg name=opt/hydra/lx,string=kernel` or the boot word `lx=kernel` (and per service
`lx.<name>=kernel`, `lx.<name>=linux`) sent calls back to an in-kernel copy. Those copies are
deleted; the words are read only to log `[lx] <word>: ignored (no switch back since wave 10: a
crashed service is restarted)`. A service that is not running answers `ENOSYS` (`EIO` once
the restart ladder gave it up; `EAFNOSUPPORT` for `socket` of its family); a restarting one
is waited for.

## Several services (wave 6, Group 19)

Since decision 9 the Linux layer becomes several ring-3 services instead of one linux-server
(`docs/linux-services-design.md`, section 3). Wave 6 builds the routing core; every piece moved
so far still runs in linux-server, which *co-locates* them.

**Service ids and the registry** (`src/lx/svc.rs`). A service id (`SvcId`, `LXS_*` in
`ipc/protocol.rs`) names a Linux-facing service: `LXS_LINUX` 1, `LXS_VFS` 2, `LXS_NET` 3,
`LXS_IPC` 4, `LXS_PROC` 5, `LXS_DISPLAY` 6, `LXS_INPUT` 7, `LXS_SOUND` 8, `LXS_TTY` 9,
`LXS_SEC` 10, `LXS_TEST` 11. The registry `SVC[id]` gives each id its endpoint, its *host* and
its mode. Several ids may name one endpoint: net, ipc, proc and sec name linux-server's 0x29
today. A **host** (`svc::Host`) is the runtime state of one serving process: its request table
and lock, workers, `req_done`/`has_work` flags, notification ring, object area and counters.
It is named by the lowest id of its endpoint (linux-server: 1, the test service: 11), made when
its first worker attaches and never freed. When a process goes online on endpoint E it becomes
the host of every id whose endpoint is E, so splitting a piece out means: give its id another
endpoint (one line, `DEFAULT_ENDPOINTS`) and start a program there.

**The route entry** is a u32 per number (`TABLE[512]`, plus `PRIV[128]` for Hydra's private
numbers `0x6700..0x677F`, so the test calls route the same way): bits 0..7 the flags of waves
4–5, bits 8..11 the service, bits 12..15 `T_FSCTX` (carry process group, session and
namespace ids), `T_IDEMPOTENT`, `T_BYARG`, `T_REDIR`. `lx::route(nr)` and `lx::entry(nr)`
stay one load. A call finds its service:

1. by number: the entry's service (keys and bpf: sec; mq_*, System V, pipes, eventfd,
   signalfd, timerfd, pidfd: ipc; the test call: test);
2. by family (`T_FAMILY`): `FAMILY_SVC[family]` (AF_UNIX: ipc; AF_INET, AF_INET6,
   AF_NETLINK: net);
3. by descriptor (`T_BYFD`): the server object records its host (`ServerObject::svc`);
4. by device major: `MAJOR_SVC[major]`, claimed by a service (`LX_SVC_CLAIM_MAJOR`); the
   kernel's `open` of such a character node forwards `LX_KCALL_DEVOPEN` (`LxCall::dev`), the
   service installs a descriptor, and that object becomes the opened file;
5. by redirect: a worker answers `LX_REPLY_REDIRECT` with `result = svc | tail << 32` and the
   object in its page's `LxCall::redir_obj`; the kernel forwards the same call (same copies)
   to that service in the same trap (`redir_obj`, `redir_tail`, `redirs`), at most 4 times,
   then `-ELOOP`.

`fast_entry` picks the host and then does exactly what it did for the one server; each host
has its own request-table lock. Request ids carry the host (`id = host << 56 | sequence`), so
`SYS_LX_COMPLETE`, client memory and the `LX_OBJ_*` operations find the right table, and a
service can only name its own requests.

**Objects.** Each host has its own 8192 slots (2048 before; Wine used about half) in an
*object area* of its own (33 pages, outside the 256 KiB window, mapped with
`LX_CTL_OBJAREA`); `LX_OBJ_OFF` and the two bitmaps are offsets in that area. The doorbell
hook finds the host by endpoint (`lx::on_signal_for::<EP>`). poll, select and epoll read the
word of whichever host owns each descriptor. `SCM_RIGHTS` of another service's object passes
through a Unix socket as a kernel descriptor (the kernel keeps it, `LX_OBJ_TAKE`/`GIVE`).

**Notifications.** One ring per host, in its window. FORK, EXEC and EXIT go to every host that
subscribed (`LX_SVC_SUBSCRIBE`; linux-server is subscribed to all); INTERRUPT goes to the
request's host, CLOSE to the object's, TIMER to the host that armed it.

**When a service dies.** linux-server: decision 6 as before (every Linux program ends, the
login screen comes back). Any other service: its calls in flight fail with `EIO`, calls made
while it is gone fail with `ENOSYS`, its objects poll `POLLERR|POLLHUP` and their calls fail
with `EBADF`; no program is ended, and the supervisor restarts it (wave 6's Group 21 adds the
restart classes).

**Switching back, per service** (decision 17): `lx=kernel` (everything), `lx.<name>=kernel`
(that service's calls go back to the in-kernel code: e.g. `lx.sec=kernel` for keys and bpf),
`lx.<name>=linux` (a split service runs inside linux-server again), as boot-entry words or in
fw_cfg `opt/hydra/lx` (words joined by `+`; `tools/hydra_run.py --lx sec=kernel+ipc=kernel`).
The boot log has one line per service.

**The service runtime** (`hydra-rt/src/svcrt.rs`): the worker loop, the start-up
(`svcrt::start`: workers, endpoint, object area, subscription; then `online()`), the main
thread's receive loop (`Service::recv`), the call being served (`Cx`, moved from linux-server's
`client.rs`), `redirect`, a small object allocator (`objs`) and a ring reader (`notes`).
linux-server and the test service run on it.

**The test service** (`userland/drivers/svc-test`, endpoint 0x32, `LXS_TEST`): the call
`0x6711` (`LX_TEST_NR`: null, new object, pending, redirect to linux-server, who, copy,
redirect loop), its own object kind, and character major 240. Test: `tests/linux/svcroute_test.c`
(`svcroute`, in the suite; `svcroute load S` is the kill test's load, `svcroute bench N` the
cost of a forwarded null call to the second service).

## The syscall page and the worker loop

Each worker thread calls `SYS_LX_CTL(LX_CTL_ATTACH)` once: the kernel allocates a 4 KiB
*syscall page*, maps it into the server, and registers the thread as a worker. Then the
worker loops:

```text
answer = (0, LX_REPLY_NONE)
loop {
    SYS_LX_REPLY_RECV(answer.result, answer.flags)   // answer the last call, wait for the next
    call = *page                                     // an LxCall, written by the kernel
    answer = serve(call)
}
```

`LxCall` (`src/ipc/protocol.rs`, shared with the server through `hydra-rt`) holds the request
ID, the caller's thread and process IDs, the system call number and its six arguments, the
caller's real, effective and saved user and group IDs, its effective capabilities (0 inside a
user namespace of its own), up to 32 supplementary groups, the notification-ring position
(`note_seq`), and `flags` (`LX_CALL_INTERRUPTED`: a signal arrived while the call was being
served).

The answer's flags: `LX_REPLY_PENDING` means the call goes on (the caller keeps sleeping) and
some server thread answers it later with `SYS_LX_COMPLETE(id, result)`: a blocking call.
When the server is ready, the main thread calls `SYS_LX_CTL(LX_CTL_ONLINE)` and forwarding
starts.

## The direct switch

A forwarded call with an idle worker:

1. The caller writes the call into the worker's page (under the request table's lock) and
   enters `int 0x82`.
2. The direct-switch vector saves only the general registers and calls
   `Scheduler::direct_call`, which, in one step under the scheduler lock, blocks the caller
   and switches to the worker through the same `switch_to` tail as the scheduler (the one
   CR3 write is there). There is no run-queue pass, no other CPU woken, no FPU save or
   restore, and the worker inherits the caller's timeslice.
3. The worker returns to user mode with the call in its page, serves it, and calls
   `SYS_LX_REPLY_RECV` with the answer: the same steps hand the CPU straight back to the
   caller, and the worker is idle again.

When the switch cannot be done (the worker is still running on the other CPU, a driver
call's hand-off is in progress, ...), nothing changes and the worker is woken the ordinary
way. There is no machine-wide stop: the direct switch is an ordinary switch between two
tasks of one CPU, and other CPUs and other processes keep running.

## Calls between services (wave 6, Group 20)

Design: `docs/linux-services-design.md` sections 4.2–4.4. Two mechanisms, both built on the
direct switch above.

**A call to a classic server** (net-server, zfs-server, a driver: one server thread in
`SYS_SVC_RECV`) uses `SYS_SVC_CALL` as before; its queued calls from ring-3 servers now take
a *direct path* (`src/ipc/service.rs`, section "The direct path"):

1. A server thread waiting in `recv` is *parked*: it blocked at a point where the compiler
   keeps nothing in vector registers, so vector 0x82 (no FPU state moved) may resume it.
   `Service::parked` names it.
2. The caller places its request as before and switches straight to the parked thread
   (`switch_to_parked`): the scheduler's `direct_call` resumes a target in an *event wait*
   when asked (`DIRECT_EVENT`) and ends its event wait. The server returns to its program
   with the request at once.
3. The server answers with **`SYS_SVC_RECV` + `RECV_REPLY`** (answer request `r10`, then
   receive: `hydra_rt::svccall::reply_recv`). When it finds nothing more to do it parks and,
   in the same step, hands the CPU straight back to the caller; the next call finds it
   parked. net-server's loop does this. When it has loopback frames to deliver right after
   an answer it uses **`RECV_YIELD`** instead (`svccall::reply_yield`): the caller gets the
   CPU at once and net-server stays ready for its round, which may run on the other CPU
   meanwhile (as after wave 5's hand-off reply). A server that still answers with
   `SYS_SVC_REPLY` wakes the caller and parks at its next `recv`.
4. The server's switch back goes only to a caller still blocked by its own direct switch;
   a caller that fell back to waiting on its queue is woken where it waits (no migrations).
5. A caller whose server is busy on the other CPU spins (kernel lock let go, at most
   40 µs) for the answer instead of sleeping and being woken across CPUs.

Whenever a step cannot be done (no parked thread, a hand-off in progress, the server just
woken on the other CPU) the call is an ordinary queued one; nothing is lost (the answer is
marked under the request table's lock before the caller is woken, and the caller's switch
checks that mark under the scheduler lock). Kernel callers keep `Handoff`/`Queued` as they
were.

Measured (KVM, 2 CPUs): linux-server -> net-server null call 3.76 µs (wave 5's hand-off in
the same build: 5.88); TCP and UDP ping-pong 20-40 % faster than before, 100 MB download as
fast or faster; bulk TCP over 127.0.0.1 (`netbench lo`) about 14 % slower than with
hand-off calls (the calls of the sender and the receiver now overlap on two CPUs and
contend for net-server's one thread). linux-server's net-server calls are queued calls now (wave 5's `SVC_CALL_HANDOFF` is
no longer used by it; the bit still works).

**A direct call to a Linux service**, `SYS_SVC_DCALL` (70) `(svc, op, in, in_len, out,
out_cap)` (`src/lx/dcall.rs`, `hydra_rt::svccall::dcall`): a forwarded call that comes from a
service. The kernel builds an `LxCall` with `nr = LX_DCALL_NR` (0x6800), `args = [op, in, out,
in_len, out_cap, from]`, `svc`, `from_svc`, `dcall_op`, `on_behalf`; copies `in` into the
target worker's copy area; and uses the target host's request table and its direct switch.
The callee answers with `SYS_LX_REPLY_RECV` (pending answers and `SYS_LX_COMPLETE` work as
for Linux calls); up to `out_cap` bytes it leaves for `out` come back. Workers make it on the
lock-free path (`fast_entry`); other service threads through the ordinary path.

- **Delegation:** a worker's dcall made while it serves request R carries R's caller's
  identity (from this CPU's identity cache, or the task) and `on_behalf = R`. While the dcall
  is being served, the callee may use R in `SYS_LX_READ`/`WRITE` and `LX_OBJ_INSTALL`/`FD`
  (`dcall::may_use`). The caller cannot choose either.
- **Call order** (no cycles): by rank, test 1 < vfs 2 < {ipc, net, display, input, sound,
  tty, sec} 3 < proc 4 < linux 5; only downward edges are allowed (`-EPERM` otherwise), plus
  what the supervisor adds with `dcall::allow`. The null operation is allowed on every edge.
  A call to the caller's own process needs an idle worker there (`-EAGAIN`), so a pool never
  waits for itself.
- **Posts:** `SYS_SVC_POST` (71) `(svc, op, data, len <= 16)` appends `LX_NOTE_POST` (8) to the
  target host's ring and wakes its main thread.
- **When the callee dies**, its calls in flight fail with `-EIO` (`server_gone`), as all
  forwarded calls.

Tests: `tests/linux/dcall_test.c` (null, echo, delegation, refused edges, two threads; `dct
kill S`: slow calls while svc-test is killed), lxbench `svc_rtt`, `svc_rtt_handoff`,
`dcall_rtt` (linux-server times the calls itself: `LX_NULL_NR` ops 5–7).

## Without the kernel lock (wave 4)

Since wave 4 (Group 10, branch `mk-lxfast`) a forwarded call and the worker's answer run
**without the kernel lock**: the system call entry (`arch::syscall`) hands every forwarded
call of a Linux thread without a tracer or seccomp filter, and every `SYS_LX_REPLY_RECV`,
to `lx::fast_entry` before it would take the lock. Two threads on two CPUs then forward at
the same time (before, the lock made them take turns: two threads were slower per call than
one).

| What | Protected by |
|---|---|
| The request table, the worker list, the copy buffers | The table's spin lock (`LX`; interrupts off; TLB flush requests served while waiting) |
| Task states and the switch | The scheduler lock, once per switch (`Scheduler::direct_call`) |
| The caller's identity (IDs, capabilities, groups) | A per-CPU cache, valid while `compat::linux`'s identity epoch is unchanged |
| The copy-in table's user memory | Nothing (wave 6): copied straight through the caller's own address space with fault fix-ups; a page not there yet is faulted in under the kernel lock, the table's lock let go |

**Why no answer or wake-up is lost:**
- an answer, a failure, or a delivery to a worker is marked under the table's lock, and
  the waiter woken after it;
- a waiter blocks only under that lock after seeing nothing (and a caller re-checks for a
  signal after blocking, under the scheduler lock, so a signal posted meanwhile wakes it);
- the direct switch blocks the switching task only if a flag is still clear when the
  scheduler lock is held: for a worker, "a call was delivered to me" (`HAS_WORK`); for a
  caller, "my call was answered" (`REQ_DONE`). On two CPUs a worker may take and answer a
  call before its caller gets to the switch.

**Why no task runs twice or on a freed stack:**
- a task switched away from without the kernel lock is marked `nobkl_wait`, and only those
  may be resumed by a CPU without the lock (everything else resumes only where the lock is
  held, as before);
- a CPU switching away from a task stays on that task's kernel stack until its trap
  epilogue has moved the `iretq` frame into its own per-CPU block (`PerCpu::leaving`); no
  other CPU resumes, or frees, that task until then;
- a task another CPU still runs is never picked, even when it is ready (it blocked itself
  and was woken before it yielded).

Anything slow on the way takes the kernel lock first: a page of a copy-in argument to fault
in, a signal for the caller (delivered the ordinary way on the way out), a task that was
killed meanwhile, a call during a driver call's hand-off (the ordinary path).

**Step 2's calls** (after the wave 4 merge) carry more than their arguments: the server
object of the descriptor in `args[0]` (`T_FD0`) or in the bpf attribute block's first u32
(`T_FDAT1`), the IPC namespace (`T_IPC`), the umask (`T_UMASK`). The lock-free path gathers
them too: the IPC namespace comes with the per-CPU identity (unshare, setns and execve bump
its epoch); the descriptor table is taken with `try_lock` (busy: the ordinary path, since
its holder may be in a driver call) for the object and the umask. The object's reference
is held until the answer, as on the ordinary path, so a `close` on another thread cannot
overtake the call; a last reference (a close came meanwhile) is dropped under the kernel
lock.

**The path under the kernel lock** (traced or seccomp-filtered callers, `read`/`write`/
`ioctl` on server objects through `call_obj`) waits the same lock-free way and takes the
kernel lock again afterwards. A caller blocked as needing the lock could otherwise never be
switched back to directly by a worker answering without it: it would be woken through the
scheduler every time (that made step 2's calls 3 to 10 times slower at the merge).
`linux prof show` prints a `[prof] lx:` line: calls forwarded, on the lock-free path,
queued, failed, and answers switched straight back or woken the ordinary way.

**Why no FPU state moves:** the direct switch only ever resumes tasks that blocked at one of
`src/lx`'s own yield points (`lx_yield`, `switch_to_task`), whose `asm!` declares every
vector and x87 register clobbered (`clobber_abi("sysv64")`), so the compiler keeps nothing
there across them; the user's FPU state is on the system call's stack and comes back at
`sysret`. If the fast path does not apply (a driver call's hand-off in progress, a caller
to resume first, the target not ready), vector 0x82 returns at once and the task yields
the ordinary way.

**When no worker is idle**, the call is queued and the caller sleeps; the next worker to
answer a call takes it instead of going idle (and then wakes that call's caller normally).

**Signals:** a queued call is withdrawn (`-EINTR`); a call being served gets
`LX_CALL_INTERRUPTED` in its page; a pending call's server gets an `LX_NOTE_INTERRUPT`
notification and may answer `-EINTR`.

## The copy-in/copy-out table (wave 4)

Without it every pointer argument costs the server a client memory call (below), about one
system call each. With it, the kernel copies the pointer arguments a forwarded call is known
to have into the worker's syscall page at trap time, and copies back what the server leaves
there for output after the answer.

**Page layout:** `0x000` the `LxCall`, `0x200` an `LxCopy` header, `0x400..0x1000` the copy
area (3 KiB). `LxCopy` (`src/ipc/protocol.rs`), per argument `i`: `in_off[i]`/`in_len[i]`
(where the bytes of `args[i]`'s pointer are, and how many; 0: not copied), `out_off[i]`/
`out_cap[i]` (room for output to that pointer; 0: none), `out_len[i]` (written by the server:
how many bytes the kernel copies back).

**The table** is `src/lx/copy.rs`: `describe(nr, &args)` gives, per call, what each of the
six arguments is: `Str(max)` (a NUL-terminated string), `In(len)`, `Out(len)`, `InOut(len)`,
with `len = fixed + mul * args[arg]`. Multiplexed calls choose by an argument (keyctl by its
operation). Today: `add_key`, `request_key`, `keyctl` operations 1, 2, 6, 10, 11, 17 and 31.

**Rules:**
- a NULL pointer is never copied and never faults: the server decides;
- a non-NULL input pointer that faults gives `-EFAULT` at once, without the server;
- what does not fit (a string without its NUL within its limit, a buffer larger than what is
  left of the 3 KiB) is not copied, and the server uses the client memory primitives;
- output is copied after an immediate answer only; a copy-out that faults makes the result
  `-EFAULT`. A call answered `LX_REPLY_PENDING` must copy what it needs out of the page first
  and write its output with `SYS_LX_WRITE` (the page is reused meanwhile);
- queued calls get the same copies (kept with the request in kernel memory).

**Server side:** `Cx::copy_in`, `Cx::user_cstr` and `Cx::copy_out` (`linux-server/src/
client.rs`) look in the page first (the pointer must equal an argument the kernel copied, or
gave output room to) and fall back to the primitives by themselves. Moving a call to the
table means adding its arm to `describe`; the code serving it does not change.

**Cheaper copies (wave 6, Group 22).** The forwarding path runs in the caller's own
address space, so the kernel copies straight from and to the user addresses, as Linux's
`copy_from_user` does, instead of locking the address space and walking the page tables
for every piece:
- the copying instructions are two small assembly routines in `src/lx/copy.rs`
  (`hydra_uaccess_copy`: `rep movsb`; `hydra_uaccess_str`: a byte loop up to the NUL);
- a page fault on one of them never reaches the ordinary page-fault handler: the trap entry
  (`hydra_exception_handler`, before it takes any lock) finds the faulting instruction in
  the fix-up table (`arch::idt::uaccess_fixup`) and resumes at the routine's fix-up label,
  which returns how far the copy got;
- the caller then faults the page in the ordinary way (`copy::fault_in`: demand paging,
  copy-on-write, file pages, under the kernel lock) and tries again; a page that cannot be
  faulted in, or faults again at once, is `-EFAULT`. Pointers are checked to be user
  addresses first (`is_user_range`); supervisor write protection (CR0.WP) makes a write to a
  read-only (copy-on-write) page fault as from user mode;
- the copy-in is made when the call is placed (`lx::place`), under the request table's
  lock, **straight into the idle worker's syscall page** (an idle worker reads its page only
  after `deliver`); a queued call's bytes go into its slot's buffer, as before. When a page
  is missing nothing has changed yet: the lock is let go, the page faulted in, and the call
  placed again;
- output still goes page → the slot's buffer (under the lock, when the worker answers: the
  page is reused at once) → the caller's memory (the same fix-up copy).

`linux prof show`'s `[prof] lx:` line ends with the copies' faults fixed up and pages
faulted in.

Measured with `tests/linux/cpbench.c` (every case timed in short interleaved bursts, so the
host's noise hits all alike; the fastest burst of 300, ns per call; Group 16's stub calls of
`tools/vfsbench/prototype.patch` built in; three VMs each, base ba75050 and wave 6,
alternating, 2026-11-19, a busy host):

| Call | Over the null forward, base | Wave 6 |
|---|---:|---:|
| `stat` stub (a 14-byte path in, 144 bytes out) | +678 .. +964 | **+418 .. +462** |
| `read` stub, 256 bytes out | +572 .. +849 | +369 .. +435 |
| `read` stub, 4 KiB out (through `SYS_LX_WRITE`) | +1119 .. +1512 | +903 .. +991 |
| `add_key` (two strings and 16 bytes in, plus the key work) | +2533 .. +2965 | +2195 .. +2267 |
| `keyctl` DESCRIBE (256 bytes out, plus the key work) | +2184 .. +2682 | +1954 .. +2065 |
| the null forward over `getpgrp` | +1944 .. +2228 | +1997 .. +2017 |

So a path call (`stat` stub) adds +2.43 .. +2.46 µs over `getpgrp` (base +2.62 .. +3.19):
inside Group 16's target of +2.5 µs. What is left of the pointer cost is mostly the server's
own work (the stub's lookup allocates the path).

## Client memory

| Primitive | Number | What it does |
|---|---|---|
| `SYS_LX_READ(id, addr, len, buf)` | 54 | Copies `len` bytes at `addr` of request `id`'s caller into the server's `buf` |
| `SYS_LX_WRITE(id, addr, len, buf)` | 55 | The other way |
| `SYS_LX_READ_STR(id, addr, max, buf)` | 56 | A NUL-terminated string (its length; `-ENAMETOOLONG` without a NUL in `max` bytes) |
| `SYS_LX_PROC_INFO(tgid, out)` | 57 | A process's `[ppid, uid, euid, suid, gid, egid, sgid]` |

They name the *request*, not the process: the server can reach only processes whose calls it
is serving (delivered or pending). The kernel faults each page in as the caller would
(`Mm::prefault`: copy-on-write, file pages from the page cache) and copies through its direct
map; an address outside user space, unmapped, or not writable for a write is `-EFAULT`, and
the server's own buffer is checked the same way. At most 1 MiB per call.

All `SYS_LX_*` calls are allowed only to the tasks of the service registered on endpoint
`0x29` (`-EPERM` otherwise).

## Server-object descriptors (step 2)

A *server object* is an open file whose state lives in linux-server: a message queue
descriptor, a bpf map, program, link or BTF object, and from step 3 on sockets and pipes. The
descriptor table stays in the kernel (design, section 7.1).

```text
 Linux process                kernel                                 linux-server
 fd 5 ──> FileDescriptor::Device(ServerObject { slot 17, gen })      slot 17 -> its object
            │ dup/fork/SCM_RIGHTS share the Arc; the last drop ──── LX_NOTE_CLOSE(17) ──> frees it
            │ mq_timedsend(5,..), read/write/ioctl(5,..) ─────────── LxCall.obj = 17 ──────> serves it
            │ poll/select/epoll read the readiness word  <───────── window 0x21000 + 16*17 (server writes)
            └ waiters sleep on the object's wait queue   <───────── doorbell: changed bitmap + SYS_SVC_SIGNAL
```

- **The descriptor** is `FileDescriptor::Device` holding a `crate::lx::obj::ServerObject`
  (`CharDevice::as_server()` tells it apart). It names the server's *slot* (`0..2048`) and the
  server's generation. `dup`, `dup2`, `fork`, `SCM_RIGHTS`, close-on-exec and process exit
  share and drop it like every other descriptor; when the last reference goes, `Drop` posts
  `LX_NOTE_CLOSE(slot, kind)` to the notification ring, exactly once. The server reuses the
  slot only after that.
- **Calls on it:** a moved call that takes a descriptor first carries the object's slot and
  its `O_NONBLOCK` (`LxCall::obj`, `obj_flags`). `read`, `write`, `readv`, `writev` and
  `ioctl` on a server object are forwarded as they are (`lx::call_obj`, hooked in
  `vfs::stream_io` and the `ioctl` dispatcher), with user pointers: the server copies with
  the client memory primitives. The kernel holds the descriptor while the call is in flight,
  so a `close` on another thread cannot overtake it. `fstat` is answered in the kernel (mode,
  owner from the install, the size from the readiness slot); `fcntl(F_SETFL, O_NONBLOCK)`
  sets the kernel object's flag, which the next call carries.
- **Readiness without a call:** the server keeps one 16-byte slot per object in its window at
  `LX_OBJ_OFF` (0x21000): `[u32 poll bits, u32 edge count, u64 size]`. `poll`, `select`,
  `epoll` and aio's poll read the word (`CharDevice::poll_events`) without asking the server.
  When the server changes words it sets the slots' bits in the changed bitmap at
  `LX_OBJ_CHANGED_OFF` (0x29000, atomic or) and rings once per call
  (`SYS_SVC_SIGNAL(0x29, LX_SIGNAL_OBJS)`); the kernel's hook takes the bitmap (atomic swap)
  and wakes each marked object's wait queue. The **edge count** grows when bits are added or
  something new happens (a message arrives, room is made): edge-triggered epoll reports a
  watch again only after it changed (`CharDevice::edges`), as Linux's wakeups do.
- **A restarted server** starts a new generation: objects of the old one poll as
  `POLLERR | POLLHUP`, their calls fail with `EBADF`, their closes are not told to the new
  server, and their waiters are woken. (The crash policy ends every Linux program anyway.)

| `SYS_LX_OBJ` (60) operation | What it does |
|---|---|
| `LX_OBJ_INSTALL(id, *LxObjDesc) -> fd` | A new descriptor for the server's slot in request `id`'s caller's table (kind, `O_CLOEXEC`/`O_NONBLOCK`, mode, owner, the name `/proc/<pid>/fd` shows). On failure the server frees the slot itself |
| `LX_OBJ_FD(id, fd)` | `slot \| kind << 32 \| nonblock << 62` of the caller's descriptor `fd` (descriptors inside structures: bpf attributes) |
| `LX_OBJ_SETFL(slot, flags)` | Sets the object's `O_NONBLOCK` (`mq_setattr`) |
| `LX_OBJ_PIN(id, fd)`, `LX_OBJ_UNPIN(token)`, `LX_OBJ_NOTIFY(token, buf, len)` | Keeps one of the caller's *kernel* descriptors for the server and queues a message on it: glibc's `SIGEV_THREAD` netlink socket for `mq_notify` |
| `LX_OBJ_COMM(id, buf, len)` | The caller's `comm` (bpf's `get_current_comm`) |
| `LX_OBJ_FDPATH(id, fd, buf)` | **Temporary** (until the VFS moves): the path of the caller's descriptor `fd` (a bpf cgroup attachment names its cgroup by a directory descriptor) |
| `LX_OBJ_BPF_DEVICE(buf, len)` | The complete list of bpf device programs attached to cgroups (see below) |

**`sig_post`:** `SYS_LX_SIG` (61) `(tgid, sig, code, spid | suid << 32, value)` queues a signal
with its siginfo for a Linux process (a message queue notification: `SI_MESGQ`). It is
delivered with the handlers the kernel keeps and interrupts a forwarded call the target waits
in, like any signal. A thread notification (`SIGEV_THREAD`) is glibc's: a message on the
netlink socket it passed, which the kernel keeps for the server (`LX_OBJ_PIN`, `LX_OBJ_NOTIFY`).

**Blocking calls do not tie up the workers:** a call that must wait (`mq_timedreceive` on an
empty queue, `mq_timedsend` on a full one, `semop`, `msgsnd`, `msgrcv`) is answered
`LX_REPLY_PENDING` and kept by the server with its parameters; the worker serves other calls.
The call that unblocks it completes it (`SYS_LX_COMPLETE`, after writing a received message
into the waiter's memory: the client memory primitives work on pending calls), the main thread
completes timeouts (it sleeps until the earliest deadline), a signal completes it with
`EINTR` (`LX_NOTE_INTERRUPT`), and a process exit drops its waiters. Sixteen threads blocked in
`mq_receive` on 4 workers do not hold up other forwarded calls (`srvobj` test). A signal that
arrives while the call is still being served is told to the server when it answers "pending"
(a step-1 gap: the caller had already marked the call and never told the server).

**System V semaphore undo at exit:** the kernel's `LX_NOTE_EXIT` reaches the server through
the ring, in order with the calls: a process's `SEM_UNDO` adjustments are applied (and the
waiters they release completed) before any call made after the exit is served.

**bpf device programs** are decided in the kernel: `bpf::device_check` runs inside the kernel's
`open` and `mknod` paths, where it cannot ask the server. Whenever the attached device programs
change, the server hands the kernel the whole list (`LX_OBJ_BPF_DEVICE`); the kernel checks each
program again and runs it with its own interpreter (`bpf::set_server_device_programs`). A device
program that uses maps (they live in the server) is refused at attach (`EINVAL`); systemd's
`DeviceAllow=` programs use none. Seccomp filters are classic BPF in `seccomp.rs` and stay in
the kernel; no socket filter runs eBPF.

## Unix sockets, pipes and event descriptors (step 4)

Wave 5, Group 13 (branch `mk-lxunix`) moved the descriptors the desktop uses most into the
server: Unix sockets (D-Bus, Wayland), pipes, eventfd, timerfd, signalfd and pidfd. Each is
a server object (above); the kernel keeps the descriptor table, `poll`/`select`/`epoll`
read the readiness words, and `lx=kernel` sends every call back to the in-kernel code
(`src/compat/linux/unix.rs`, `fs/pipe.rs`, `eventfd.rs`, `timerfd.rs`, `signalfd.rs`,
`pidfd.rs`), which stays until a later step deletes it.

| Server module | Calls | Object kind |
|---|---|---|
| `pipe.rs` | `pipe`, `pipe2`, FIFOs (`open` of an `mkfifo` node: `LX_KCALL_FIFO`); `read`/`write`/`readv`/`writev`, `FIONREAD`, `F_GETPIPE_SZ`/`F_SETPIPE_SZ`, `tee`; `splice`/`vmsplice` through them; `/proc/self/fd/N` re-open | `LX_OBJ_KIND_PIPE_R`/`_W` (one slot per end) |
| `unix.rs` | `socket`/`socketpair(AF_UNIX)`, every socket call on them, `read`/`write`, `FIONREAD`/`SIOCOUTQ`, `/proc/net/unix` | `LX_OBJ_KIND_UNIX` |
| `eventfd.rs` | `eventfd`, `eventfd2`; `read`/`write` | `LX_OBJ_KIND_EVENTFD` |
| `timerfd.rs` | `timerfd_create`, `timerfd_settime`, `timerfd_gettime`; `read` | `LX_OBJ_KIND_TIMERFD` |
| `signalfd.rs` | `signalfd`, `signalfd4`; `read` | `LX_OBJ_KIND_SIGNALFD` |
| `pidfd.rs` | `pidfd_open`, `clone(CLONE_PIDFD)`, `SO_PEERPIDFD` | `LX_OBJ_KIND_PIDFD` |

**Routing.** `pipe`, `pipe2`, `eventfd`, `eventfd2`, `pidfd_open`, `timerfd_*` and
`signalfd*` are table entries (`lx::MOVED_STEP4`; the calls taking a descriptor carry its
object with `T_FD0`). `socket`/`socketpair` go by address family and the socket calls by
descriptor (Group 12's routing, `T_FAMILY`/`T_BYFD`; AF_UNIX is in `MOVED_FAMILIES`).
`read`, `write`, `readv` and `writev` are routed by descriptor too (`BYFD_IO_NUMBERS`): a
call on a kernel descriptor pays one bit test of the table's server-object bitmap; one on
a server object takes the lock-free path. (When that test cannot be made, for example for
a seccomp-filtered program, `vfs::stream_io` forwards the call under the kernel lock as in
step 2.) `ioctl` and `fcntl` stay on the kernel-lock path (`FIONBIO`, `FIOCLEX`, `F_SETFL`
are kernel descriptor state); `F_GETPIPE_SZ`/`F_SETPIPE_SZ` are forwarded from there with
the kernel's own call number `LX_KCALL_FCNTL`.

**Blocking.** A `read` of an empty pipe, a `recv` with nothing queued, a full `write`/`send`,
an `accept` with nobody connecting and a timerfd or signalfd `read` with nothing to give
answer "pending". The call that unblocks them completes them: it writes the bytes straight
into the waiter's memory (`SYS_LX_WRITE`, the waiter's `iovec` kept from its call), installs
its descriptors, and answers `SYS_LX_COMPLETE`. A completion that arrives before the
worker's "pending" answer is kept (Group 12's fix, `Req::early`). A signal answers
`ERESTARTSYS`, so `SA_RESTART` restarts the call as on Linux (a writer that wrote part gets
its count). A write to a pipe or socket nobody reads posts `SIGPIPE` (`sig_post`) and
fails with `EPIPE` (not with `MSG_NOSIGNAL`).

**Kernel calls made on the program's behalf.** `clone(CLONE_PIDFD)` asks the server for the
pidfd (`LX_KCALL_PIDFD`), the `/proc/self/fd/N` re-open of a pipe for a new end
(`LX_KCALL_REOPEN`), both with `lx::call_plain`/`call_obj` from the system call that needs
them. `splice`, `vmsplice` and `sendfile` already worked through the program's own
`read`/`write` calls (`nested`), so a server pipe needs nothing more; `tee` between two
server pipes is one forwarded call. When the kernel itself moves bytes to or from a server
object (io_uring's registered eventfd), `ServerObject::read/write` make a *kernel-buffer*
call: `args[1]` is `LX_KBUF_ADDR`, the bytes travel in the syscall page's copy area
(`LX_OBJ_FLAGS_KBUF`: never pending, no `SIGPIPE`); io_uring's eventfd is written from a
kernel task (`obj::write_later`), since completions are posted under the ring's lock.

**FIFOs.** Opening an `mkfifo` node (after the kernel's permission, Landlock and mount
checks) asks the server for a pipe end found by the node's inode (`LX_KCALL_FIFO(ino,
flags)`): a reader's open waits for a writer and a writer's for a reader (answered pending,
installed when the other side comes), `O_NONBLOCK` lets a reader go on and fails a writer
with `ENXIO`, `O_RDWR` is one end that reads and writes (`LX_OBJ_KIND_PIPE_RW`). With
`lx=kernel` the kernel's own pipes do the same (`vfs::open_fifo_kernel`; `O_RDWR` gives the
read end there). Before, a FIFO opened as an empty regular file.

**pidfd.** The server keeps the object and makes it readable when the process ends
(`LX_NOTE_EXIT`); the kernel reads the process back from the descriptor (`LxObjDesc::tag`,
`ServerObject::tag`) for the calls that act on it and stay in the kernel:
`pidfd_send_signal`, `pidfd_getfd`, `waitid(P_PIDFD)`, `setns`, `process_madvise`.

**signalfd.** The server keeps the mask; reading takes signals with **`sig_take`**
(`SYS_LX_SIGTAKE`, native 63: the lowest pending signal of the mask for the request's
caller, its thread's first, as one 128-byte `signalfd_siginfo`). The kernel answers `poll`
on a signalfd itself from the process's pending signals (`LX_OBJ_SIGMASK` gives it the
mask), since posting a signal already wakes the process's waits; a blocking read with
nothing pending is looked at again by the main thread at every tick.

**timerfd** arms **`timer_arm`** (`SYS_LX_TIMER`, native 62): `LX_TIMER_ARM(cookie,
deadline)` on the kernel's monotonic clock, `LX_TIMER_CANCEL`, `LX_TIMER_NOW`. When the
deadline passes the kernel posts `LX_NOTE_TIMER(cookie)` (the timer tick looks every
10 ms; an idle CPU waits for the earliest deadline the way it waits for precise sleeps, so
the suite's 2.5 ms timerfd ends within its 3 ms bound). Cookies carry their owner in the
top byte (1 timerfd; 3 reserved for Group 12's socket timeouts).

**Unix socket names (temporary `vfs_resolve`, until step 6a).** A path name is a socket node
in the file system, found through its inode (a socket is attached to its node, under any
name the node gets). `bind` and `connect` on a server socket are not forwarded at the trap
(`lx::kernel_first`): the kernel's dispatcher reaches `ServerObject::socket_call`, which
calls `unix::server_call` in the caller's context: `bind` makes the node (mode `0777 &
~umask`, ACL inheritance, Landlock), `connect` checks it is a socket the caller may write to
(`ENOENT`, `ECONNREFUSED`, `EACCES`); the call then carries the node's inode
(`LxCall::ino`). A bind the server refuses afterwards removes the node again. Abstract
names are the server's alone.

**Descriptor passing (`SCM_RIGHTS`, temporary until the descriptor table moves).** The
server never holds descriptors. A send's `SCM_RIGHTS` descriptors are taken into the
kernel's kept table (`LX_OBJ_TAKE(request, [fd -> token, what])`: a reference like a `dup`,
any kind: a regular file, DRM, a memfd, a pipe end, another server object; all or nothing).
The message holds the tokens. The receive installs them in the receiver's table
(`LX_OBJ_GIVE`, with `MSG_CMSG_CLOEXEC`); those that do not fit the control buffer, those of
a plain `read`, and those of a socket closed with its queue full are let go
(`LX_OBJ_DROP`), and `MSG_CTRUNC` is set. `SCM_CREDENTIALS` (with `SO_PASSCRED`) and
`SO_PEERCRED` give the sender's process and effective IDs from its call; `SO_PEERPIDFD`
makes a server pidfd. **Garbage collection:** a socket whose own receive queue holds a
Unix socket cannot be sent (`ETOOMANYREFS`, the kernel's rule), and sockets alive only in
unreadable queues (a socket sent through itself, then closed) are collected as Linux's
`unix_gc` does: candidates are sockets all of whose kernel references are tokens in our
queues (`LX_OBJ_REFS(slot)` equals their count in flight); those not reachable from the
queue of a non-candidate have their queues emptied, and the kernel then drops them. The
main thread collects about once a second, before answering `/proc/net/unix`, and after
256 sockets were sent.

| New primitive | Number | What it does |
|---|---|---|
| `timer_arm` | native 62 `SYS_LX_TIMER(op, cookie, ns)` | A notification at a deadline (`LX_NOTE_TIMER`) |
| `sig_take` | native 63 `SYS_LX_SIGTAKE(id, mask, buf)` | Takes a pending signal of a call's caller as a `signalfd_siginfo` |
| `LX_OBJ_TAKE`/`GIVE`/`DROP` | `SYS_LX_OBJ` 9/10/11 | Descriptor passing: keep any descriptor of a caller under a token, install kept ones in a caller's table, let them go (temporary) |
| `LX_OBJ_REFS` | `SYS_LX_OBJ` 12 | Kernel references to a server object (garbage collection) |
| `LX_OBJ_PROC` | `SYS_LX_OBJ` 13 | Whether a process runs or has exited (pidfd) |
| `LX_OBJ_SIGMASK` | `SYS_LX_OBJ` 14 | A signalfd's mask, for the kernel's `poll` |
| `LxCall::ino` | | The socket node `bind`/`connect` resolved (temporary `vfs_resolve`) |
| `LxObjDesc::tag` | | A value the kernel reads back (a pidfd's process; a pipe's or socket's inode for `fstat`) |
| `MSG_LX_PROC_NET_UNIX` | endpoint request | `/proc/net/unix` |

## Notifications

Events the server must know about go to a ring at the start of its service window
(`LX_NOTES_OFF`): `LX_NOTE_FORK(parent, child)`, `LX_NOTE_EXEC(tid, tgid)`,
`LX_NOTE_EXIT(tgid)` (the last thread ended), `LX_NOTE_INTERRUPT(request id)`, `LX_NOTE_CLOSE(slot, kind)`, `LX_NOTE_TIMER(cookie, deadline)` (step 4). The kernel
appends and rings the main thread (`NOTIFY_LX_NOTES`); the server takes them in order under
one lock and advances the tail. Every call carries the ring position at the time it was made
(`note_seq`), and a worker takes the ring up to there before serving the call: a child's
first `keyctl` can never overtake its fork. A full ring (4096 entries) drops notifications
and counts them (word 2 of the ring header).
In the services built on `svcrt` (wave 10, Group N), a worker that finds another thread taking
the ring spins briefly and then gives its CPU away: the taker may be waiting for another
server (lx-net's main thread closing sockets in net-server), which can then run on this CPU
instead of only on the other one.

## Requests made by the kernel

When the kernel itself needs the server while it may hold locks, it uses an ordinary
hand-off call to the main thread's endpoint (`ipc::service::call`): today only `/proc/keys`
(`MSG_LX_PROC_KEYS`; the caller's groups in, the text out through the window). The server's
other threads may run during such a hand-off (`handoff_participant`), since the main thread
may need a lock a worker holds.

## When linux-server dies: the crash policy

The user's decision (2026-11-17): *every Linux program ends, the supervisor restarts the
server, and the desktop comes back at the login screen; the kernel, the drivers and the
emergency prompt stay up.*

1. The supervisor sees the server's main thread gone (or a worker that died alone:
   `lx::watch` then ends the whole server) and restarts it. Unregistering the endpoint runs
   `lx::on_signal(SIGNAL_GONE)`.
2. Every call in flight (queued, being served, pending) fails at once with `-EIO`, and its
   caller is woken: nothing hangs. The server's remaining threads end.
3. A kernel task `lx-recover` ends every Linux program (every user task with the Linux
   personality; Hydra's drivers, servers and hydra-shell stay), waits for the new server to
   come online, and starts the login screen (SDDM) again if it had been started.

`service kill linux_server` and `service restart linux_server` in hydra-shell run the same
path.

## Restart support for every service (wave 6, Group 21)

Since wave 6 the crash policy above is one of three **restart classes**, chosen per Linux
service (`src/lx/restart.rs`, decisions in `src/lx/restart_policy.rs`,
`docs/linux-services-design.md` section 5):

| Class | When the service dies | Default for |
|---|---|---|
| **EndLinux** | Decision 6, as above: every Linux program ends, the login screen returns | linux-server (while it hosts pieces with unkept state) |
| **FailObjects** | Calls in flight fail with `EIO`; the old instance's objects fail with a per-kind error (pipes `EPIPE`, sockets `ECONNRESET`, device objects `ENODEV`, others `EBADF`) and poll `POLLERR\|POLLHUP`; **new calls wait** for the new instance; programs live | services the supervisor does not configure |
| **Transparent** | Callers wait (at most 30 s; a signal ends the wait with `ERESTARTSYS`); calls that were queued or answered "pending" are sent again; calls being served are sent again only if `restart_policy::idempotent(nr, args)` says so, the others get `EIO`; objects the new instance adopts keep working | lx-sec (keys), later vfs-server, lx-net, lx-proc |

- **The ladder:** a second crash within 30 s of a restart is handled one class lower
  (Transparent becomes FailObjects) and drops the kept state; a third stops restarting the
  service (its calls fail with `EIO`) until `service start` (callers then wait for it again).
  EndLinux keeps its restarts (the supervisor's own limit). `service restart` is not a crash.
- **How callers wait and re-send:** `server_gone` asks `restart::gone(svc)` first; for
  Transparent it completes the requests in flight with the internal results `LX_RESEND`
  (queued, pending) or `LX_RESEND_MAYBE` (being served). The caller's loop in `call_with`
  (next to Group 12's `LX_RETRY`) waits in `restart::wait_online` and sends **its own copy**
  of the call again (same copy-in bytes). A call made while the service is down gets the
  internal `LX_OFFLINE` and waits the same way. Descriptors the dead instance installed for a
  request whose answer was lost are closed before the call is sent again.
- **Kept state** (`SYS_LX_SVC` op `LX_SVC_KEPT(size)`, at most 2 MiB): memory owned by the
  kernel, not the process; the first instance gets it zeroed, later instances the same
  pages; the ladder drops it. hydra-rt's `kept::Kept` is a checked record format
  (magic, layout version, two copies per record with CRC-32C: a torn write leaves the old
  value). No pointers in kept state.
- **Revalidation:** a Transparent service's new instance gets the `(slot, kind, key)` of
  every live object (`LX_SVC_LIST`; `key` = `LxObjDesc::key`, chosen at install), marks the
  ones it cannot rebind dead (`LX_SVC_DEAD`) and adopts the rest (`LX_SVC_ADOPT`) before
  `LX_CTL_ONLINE`; adopted objects keep their readiness words. A service that does not adopt
  gets FailObjects for its objects.
- **The class per service:** the supervisor entry (`ServiceDescriptor::linux_service(svc,
  class, name)`); for tests or as the user's policy, QEMU fw_cfg `opt/hydra/restart.<name>` =
  `transparent|failobjects|endlinux` (`tools/hydra_run.py --restart NAME=CLASS`).
- **Counters:** `linux prof show`'s `[prof] lx:` line ends with "restarts: N calls waited, N
  sent again, N failed" and each service's class, crashes and phase.
- **Test:** `tests/linux/restart_test.c` (`restart SECONDS [svc]`: 8 threads of calls while
  the service is killed from the console); host tests `tests/host/tests/restart.rs`.

## The server program

Step 2 added `obj.rs` (slots, readiness words, the doorbell, the test object), `timeout.rs`
(deadlines of blocked calls; the main thread wakes at the earliest), `mqueue.rs`, `sysv.rs`
(semaphores and messages) and `bpf.rs`, each the kernel's file with the client memory
primitives and the server-object calls replacing the kernel's internals.

`userland/drivers/linux-server` (on `hydra-rt`): `main.rs` starts the workers (`workers=N`,
default 4), registers the endpoint and serves it; `notes.rs` takes the notification ring;
`client.rs` wraps the caller's identity and the client memory primitives; `keys.rs` is the
kernel's `src/compat/linux/keys.rs` with those replacing the kernel's internals; `lock.rs` is
a spin lock that yields. A panic ends every thread of the server (`sys::exit_group`), which
the crash policy then handles.

## Network sockets (step 3, wave 5)

Since wave 5 (Group 12, branch `mk-lxnet`) `AF_INET`, `AF_INET6` and `AF_NETLINK` sockets are
server objects (kinds `LX_OBJ_KIND_INET` 7 and `LX_OBJ_KIND_NETLINK` 8), and linux-server is
net-server's client directly ([net/mod.md](net/mod.md), "Two clients"). The kernel's
`inet.rs`, `sockopt.rs`, `rtnetlink.rs` and `netlink.rs` stay for `lx=kernel`.

```text
 Linux program        kernel (src/lx)                      linux-server                     net-server
 socket(AF_INET,..) -- T_FAMILY: family moved? -----------> socket.rs: by_family -> inet.rs
 recv(fd, ..)       -- T_BYFD: fd a server object? -------> socket.rs: by_kind  -> inet.rs -- MSG_NETS_TCP_RECV -->
 sendmsg(unix fd,..)-- T_BYFD: kernel descriptor ---> the kernel's dispatcher, as before
 poll/epoll         <- readiness word (no call) <---------- obj::set_ready_ev  <- relay <-- event ring + doorbell
```

**Socket routing** (`src/lx/mod.rs`, block "Socket routing"; Group 13 uses it for `AF_UNIX`):
- `socket` and `socketpair` carry `T_FAMILY`: the server answers iff the family in `args[0]`
  is in `lx::MOVED_FAMILIES` (2, 10, 16 since step 3) and the server is online; otherwise the
  kernel's dispatcher runs as before.
- the calls on a socket descriptor (`BYFD_NUMBERS`: 42–52, 54, 55, 288, 299, 307) carry
  `T_BYFD`: the server answers iff descriptor `args[0]` holds a server object (the call then
  carries it as `T_FD0` calls do); a kernel socket, a file or a bad number goes to the kernel.
- the test is cheap: each descriptor table keeps a lock-free bitmap of the descriptors that
  hold a server object (`FdTable::srv_bits`, kept by every method that stores or removes one),
  reached through a per-CPU cache of the caller's table (a `Weak`, valid while the caller's
  identity epoch is). A call on a kernel descriptor costs one bit test and no lock.
- `read`, `write`, `readv`, `writev` and `ioctl` on a socket keep the step-2 path
  (`vfs::stream_io` -> `lx::call_obj`); `FIONBIO`, `FIOCLEX` and the interface queries
  `SIOCGIF*` stay in the kernel (kernel descriptor state, and interface data any descriptor
  may ask for).

**Blocked calls** (`linux-server/src/socket.rs`): a call that must wait answers "pending"
and is kept with what it did so far (bytes a stream send already sent, its deadline). It is
tried again when its socket's readiness changes (net-server's events, relayed by the main
thread) or something local happens (a `shutdown` in another thread, a message queue
notification on a netlink socket), completed at its `SO_RCVTIMEO`/`SO_SNDTIMEO` deadline, by
a signal (`ERESTARTSYS`, so `SA_RESTART` restarts it; `EINTR` with a timeout, as Linux), or
dropped when its process ends. No wake-up is lost: every slot has an event count bumped
before its waiters are tried again, and a call about to wait checks under the waiter list's
lock that the count did not move since its attempt began.

**Net waits** (kernel `src/lx`, "Net waits"): a blocked socket call without a deadline does
not wait in linux-server. The worker registers the net-server handle it waits on
(`SYS_LX_OBJ` `LX_OBJ_NETWAIT`, with the readiness word its attempt saw) and answers
"pending"; the kernel's net-server doorbell hook completes it with `LX_RETRY` and the caller
makes the same call again (`LX_CALL_RETRIED`), so a wake-up costs what it did when the
sockets were the kernel's plus one forwarded call. `LX_OBJ_NETCANCEL` withdraws a wait
(signals, `shutdown` in another thread, process exit). The doorbell reaches linux-server's
main thread only while it keeps waiting calls (`LX_OBJ_RELAY`) or an Internet socket is
watched by `poll`/`select`/`epoll`; turning the relay on makes it catch up from net-server's
event ring.

**Completing a call the worker has not answered yet** (kernel, `lx::complete`): another server
thread may finish a waiting call before the worker's "pending" answer reaches the kernel (the
main thread retried it at once). `SYS_LX_COMPLETE` on a call still being served now keeps the
result (`Req::early`), and the "pending" answer then turns into it. Before this, the completion
was refused and the caller slept forever (a TCP ping-pong between two processes hung within a
few hundred round trips); step 2's blocked message-queue and System V calls had the same race.

**Readiness:** linux-server relays net-server's readiness (design, section 14): the main thread
takes net-server's event ring, maps the handles to its sockets, writes their objects'
readiness words and rings the kernel's doorbell once; `poll`, `select` and `epoll`
(edge-triggered too) read the words without a call.

**Primitives added** (`SYS_LX_OBJ`): `LX_OBJ_NETCHECK` (16: Landlock's TCP port rules for the
request's caller), `LX_OBJ_SIGTHREAD` (17: `SIGPIPE` to the calling thread). A socket call's
`obj_flags` has `LX_OBJ_FLAGS_NETNS` when the caller is in a network namespace of its own.
`/proc/net/tcp`, `tcp6`, `udp`, `udp6` come from the server (`MSG_LX_PROC_NET`, a hand-off
request like `/proc/keys`), since only it knows which socket (inode, owner) holds a
connection. glibc's `mq_notify(SIGEV_THREAD)` netlink socket is now the server's own: the
notification is queued on it directly (`netlink::pin`/`deliver`).

**Copy table:** the socket calls have `describe` arms (socket addresses in, 128 bytes of room
out and the 4-byte length in/out, send/receive buffers, `setsockopt` values, 256 bytes for
`getsockopt`, the 56-byte `msghdr` whole); they are family-independent.

**Crash policy:** killing linux-server ends every Linux program (their sockets with them) and
a restarted server first closes its predecessor's handles in net-server
(`MSG_NETS_CLIENT_RESET`). Killing net-server makes every blocked socket call return an error
(`ECONNRESET` for TCP, `ENETDOWN` for UDP/ICMP), their readiness words read `POLLERR|POLLHUP`,
and new sockets go to the restarted net-server.

## Tests (step 2)

- `tests/linux/srvobj_test.c` (suite test `srvobj`, run after `tlbstress` by
  `scratch/run_suite.py`): a test server object (`LX_NULL_OBJ`: readable/writable on
  command, the doorbell waking an `epoll_wait` in another thread, edge-triggered epoll),
  reference counting (`dup`, `F_DUPFD_CLOEXEC`, a child closing or exiting with a copy,
  close-on-exec across `execve`: the server sees the last close exactly once, counted by
  `LX_NULL_OBJ_CLOSES`), 300 objects at once; message queues under `poll` in another thread,
  `select`, edge- and level-triggered `epoll` (also in a child process), `fstat`,
  `fcntl(O_NONBLOCK)`, 16 threads blocked in `mq_receive` while `keyctl` calls go on, `EINTR`
  and `ETIMEDOUT` on blocked receives. With `lx=kernel` the test-object checks are skipped.
- `srvobj block`: the kill test's load (threads blocked in `mq_receive`, `semop` and
  `epoll_wait` on a queue descriptor).
- The suite's `mqaio`, `sysv` and `bpf` tests, with the forwarding on and switched back.
- `tests/linux/lxbench.c`: `mq_rtt`, `semop`, `msg_rtt`, `bpf_lookup` (root), `poll_pipe`,
  `epoll_pipe`, `poll_mq`.

## Tests (step 1)

- The suite's `keys` and `keyparent` tests, with the forwarding on and switched back.
- `tests/linux/lxfwd_test.c`: the test call, client memory across a page boundary and its
  `EFAULT` cases, a pending call completed by another thread, a signal during a pending call
  (`EINTR`), and 4 processes x 8 threads making key calls and test calls at once (every answer
  checked). `lxfwd hammer N` is the load for the kill test.
- `tests/linux/lxbench.c`: `lx_null`, `lx_null_par2`, `keyctl`, `keyctl_par2`, `add_key`,
  `keyctl_describe`.
- wave 4 additions to `lxfwd_test.c`: the copy table at page edges (strings ending at an
  unmapped page, output crossing into one, read-only output, bad pointers, a payload larger
  than the copy area, a 64 KiB output buffer), and `sigstress` (a 1 ms timer signal while 4
  threads make forwarded calls for 3 s).

## Cost

Measured in KVM with 2 CPUs (details and the breakdown in section 11 of
[linux-server-design.md](../linux-server-design.md)): a forwarded null call costs 4.5 µs
without PCID and 3.4 µs with it, against 0.7 µs for a null call answered in the kernel (the
budget allows 3 µs added: met with PCID). Step 2's moved calls add, per call, against the
in-kernel code of the same build: `mq_send`/`mq_receive` +3.1 µs, `semop` +2.9, `msgsnd`/`msgrcv`
+2.9, a bpf map lookup +4.1 (one client memory call per pointer; Group 10's copy-in table
removes those); `poll` on a server object costs no more than in the kernel (section 12 of the
design). `keyctl` through the server costs 3.5 µs with PCID
(0.7 µs in the kernel). Calls that were not moved are unchanged. Two threads forwarding at
once are not faster than one: the kernel lock still serializes the kernel part of each call.

## lx-sec: keys and bpf in a service of their own (wave 6, X1)

The first piece split out of linux-server (design `docs/linux-services-design.md`, table 9.1
row X1): `add_key`, `request_key`, `keyctl`, `/proc/keys` and `bpf` are served by the
program `userland/drivers/lx-sec` (service id `LXS_SEC`, endpoint `0x31`), on the service
runtime (`hydra_rt::svcrt`). The supervisor starts it as `lx_sec`.

- **One source.** `keys.rs`, `bpf.rs` and `kept.rs` live in `lx-sec/src`; linux-server
  builds the same files (`#[path]`), so `lx.sec=linux` (fw_cfg `opt/hydra/lx`, or
  `tools/hydra_run.py --lx sec=linux`) puts keys and bpf back into linux-server, and
  `lx.sec=kernel` sends them to the in-kernel code. lx-sec exits at start when no service id
  names its endpoint.
- **Restart class Transparent** (Group 21). When lx-sec dies, key calls wait for the new
  instance (the call being served at the crash is re-sent if it is a read-only one,
  otherwise it gets `EIO`).
- **Kept keyrings.** The key table is written to the service's kept-state object
  (`LX_SVC_KEPT`) whenever a call or a process event changed it, before the answer leaves
  the worker (`keys.rs`: the lock guard writes it when the table is dirty). The object holds
  two halves per blob; a new copy goes into the half not in use, with its length, sequence
  and FNV checksum, and a word then names it current (`kept.rs`), so a crash in the middle
  leaves the previous copy whole. A new instance reads the table back before it goes online
  and drops the thread, process and session anchors of processes that ended meanwhile (their
  exit notification went to the dead instance).
- **bpf is FailObjects.** Maps, programs and links of the old instance are gone: lx-sec does
  not adopt objects, so their descriptors fail `EBADF` (`LX_OBJ_FD` answers the stale errno).
  The device programs the kernel was handed (`LX_OBJ_BPF_DEVICE`) are kept too and handed
  over again right after the new instance goes online, attached as by `BPF_PROG_ATTACH`
  (`BPF_PROG_DETACH` on their cgroup removes them), so device control does not lapse.
- **bpf map element commands through the syscall page** (`src/lx/sec.rs`). Their key and
  value pointers sit inside the attribute block. The `T_FDAT1` step reads the block's first
  24 bytes; for a bpf map object it puts the key and value pointers into bpf's unused
  argument words `args[3]`/`args[4]` (cleared first for every bpf call) and their lengths in
  `args[5]`, from the object's tag (`key_size | user_value_size << 32`, set by lx-sec when it
  installs the map's descriptor). The copy table then copies them like any argument, and the
  server's `Cx::copy_in`/`copy_out` find them in the page. The map's descriptor is found
  through the per-CPU cached descriptor table (`byfd_fast`), not the scheduler's lock.
- **Tests:** the suite's `keys`, `keyparent`, `bpf`; `tests/linux/lxsec_test.c`
  (`keep`/`check`: keys kept across a kill; `hammer N S`: key calls while lx-sec is killed;
  `bpfhold`: an old map gives `EBADF`, a new one works; `devset`/`devcheck`: a device
  program still enforced after a restart, then detached).

## lx-net and lx-ipc: sockets and IPC objects in services of their own (wave 8, X2)

The network and IPC pieces left linux-server (design `docs/linux-services-design.md`,
sections 2 and 9.3):

- **lx-net** (`userland/drivers/lx-net`, service `LXS_NET`, endpoint `0x2E`, supervisor name
  `lx_net`, 2 workers): `AF_INET`/`AF_INET6` sockets as net-server's client (`inet.rs`,
  `sockopt.rs`, `netc.rs`), `AF_NETLINK` routing and uevent sockets (`netlink.rs`), blocked
  calls and readiness (`socket.rs`), `/proc/net/{tcp,udp}[6]`. Restart class
  **Transparent**.
- **lx-ipc** (`userland/drivers/lx-ipc`, `LXS_IPC`, `0x2F`, `lx_ipc`, 3 workers): Unix
  sockets, pipes and FIFOs (vfs-server's FIFO redirect lands here), eventfd, timerfd,
  signalfd, pidfd, POSIX message queues, System V messages and semaphores,
  `/proc/net/unix`. Restart class **FailObjects**: the old instance's objects fail with
  their kind's error (pipes `EPIPE`, Unix sockets `ECONNRESET`, the rest `EBADF`), programs
  live; the desktop session, which lives on D-Bus and Wayland sockets, ends.
- **One source, three hosts.** The moved files live in the new crates; each has one glue
  file (`netsvc.rs`, `ipcsvc.rs`: which calls, families and object kinds are its, process
  exits, signals, closes, deadlines, main-thread work). linux-server builds the same files
  with `#[path]` and dispatches through the same glue, so `lx.net=linux` / `lx.ipc=linux`
  co-locate them back (and `lx.<name>=kernel` sends them to the in-kernel copies). The new
  programs build linux-server's small shared files (`obj`, `lock`, `timeout`, `client`,
  `fdio`) by `#[path]`; `obj.rs` takes the doorbell's endpoint and calls the program's
  `on_closed` hook. Routing needed one change: `DEFAULT_ENDPOINTS` in `src/lx/svc.rs`.
- **lx-net's kept state** (`sockkept.rs`): one record per socket in the kept-state object
  (`hydra_rt::kept`, 2048 records of 160 bytes): kind, net-server handles, addresses, flags,
  options (an Internet socket: `InetRec` + `Options::save`; a netlink socket: `NlRec`). The
  kernel object's key is the record's number plus one. A socket writes its record after a
  call or event changed it (it keeps the image it wrote last, so an unchanged socket costs a
  comparison) and clears it when its last descriptor goes.
- **lx-net's restart.** The new instance lists its live objects (`LX_SVC_LIST`), rebuilds
  each socket from its record (others: `LX_SVC_DEAD`), adopts them (`LX_SVC_ADOPT`), asks
  net-server to close every handle of its client tag except the adopted sockets' ones
  (`MSG_NETS_CLIENT_RESET` with a keep list; lx-net's own tag `NETS_CLIENT_LXNET`, so a
  linux-server restart never touches its connections), goes online and catches up on
  net-server's events. A second crash within 30 s resets the kept state (the ladder): the
  sockets then fail and their handles are closed.
- **Calls in flight at a crash** (new kernel words in the worker's page, any Transparent
  service may use them): `LX_CALL_RESEND_OFF` holds the id of the call being served while
  it has had no effect, so the kernel re-sends it instead of failing it with `EIO`; lx-net
  sets it for receives, accepts and sends on Internet sockets and clears it just before it
  takes data or a connection from net-server or hands it bytes. `LX_CALL_PARTIAL_OFF` holds
  `(id, answer)` once a stream send handed some bytes on: the caller then gets that short
  count. A blocking stream send that sent part of its bytes and would wait answers the short
  count at once in lx-net (a waiting call is re-sent from the start after a restart).
- **Across services:** `mq_notify(SIGEV_THREAD)` in lx-ipc keeps lx-net's netlink socket
  through the kernel (`LX_OBJ_PIN` now accepts another service's object; `LX_OBJ_NOTIFY`
  forwards the cookie to its owner as `LX_KCALL_NLDELIVER`). net-server's doorbell goes to
  `LXS_NET`'s host; a Transparent restart keeps `WATCHED_NET`.
- **Tests:** the suite (sockets, pipes, FIFOs, epoll, scmrights, netlink, procnet, mqaio);
  `tests/host-w8-x2` (kept records); host-t30 (split routing, re-send marks, partial
  answers, pins across services); kill scripts `scratch/x2_killnet.sh`,
  `scratch/x2_killipc.sh`, `scratch/x2_kde.sh`.

## The file service's calls (wave 7, Group 7-2)

Design: `docs/vfs-design.md` sections 5-7. vfs-server (`userland/drivers/vfs-server`,
`LXS_VFS`, endpoint 0x2D; core by Group 7-1) answers the path calls and the metadata calls on
open files; the kernel keeps the descriptor table as a table of handles (`src/lx/fileh.rs`).

- **A handle is the kernel's `FileDescriptor::Vnode`** (`OpenFile`: pool object = page-cache
  object, offset or `getdents64` cookie, open flags, mount, shown path). vfs-server keeps no
  per-open state: `open` makes the handle with `LX_FH_INSTALL` and forgets it; a call on a
  handle carries its data (`LxCall::at_ino`, `fh_off`, `fh_flags`). `read`, `pread`, `lseek`,
  `mmap`, `fstat`, **writes**, `close`, `dup`, `fcntl` and `poll` stay in the kernel and work
  while vfs-server is down.
- **Claims:** vfs-server claims each number it serves at start-up (`SYS_LX_OBJ(LX_FH_CLAIM,
  nr, 1)`); only claimed numbers get a routing entry (bit `fileh::T_VFS`). `calls=0` /
  `calls=4,6,...` among vfs-server's arguments narrow that (wave 9, 9-C: neither
  `lx.vfs=kernel`, which is gone, nor `lx=kernel` zeroes them any more). Claimed today (32): stat, lstat, newfstatat, statx, access, faccessat,
  faccessat2, readlink, readlinkat, statfs, open, openat; chmod,
  fchmodat, fchmod, chown, lchown, fchownat, fchown, truncate, ftruncate, utimensat; mkdir,
  mkdirat, symlink, symlinkat, unlink, rmdir, unlinkat, rename, renameat, renameat2.
  `getdents64`/`getdents` are served (`calls/dir.rs`) but not claimed by default: a warm
  `find /usr` took 0.87-0.93 s with them against the kernel's 0.46-0.52 s, 0.44-0.48 s without
  (`calls=...` claims them for tests). The kernel also keeps a call vfs-server would send
  straight back (`fileh::kernel_mask`: foreign roots, mounts, per call Landlock, fanotify,
  inotify, ABAC), without the round trip.
- **The context** each call carries (`fileh::fill`, both forwarding paths): root and working
  directory (inode and mount), umask, the directory descriptors of `*at` calls
  (`at_kind`: AT_FDCWD, file, directory, other), namespaces (`T_FSCTX`) and `fs_flags`
  (Landlock, fanotify, inotify, ABAC, a root/cwd outside the pool or under `/proc`, `/sys`,
  `/dev`, a mount namespace of its own or FUSE mounts).
- **Redirect to the kernel:** a worker answers `LX_REPLY_REDIRECT` with service 0 and the
  kernel's own code answers the same call in the same trap (for any service). vfs-server
  does so before changing anything for what it does not serve yet: walks into `/proc`,
  `/sys`, `/dev`; descriptors that are not pool handles; the `fs_flags` cases; opens that
  create or truncate, `O_PATH`, `O_TMPFILE`, devices, FIFOs, sockets; changes while inotify
  or fanotify watches exist (their events come from the kernel's ZFS client); a new object in a
  directory with xattrs (default ACLs); `utimensat` with "now".
- **Coherence.** Both sides work on the same pool and keep each other's caches current:
  vfs-server tells the kernel what it changed (`LX_FH_CHANGED`: forget names / attributes,
  page cache cut at a size or dropped for an unlinked file); the kernel posts
  `LX_NOTE_FSCHANGE(ino or 0)` to vfs-server's ring for every change it makes (from
  `fs/zfs`'s forget functions), which a worker takes before its next call.
- **vfs-server not online:** while it restarts, every file call waits for it (the ladder's
  30 s; wave 9, 9-C); before it first comes up and after the ladder gave it up, the kernel
  answers.
- Other operations: `LX_FH_SEEK` (a handle's cookie), `LX_FH_INFO`, `LX_FH_CHDIR`,
  `LX_FH_CHROOT` and `LX_FH_REROOT` (for 7-3's `chroot`/`pivot_root`).
- Tests: host-t30 `lx::fileh` (25), `tests/host-w7-37` (result layouts, decisions); the QEMU
  suite with vfs-server serving.
- **Landlock and ABAC (wave 9, Group 6b-3).** vfs-server checks both for the calls it serves
  (`vfs-server/src/policy/`), so `kernel_mask` no longer keeps open, access, the attribute
  changes, mkdir, symlink, unlink, rename and the mount calls of such callers (mknod, link, the
  xattr calls, utime(s), `execve`'s front half and socket nodes still go to the kernel).
  *Landlock:* the kernel keeps the rulesets and domains; each domain has an id that is never
  reused (`LxCall::ll_dom`), and vfs-server keeps a copy per id, fetched once with
  `LX_FH_LANDLOCK` (76). The checks use the pool's `..` chain above the object, as the
  kernel's: vfs-server takes it from parent hints its walks leave (each confirmed by the name
  cache) or from zfs-server. A landlocked open that walks into `/proc`, `/sys`, `/dev` or a FUSE
  mount is the kernel's (its chain is by name there). Truncation refused at the open travels
  with the handle (`LX_FH_NOTRUNC`, bit 30 of the handle flags), so `ftruncate` refuses it.
  *ABAC:* asked of the kernel (`LX_FH_ABAC`, 77; see `docs/abac.md`). A vfs-server restart
  loses only copies, which are fetched again. (`lx.policy=kernel`, the old routing, is gone
  since 9-C.)

## Mount tables for the file service (wave 7, Group 7-7)

- **One owner:** the kernel's `compat/linux/mount.rs` table stays the owner of every mount
  namespace's mounts (the mount system calls stay the kernel's); vfs-server walks with a
  **copy** of the caller's table (`vfs-server/src/kmounts.rs`). Every change moves the
  namespace's generation on (`mount::bump`: after each mount system call, a namespace copy,
  a FUSE mount or unmount of the initial namespace). Each call carries its caller's
  generation (`LxCall::mnt_gen`, set in `fileh::fs_flags_global`); vfs-server takes the
  table again with `SYS_LX_OBJ` op `LX_FH_MNTTAB = 53 (ns, buf, cap)` (`LxMntHead` + one
  `LxMntRec` per slot: tree / tmpfs / kernel-served, `MS_*` flags, parent, mount point,
  root) when its copy is older than the call. Mount numbers are the kernel's
  (`FdTable::root_mnt`, `OpenFile::mnt`).
- **What the walk does with it:** pool trees (binds, the kernel's tmpfs trees, the root) are
  walked by vfs-server; FUSE mounts and named mounts the kernel serves by another path end
  the walk with "redirect to the kernel"; `/proc`, `/sys`, `/dev` under the caller's root as
  before. Read-only mounts (changes, writable opens, `W_OK`), `X_OK` on noexec mounts,
  removing or renaming a mount point, renames across mounts and `statfs` of a tmpfs go to the
  kernel. The caches keep pool objects by object, so a change through one bind is seen
  through every other.
- **What stays in the kernel (`LX_FS_MOUNTS`):** only a table vfs-server cannot walk (a named
  mount whose mount point the kernel could not locate, `MS_NOSYMFOLLOW`), and everything with
  the boot word `lx.vfsmnt=kernel` (the behaviour before; gone since wave 9's 9-C). Exec front halves
  and socket names of callers in a namespace of their own still take the kernel's path
  (`xexec::servable` wants mount 0); the initial namespace's callers with FUSE mounts around
  (all of KDE: xdg-document-portal) are served.
- **chroot** (161) is claimed again; a caller in a user namespace of its own (capabilities not
  carried in `LxCall::caps`) gets the kernel's answer.
- Measured (KDE login, same ISO): served 47,028 / kept 136,069 with `lx.vfsmnt=kernel`;
  served 179,784 / to the kernel 4,894 / kept 730 with the copies.
- Tests: host-t26 `mount` (generations and the view), host-t30 `lx::fileh` (fill, `kernel_only`,
  `LX_FH_MNTTAB`), `tests/host-w7-43` (the copy, walks across it, the walk's leftovers).

## The terminal service (wave 8, Group T)

Design: `docs/display-input-design.md` sections 3.2, 3.6 and 5 (row T of section 7). The
terminals left the kernel for a service of their own, **tty-server**
(`userland/drivers/tty-server`, service `LXS_TTY`, endpoint `0x2C`, two workers and a
console thread). The in-kernel copies (`src/compat/linux/tty.rs`, `pty.rs`) stay as the
switch back: `lx=kernel` or `lx.tty=kernel` (tty-server then idles: it gets no calls and no
keys).

| Piece | Where now | How it is reached |
|---|---|---|
| Line discipline, termios, window size, `ISIG` signals | tty-server `ldisc.rs` | (shared by the two below) |
| Pseudo-terminals (`/dev/ptmx`, `/dev/pts/N`, `/dev/tty` naming one) | tty-server `ttys.rs`, objects of kinds `LX_OBJ_KIND_PTY_M` (67) / `PTY_S` (69) | `open`: `vfs.rs::open_pty_path` -> `lx::console::open_pty` -> `LX_KCALL_TTY` `K_OPEN` (tty-server installs the object, the kernel takes it as the opened file); `read`/`write`/`readv`/`writev` by descriptor (the lock-free path), `ioctl` through `call_obj`, `poll` on readiness words |
| `stat`/`chmod`/`chown` of `/dev/pts/N`, `vhangup` | tty-server | `pty.rs`'s `stat_path`/`setattr_path`/`hangup` -> `K_STAT`/`K_SETATTR`/`K_HANGUP` |
| The console terminal (the Linux programs' terminal on hydra-shell) | its line discipline in tty-server; the descriptors (`ConsoleIn/Out/Err`), the attach state and the keyboard stay in the kernel (`src/lx/console.rs`) | `tty.rs`'s `read`/`write`/`ioctl` -> `K_READ`/`K_WRITE`/`K_IOCTL` (user pointers, the caller's group and session in the header); the VT requests (`VT_*`, `KD*`) stay the kernel's |

**Kernel primitives for tty-server** (`SYS_LX_OBJ` op `LX_OBJ_TTY` = 70, its host only;
sub-op in the first argument):

| Sub-op | What |
|---|---|
| `LX_TTY_CONS_WRITE (buf, len)` | prints tty-server's bytes on the console (output processing done) |
| `LX_TTY_CONS_WAIT (buf, cap)` | waits (at most about 1 s) for keys typed while a Linux program owns the console, or an attach/detach; `buf` = `LxConsState` (generation in/out, session, group, console size) + keys (`u32`: a character, or `LX_CONS_KEY_SPECIAL` + UEFI scan code); `-EPERM` when not forwarded |
| `LX_TTY_CONS_READY (gen, readable)` | whether a console `read` would return (for `poll`; wakes the console's waiters) |
| `LX_TTY_SESS (pid)` | `sid \| pgid << 32` of a process |
| `LX_TTY_PGRP_IN (pgid, sid)` | 0: the group has a member in the session; 1: only elsewhere; `-ESRCH`: no such group |
| `LX_TTY_SIGGRP (pgid, sig)` / `LX_TTY_SIGPROC (pid, sig)` | signals a group / a process (Ctrl+C, `SIGWINCH`, hang-ups) |

**Sessions** stay the kernel's (decision 11). The kernel's `LX_KCALL_TTY` calls carry the
caller's group and session in the header; for a pty `ioctl` that needs them (`TIOCSCTTY`,
`TIOCSPGRP`) tty-server asks `LX_TTY_SESS`. A session leader's exit (`LX_NOTE_EXIT`,
subscribed) gives its pty up. A console reader in a background group gets the internal
answer `LX_TTY_BGREAD` and the kernel posts `SIGTTIN` in its context, as before.

**What changed in behaviour** (Linux's rules, which the kernel copy could not follow):
closing a master that is some session's controlling terminal sends `SIGHUP` and `SIGCONT` to
the session leader and `SIGHUP` to the foreground group (the kernel copy only gave
end-of-file: its last close could run under the scheduler lock); `TIOCSPGRP` on a pty a
session holds refuses another session's caller (`ENOTTY`) and a group of another session
(`EPERM`, `ESRCH` for none); a hung-up slave polls readable and hung up.

**Blocking:** reads with nothing to give and slave writes past 64 KiB of unread output are
answered "pending" and completed by the call that brings bytes or room (signals:
`ERESTARTSYS`; exits drop them). At most 32 console reads wait at once (`EIO` beyond: each
holds a request slot of the service).

**Restarts** (FailObjects, decision 12, design 3.6): pty objects of the dead instance fail
(`ENODEV`, `POLLERR|POLLHUP`), so the shells in Konsole and ssh sessions end and the desktop
stays; console calls in flight fail with `EIO`; while tty-server is down the kernel prints
console writes itself (with `ONLCR`), answers console `ioctl`s with its copy and fails
console reads with `EIO`; the new instance takes the console's attach state from its first
`CONS_WAIT` (a cooked terminal).

**Tests:** host crate `tests/host-w8-t` (line discipline, the pty table, the console
terminal, the kernel's encodings); `ptytest`, `notty`, `stdfd`, `signals` and the whole
suite (every test prints through the console terminal); lxbench `pty_rw` (one process,
slave to master) and `pty_rtt` (two processes ping-pong a byte).

## The kernel's copy of the file code deleted (wave 9, Group 9-C)

- **No switch back for the file service.** `lx.vfs=kernel`, `lx.vfsmnt=kernel`,
  `lx.fuse=kernel`, `lx.policy=kernel` and `lx.tmpfs=pool` are ignored (one boot-log line
  each). `lx=kernel` still moves every *other* service back into the kernel (linux-server's
  families, lx-net, lx-ipc, lx-sec, the device services); the file service stays vfs-server
  (its redirects to a service in the kernel are answered by the kernel's code, as before).
- **Deleted:** the kernel's inotify instances and fanotify groups (`inotify.rs`, most of
  `fanotify.rs`, the `FileDescriptor::Inotify` kind, the kernel-instance event hooks) and the
  kernel's FUSE client (`fuse.rs`' protocol engine, connections, node tables and its
  `/dev/fuse`). What reaches the kernel for them now: `inotify_init*`/`fanotify_init` with
  vfs-server not there (`ENOSYS`), the other notify calls on a descriptor that is no instance
  (`EBADF`/`EINVAL`), a FUSE inode of no vfs-server connection (`ENOTCONN`).
- **Kept, because they are still the implementation, not a copy:** the walk and the path
  calls answer every call vfs-server sends back (creating, truncating, `O_PATH`/`O_TMPFILE`
  opens, devices and `/dev`, mknod, link, the xattr calls, utime(s), read-only mounts, FUSE
  leftovers) and what boot needs before vfs-server; the descriptor table and handles, the page
  cache, tmem, exec, the mount tables (the kernel still decides the initial namespace's FUSE
  mounts), Landlock domains and the ABAC evaluator (vfs-server asks).
- **Measured** (KDE login + Firefox + Dolphin, prof line `vfs to kernel by call`): vfs-server
  served 267,289 file calls, the kernel's code 7,956 (openat 6,064, readlink 777, ftruncate
  451 on non-pool handles, faccessat2 150, readlinkat 142, statx 87, statfs 83, ...).

## What the kernel is after wave 10 (Group 10-C)

Wave 10's closing group deleted every in-kernel copy of a moved piece and every switch-back
word. Measured first (KDE login + Firefox + Dolphin, with a temporary counter of moved call
numbers reaching the kernel's dispatcher and of device opens the kernel's own drivers
answered): 525,978 calls were forwarded and the copies answered nothing; the only moved
numbers that reached the kernel were lx-proc's approved redirects (`prctl` options it leaves
to the kernel, `unshare` after its decision), which are mechanism.

- **Gone:** `keys.rs`, `mqueue.rs`, `inet.rs`, `socket.rs`, `sockopt.rs`, `netlink.rs`,
  `eventfd.rs`, `signalfd.rs`, `timerfd.rs`; the System V semaphore and message queue copy;
  bpf's maps, programs and `bpf()`; the kernel's DRM, evdev and ALSA devices; the kernel's
  terminals (ptys, the console line discipline); the setuid family, `setgroups`,
  `setpgid`/`setsid`/`getpgid`/`getsid`, `setrlimit`/`prlimit64`, `sethostname` and
  `setdomainname` arms; the kernel's TCP/UDP/ICMP socket client in `net/client.rs`; the
  `FileDescriptor` kinds only those copies made (`Socket`, `Inet`, `Unix`, `EventFd`,
  `SignalFd`, `TimerFd`, `PidFd`, `Pty`); `SvcMode`, `all_kernel`, `lx.uring=kernel`;
  linux-server's co-located builds of lx-net, lx-ipc and lx-sec (`lx.<name>=linux`).
- **Kept, as mechanism:** the descriptor table and file handles, the page cache, `mm`,
  `tmem`, exec's back half, the info and identity primitives, the ptrace stop mechanism and
  perf counters (lx-proc decides, decision 35), the `io_uring`/`aio` rings (decision 34; each
  request is routed to its descriptor's owner), readiness words, `lx/shm.rs` (maps System V
  segments after lx-ipc's answer; `shmdt`), the bpf device-program interpreter (lx-sec hands
  device programs over), the device services' kernel side (`ipc/input.rs`' ring and routing,
  `ipc/screen.rs`, `ipc/sound.rs` with the HDA probe and stream programming in `snd.rs`, the
  VT switch hooks in `drm.rs`, the `/sys` input descriptions in `evdev.rs`, `lx/console.rs`),
  the `/dev/mem` family, `/dev/pts` names answered with tty-server's node table, the
  path half of a Unix socket's `bind`/`connect` (`unix.rs`), `/proc/net/dev` and the
  interface ioctls (`rtnetlink.rs`), the emergency prompt, and the `prctl`/`unshare`/
  `setns`/`syslog`/`acct` mechanism lx-proc approves.
- **The kernel walk and path calls stay:** they implement what vfs-server still sends back
  (1,796 calls under KDE: the `/proc` files the kernel keeps, `mount`/`umount2`/`pivot_root`
  in the kernel's mount table, changes inside FUSE mounts through `fuse.rs`) and boot before
  vfs-server runs. `mount.rs` stays (the table's write-through owner, the FUSE ns-0 mirror).
- **linux-server stays, smaller:** it serves `/sys` (cpu ranges, efivars), exec's front half
  (169 under KDE) and Hydra's test calls (`lx_null`, `svc_rtt`, `dcall_rtt` benches). With no
  unkept pieces left it is **FailObjects** now (was EndLinux): a crash fails its calls in flight
  and its open `/sys` files, nothing else. Retiring it would mean moving `/sys` to vfs-server
  or lx-proc, exec's front half to vfs-server and the test calls to svc-test: small, but not
  needed for decision 32 (no copy is left in it).

Kernel `src/`: 118,176 lines at the start of 10-C, about 102,100 after (wave 9 ended at
113,823).

## What the kernel is after wave 11 (Group 11-C)

Measured first, as V1 did (KDE login + Firefox on Wikipedia + Dolphin, `scratch/kmap.sh map`,
the `vfs to kernel by call` counter, plus a temporary print of every send-back in vfs-server
and lx-proc): the base (354a76f) and 11-C give the same picture, **about 280 calls in a whole
session**, all of them path *lookups*, none a change: `openat` ~230-310, `statx` ~40-70,
`access`/`faccessat2` 1-9, `newfstatat` 0-7, `readlink` 1; kept without asking **0**,
unclaimed **0**. What they are:

- lx-proc's redirects to the kernel (~180): re-opening a magic link (`/proc/self/fd/N`, by
  far the most), walks through `/proc/N/root` (the portal's `.flatpak-info`/`.linyaps`),
  writes to `oom_score_adj`, `access` of `ns/*`;
- walks relative to a `/proc` directory descriptor the kernel made (`self/mountinfo`,
  `uid_map`/`gid_map`/`setgroups`, `stat` of `ns/*`), and an `O_PATH` open of `/proc`;
- `cgroup.procs` opens (the kernel's cgroup mechanism, by design);
- not in this workload but by construction: a landlocked caller's opens under `/proc` (their
  lexical Landlock chain is the kernel's), changes inside a bubblewrap/flatpak namespace whose
  mounts are kernel `Named` mounts (`LX_FS_MOUNTS`/foreign mounts), a FUSE call that cannot run
  again after the daemon's reply, and every file call once the ladder gave vfs-server up.

So **the kernel walk and the path calls stay** (they answer exactly these), and so does the
kernel's `/proc` text in `compat/linux/fs.rs` (a landlocked open, or a walk from a kernel
`/proc` directory, can name any `/proc` file). Making them dead needs lx-proc to follow magic
links and walk from kernel-made `/proc` directories, and vfs-server to decide bubblewrap's
named mounts and Landlock's lexical checks: wave 12 material, not a deletion.

**Deleted (dead by construction):** `fileh::notify_init_wait` and its callers' waits
(inotify/fanotify inits before vfs-server's first start): vfs-server now claims its numbers
*before* it goes online, and a call made before a service is online waits for its first start
(`lx::restart::first_start`, below), so the kernel's inotify/fanotify init path is reached only
when vfs-server never claimed them (it answers `ENOSYS`).

**Startup (11-C):** a Linux service's first start is not a restart. The supervisor marks it
(`first_start`); until it is online its callers wait (at most 60 s from its start, one log
line `[lx] a call waits for service N, which is still starting`), also for numbers it has not
claimed yet; a death during the first start is not counted by the ladder; the watchdog does
not ping it before it is online. Wave 11 H's desktop wait for the Linux services is gone.

**Memory (11-C):** the kernel heap is a sixth of the memory (256 MiB..1 GiB; it was half, up to
1 GiB, while KDE + Firefox + Dolphin use 40-60 MiB of it), and when the image stays low (the
firmware loaded it into the 2-4 GiB slot) the free RAM below 1 GiB joins the frame allocator
once the direct map is on (it was never used: a 2.5 GB machine had 1,496 MiB, now 2,503).
tmpfs pages ask the page cache to give back before they are refused, and a program killed for
lack of memory gets a log line (`[mem] out of memory: process N gets SIGBUS ...`).

Kernel `src/`: 102,152 lines after wave 10, 107,335 at 11-C's start (F, P and H added mechanism:
`/proc` facts, FUSE changes, boot logs and hardware), 107,571 after 11-C (+349/-113).


## lx-proc: the process service (wave 10, Group 7b-1)

lx-proc (`userland/drivers/lx-proc`, service id `LXS_PROC`, endpoint `0x30`, two workers) holds the **policy** of process identity; the **data** stay in the kernel (decision 11: credentials, the process table with groups and sessions, limits, namespace ids, UTS names, the log ring, the accounting file).

- **Its calls** (routed by number, `MOVED_PROC` in `src/lx/mod.rs`): `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `setresgid`, `setfsuid`, `setfsgid`, `setgroups`, `setpgid`, `getpgid`, `setsid`, `getsid`, `setrlimit`, `prlimit64`, `prctl`, `unshare`, `setns`, `sethostname`, `setdomainname`, `syslog`, `acct`. The identity *reads* (`getuid`, `getpid`, `getgroups`, `getpgrp`, `getrlimit`, `uname`, ...) stay in the kernel, unchanged in cost (lx-proc can answer `uname` too, from the kernel's names, but a read gains nothing from the extra hop, and a `uname` loop is how programs such as the suite's `cputime` measure system time, which a forwarded call spends in the service). `fork`/`clone`/`execve`/`exit`/`wait` stay kernel mechanism; `clone` with `CLONE_NEW*` applies the namespace ids in the kernel as before.
- **Its rules** (`policy.rs`, pure): the kernel's `src/lx/proc_rules.rs` (wave 9, 7a) built in with `#[path]` (one copy), plus the rest of today's checks, check for check and in the kernel's order (so `lx.proc=kernel` and lx-proc answer the same).
- **The primitives**: `SYS_LX_OBJ` op 75 `LX_OBJ_PROCID` (`src/lx/procsvc.rs`): `SYS_LX_OBJ(75, req, sub, io)` with an `LxProcIo` in lx-proc's memory, for the caller of one of lx-proc's own requests; sub-ops `LXP_TASK_GET`, `CREDS_SET`, `GROUPS_GET/SET`, `PGRP_GET/SET`, `LIMIT_GET/SET`, `ATTR_SET`, `NS_GET`, `NS_FD`, `PID_GET`, `UTS_GET/SET`, `APPROVE`. `PGRP_SET` and `LIMIT_SET` are compare-and-set: the rule runs in lx-proc outside the kernel's locks, the kernel sets only if the state is still what lx-proc saw, else `EAGAIN` and lx-proc decides again (the `setsid` race of several threads gives exactly one winner).
- **Calls whose mechanism needs the caller's context** (`unshare`, `setns`, `syslog`, `acct`, and `prctl` options of kernel mechanism such as seccomp or `PR_GET_AUXV`): lx-proc decides, marks the call approved (`LXP_APPROVE`) and answers with a redirect to the kernel (service 0); the kernel's code then runs without its own permission check (`lx::proc::take_approval`).
- **`prctl` attributes** (`comm`, dumpable, parent-death signal, subreaper) are kernel records (`lx::proc::ThreadAttrs`/`ProcAttrs`), inherited at fork and reset at exec; `/proc/<pid>/comm` and `task/<tid>/comm` show the name. The parent-death signal is stored and read back, not delivered yet.
- **`/proc`** (wave 10, Group 7b-2): lx-proc serves it (`lx-proc/src/procfs/`, moved from linux-server, which keeps only `/sys`): vfs-server redirects a lookup under `/proc` to `LXS_PROC`, whose host is lx-proc. Served: `version`, `uptime`, `loadavg`, `stat`, `meminfo`, `cpuinfo`, the fixed `/proc/sys/...` files, `sysvipc/{shm,sem,msg}` (lx-ipc's info call `LX_IPC_OP_SYSVIPC`, a delegated direct call), the `self`/`thread-self` links, `<pid>/{stat,status,statm,comm,cmdline,maps,environ,limits}` and `task/<tid>/{stat,status,comm}` (stat family, access, readlink, open). Everything else (the magic links `fd/N`, `exe`, `cwd`, `root`; directory listings; `ns/`, `fdinfo`, `auxv`, `cgroup`, `mountinfo`, `net/`, ...) and callers in a PID or user namespace of their own go on to the kernel (redirect to service 0). `environ` comes from `LX_INFO_ARGS` with `LX_INFO_ARGS_ENV` (the `ptrace` read rule, mode 0400), `limits` from op 75's `LXP_LIMIT_GET`.
- **Kernel-held snapshots** (`src/lx/procsnap.rs`): an opened `/proc` file is not a server object: lx-proc makes its text and gives it to the kernel with `SYS_LX_OBJ(LX_OBJ_PSNAP = 80, req, LX_PSNAP_INSTALL, *LxSnapIo)`, which installs a descriptor holding the text and the file's *identity* (`[code, pid, tid, start time]`). `read`/`readv`, `lseek`, `pread`, `fstat`, `poll` and close are the kernel's alone (no round trip, nothing kept in lx-proc). A rewind (`lseek(fd, 0, SEEK_SET)`) or a `pread` at 0 makes fresh text, as Linux's seq_file does: the kernel sends `LX_KCALL_PREMAKE` (0x6793) with the identity, from the reader's context; lx-proc checks the pinned process (start time, else `ESRCH`), makes the text and writes it into the call's kernel buffer (`LX_KBUF_ADDR`, up to one copy area), or hands a longer one over with `LX_PSNAP_FILL`. A rewind only marks the text: `lseek` always succeeds and the next `read` makes the text again (an error such as `ESRCH` comes with that read). The remake is answered with the *opener's* rights (the kernel keeps the opener's user, capabilities, PID and IPC namespace with the snapshot; the info primitives use them for a remake request), as Linux checks access at open. Snapshot text is counted (256 MiB in all, 64 MiB per user) and allocated fallibly (`-ENOMEM`). Because the snapshot and its identity live in the kernel, an open `/proc` file keeps working across lx-proc restarts; a remake during the gap waits and is sent again (`restart_policy::idempotent`).
- **The read rule** (`lx::info::may_see`, one function): itself, `CAP_SYS_PTRACE`, or the same uid/gid triple *and* a dumpable target; a process is not dumpable after `prctl(PR_SET_DUMPABLE, 0)` or after an exec that gained privileges (set-ID to other ids, file capabilities). `access()` of a served file honours its mode and owner (`environ` 0400).
- **Restarts**: lx-proc keeps nothing, so it is Transparent: calls wait for the new instance; a call cut by the crash is sent again when making it twice gives the same result (`restart_policy::idempotent`: the setuid family, `setgroups`, `setpgid`, `setrlimit`, the UTS sets, `acct`, `prctl`'s sets and gets, `syslog`'s reads), otherwise it fails with `EIO`.
- **Switch back**: `lx.proc=kernel` (and `lx=kernel`) sends the calls and `/proc` back to the kernel's copy until 10-C; `lx.proc=linux` is ignored (and `/proc` is no longer in linux-server).
- **Tests**: `tests/linux/procid.c` (suite; `procid loop SECONDS THREADS` for kill tests), `tests/host-w10-proc` (the policy against a model of the primitives), `tests/host-t29` (the primitives).
- **`/proc` tests** (7b-2): `tests/host-w7-40` (which file a path names, the texts, identities), `tests/host-w10-7b2` (the snapshot's position rules); in VMs `procinfo`, `proctest`, `pseudofs`, `procnet`, vfsbench's `proc_*` rows.

### Tracing and observing other processes (wave 10, Group 8-1)

lx-proc also decides who may trace and observe whom; the kernel keeps the mechanism (stopping and resuming tasks, registers and memory, single-step, breakpoints, the perf counters).

- **The rule, one copy**: `src/lx/ptrace_rules.rs` (pure; built into lx-proc with `#[path]`): Linux's `__ptrace_may_access` (its own process always; a service's never; the caller's real ids (`MODE_REALCREDS`) or effective ids (`MODE_FSCREDS`, Hydra's file-system ids) equal to the target's real, effective and saved user **and** group ids, or `CAP_SYS_PTRACE` with the target's user namespace at or below the caller's; then a target that is not dumpable only with `CAP_SYS_PTRACE`), and the decisions of the calls below in the kernel's error order. `lx::info::may_see` (the `/proc` read rule of `environ`, `maps`) is built on it; so are the kernel copy's `extra::may_access` (`/proc/<pid>/mem`, `fd/`, `migrate_pages`, `move_pages`, `process_madvise`). No Yama scope (Hydra enforces none).
- **The calls** (`MOVED_TRACE`): `ptrace` `ATTACH`/`SEIZE`/`TRACEME` and options that suspend seccomp (`CAP_SYS_ADMIN`, tracer not under seccomp), `perf_event_open` (`perf_event_paranoid` 2: kernel-mode counting and whole-CPU events for `CAP_PERFMON`/`CAP_SYS_ADMIN`; another task by the read rule, `EACCES`), `process_vm_readv`/`writev` and `pidfd_getfd` (attach rule), `kcmp` (read rule, both). Every other `ptrace` request is mechanism on an attached tracee: `lx::forward` and `fast_entry` send it to the kernel at once (no hop per `PEEKDATA`/`GETREGS`/`CONT`/`SINGLESTEP`); perf's `read`/`ioctl` are on the event descriptor and never forwarded.
- **Decide, then act**: lx-proc asks `LXP_TRACE_FACTS` (op 75 sub-op 17; `lx::trace::gather`: the call's targets resolved as the kernel will run it, in the caller's PID namespace and descriptor table) and runs the rule; it answers with a redirect to the kernel whose object word is the verdict's key (`ptrace_rules::key`: a hash of every fact, the verdict in the low byte), which the kernel keeps as the caller's approval mark. The kernel's code runs its argument checks as before and, where it checked permission, gathers the facts again (`lx::trace::check`): the same facts give lx-proc's verdict; no mark (`lx.proc=kernel`) or different facts (the target exec'd or changed its ids in between) and the kernel runs the same rule itself. A redirect on the lock-free path is marked per CPU so that the ordinary path does not forward it again. `linux prof show` prints the counts.
- **Dumpable** (the rule's input): `PR_SET_DUMPABLE`; cleared when a credential change alters the effective ids or gains capabilities (`lx::proc::task_creds_set`, both modes, as Linux's `commit_creds`) and by an exec that gains privileges (7b-2); back to 1 at an ordinary exec.
- **Restarts**: lx-proc only decides these calls (the kernel acts after the redirect), so a decision cut by a crash is made again (`restart_policy::idempotent`); an attached tracer never needs lx-proc again.
- **Tests**: `tests/linux/ptperm.c` (suite: the permission matrix; `ptperm bench N` timings; `ptperm step S` single-steps a child and attaches anew every second, for kill tests), `tests/host-w10-81` (the rule, the facts and keys, lx-proc's half against a model of the kernel).

### The rest of `/proc` (wave 11, Group P)

Wave 11 moved what the kernel still served of `/proc` into lx-proc. Measured first (a
temporary counter at the kernel's own `/proc` code, KDE login + Firefox + Dolphin on `/proc` +
the system monitor + console tools + `unshare -pf --mount-proc`): 7,680 calls reached it; after
the move fewer than 512 do in the same session.

- **Directories** (`/proc`, `<pid>`, `task/`, `task/<tid>`, `fd/`, `fdinfo/`, `ns/`, the
  `/proc/sys` directories, `sysvipc/`, `asound/`) are **directory snapshots**: the same
  kernel-held `ProcSnap` as a file's, installed with `LX_PSNAP_INSTALL` and `mode` `S_IFDIR`;
  its text is lx-proc's entry list (`ino`, type, name). The kernel's `getdents64` walks it
  (`CharDevice::getdents64`, no round trip), `lseek(fd, 0, SEEK_SET)` (`rewinddir`) makes the
  list again through `LX_KCALL_PREMAKE`, a read is `EISDIR`. Like the files they survive
  lx-proc's restarts. Every snapshot (file or directory) reports its text's length as
  `fstat`'s `st_size` (dbus-daemon reads `fdinfo` up to it and takes an early end as an error),
  polls readable only, and is edge-triggered once in `epoll` (`CharDevice::edges`, as the
  kernel's own files: a level-triggered `mountinfo` watch spun the SDDM greeter).
- **Walks relative to a `/proc` directory descriptor** (the system monitor opens
  `<pid>/stat` from its `/proc` descriptor; Chromium's sandbox walks `self/...`): such a call
  goes from the kernel straight to lx-proc (`fileh::proc_dirfd_call`: a redirected call with
  `LX_PROC_AT_DIRFD` in `redir_obj`); lx-proc reads the descriptor's path with
  `LX_PSNAP_IDENT` (op 80 sub-op 3) and classifies `base/path`. vfs-server is not asked.
- **Magic links** `fd/N`, `exe`, `cwd`, `root`, `ns/<kind>`: `readlink`, `lstat` and the
  `fd/` listing are lx-proc's, under the `ptrace` read rule (`fd/` of another process now
  works for `lsof`; the kernel's copy showed only the caller's own). `exe` and `root` stay
  readable by everyone, as before (KWin reads a client's `exe`). `stat` of a namespace
  link answers the namespace's inode number (nsfs device 0:4; the kernel's `fstat` of an
  opened namespace descriptor says the same). **Following** a link (`open`, `stat`,
  `execve`, `linkat` of `/proc/self/fd/N`, a walk through `root/` or `cwd/`, opening a
  namespace file for `setns`) needs the handle it names: lx-proc answers with a redirect to the
  kernel, whose handle resolution (`vfs::fd_link`/`desc_link`, `fs::proc_link`,
  `magic_fd_target`, `ns.rs`'s namespace descriptors) is mechanism and stays.
- **Files:** `fdinfo/N`, `auxv` (0400, read rule), `cgroup`, `mountinfo`, `mounts`
  (`/proc/mounts`), `uid_map`/`gid_map`/`setgroups` and `oom_score`/`oom_score_adj` (reads),
  `filesystems`, `swaps`, `locks`, `asound/*`, `sys/kernel/random/{boot_id,uuid}`. Their facts
  come from **`SYS_LX_OBJ` op 82 `LX_INFO_PROCX`** (`src/lx/procx.rs`: descriptor list, link
  texts, `fdinfo` fields, auxiliary vector, control group, namespace inode numbers, threads,
  the caller's visible processes, id maps, OOM numbers, and tables other parts keep, relayed as
  their owners write them). **Writes** to `uid_map`/`gid_map`/`setgroups`/`oom_score_adj` are
  redirected to the kernel's namespace and OOM mechanism.
- **Names that do not exist** (`pressure/*`, `<pid>/ctty`, `smaps`, unknown `/proc/sys`
  files, Dolphin's `.directory`) are answered `ENOENT` by lx-proc (the kernel answered the
  same).
- **Callers in a PID or user namespace of their own** are lx-proc's now: the info primitives
  answer them (`info::may_query` no longer refuses), translate the IDs (`to_caller` for pid,
  tid, parent, group, session, tracer, the `/proc` listing; the user namespace's map for the
  user and group ids) and hide processes outside the caller's PID namespace (`info::in_view`).
- **Still the kernel's `/proc`:** the link resolution above; the sound card's stream files
  (`asound/card0/pcm0p/sub0/status`, ...); `net/*` (the kernel relays
  lx-net's and lx-ipc's tables and keeps the interface ones), `keys`,
  `sys/user/max_user_namespaces`, `<pid>/mem`, `thread-self/` as a directory, `..` walks,
  `chdir` into `/proc`, and boot before lx-proc runs.
- **Tests:** `tests/linux/procrest.c` (suite; `procrest bench N`, `procrest hold SECS` for kill
  tests), `tests/host-w7-40` (classify, identities, texts, the view rule, op 82's rules),
  `tests/host-w10-7b2` (the directory records).
