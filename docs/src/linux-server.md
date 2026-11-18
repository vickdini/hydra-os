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
`semop`, `semctl`, `semtimedop`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`; shared memory stays in
the kernel) and `bpf` (321), listed in `lx::MOVED_STEP2`. While linux-server is not online the
forwarded calls fail with `ENOSYS`.

Each table entry is a byte of flags: the server answers the call (`T_SERVER`), `args[0]` is a
descriptor whose server object the call carries (`T_FD0`: `LxCall::obj`), and the call
carries the caller's IPC namespace and umask (`T_IPC`).

**The switch back to the in-kernel code** (for bisecting inside one build): QEMU's
`-fw_cfg name=opt/hydra/lx,string=kernel`, or the word `lx=kernel` in the boot entry's
options. The kernel's copy of `keys.rs` then answers, exactly as before step 1; the test call
returns 0 from the kernel. The boot log says which: `[lx] add_key, request_key, keyctl:
forwarded to linux-server` or `... in the kernel (switched back: lx=kernel)`.

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
| The copy-in table's user memory | The caller's address-space lock (taken with `try_lock`; when busy, the kernel lock first) |

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
