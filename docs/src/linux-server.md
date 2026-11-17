# The Linux server: forwarding Linux system calls out of the kernel

Since microkernel wave 3 (Group 7, branch `mk-lxfwd`) part of the Linux personality runs in
a ring-3 program, `linux-server`. This is **step 1** of the plan in
[linux-server-design.md](../linux-server-design.md) (section 7): the forwarding machinery,
with one harmless tenant, the key retention service (`add_key`, `request_key`, `keyctl`,
`/proc/keys`). Every later step moves more of `src/compat/linux` into the same server over
the same machinery.

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
`0x6710` (`LX_NULL_NR`). While linux-server is not online the forwarded calls fail with
`ENOSYS`.

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

1. The caller (in its system call, under the kernel lock) writes the call into the worker's
   page and calls `Scheduler::direct_handover(worker)`: the caller becomes blocked and the
   worker ready, **without waking another CPU**.
2. `int 0x82`: the direct-switch vector saves only the general registers and calls
   `direct_switch_core`, which saves the caller and switches to the worker through the same
   `switch_to` tail as the scheduler (the one CR3 write is there). There is no run-queue
   pass, no FPU save or restore, and the worker inherits the caller's timeslice.
3. The worker returns to user mode with the call in its page, serves it, and calls
   `SYS_LX_REPLY_RECV` with the answer: the same steps hand the CPU straight back to the
   caller, and the worker is idle again.

There is no machine-wide stop: today's hand-off (`CallMode::Handoff`) stops every other
system call entry while it runs, but the direct switch is an ordinary switch between two
tasks of one CPU, and other CPUs and other processes keep running (they wait only for the
kernel lock, as every system call does).

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

## Notifications

Events the server must know about go to a ring at the start of its service window
(`LX_NOTES_OFF`): `LX_NOTE_FORK(parent, child)`, `LX_NOTE_EXEC(tid, tgid)`,
`LX_NOTE_EXIT(tgid)` (the last thread ended), `LX_NOTE_INTERRUPT(request id)`. The kernel
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

`userland/drivers/linux-server` (on `hydra-rt`): `main.rs` starts the workers (`workers=N`,
default 4), registers the endpoint and serves it; `notes.rs` takes the notification ring;
`client.rs` wraps the caller's identity and the client memory primitives; `keys.rs` is the
kernel's `src/compat/linux/keys.rs` with those replacing the kernel's internals; `lock.rs` is
a spin lock that yields. A panic ends every thread of the server (`sys::exit_group`), which
the crash policy then handles.

## Tests

- The suite's `keys` and `keyparent` tests, with the forwarding on and switched back.
- `tests/linux/lxfwd_test.c`: the test call, client memory across a page boundary and its
  `EFAULT` cases, a pending call completed by another thread, a signal during a pending call
  (`EINTR`), and 4 processes x 8 threads making key calls and test calls at once (every answer
  checked). `lxfwd hammer N` is the load for the kill test.
- `tests/linux/lxbench.c`: `lx_null`, `lx_null_par2`, `keyctl`, `keyctl_par2`.
