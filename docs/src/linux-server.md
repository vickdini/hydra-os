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
budget allows 3 µs added: met with PCID). `keyctl` through the server costs 3.5 µs with PCID
(0.7 µs in the kernel). Calls that were not moved are unchanged. Two threads forwarding at
once are not faster than one: the kernel lock still serializes the kernel part of each call.
