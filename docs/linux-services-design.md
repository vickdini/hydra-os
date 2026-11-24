# Splitting the Linux layer into services: design (step 0)

Microkernel wave 5, Group 18, 2026-11-18. Base: `host-unit-tests` d0d38ab. No kernel or server code changes in this step: this document, a counting tool (`tools/services/hops.py`) and the profile data it reads.

**Why this document exists.** The user's decision 9 (2026-11-18, [microkernel-plan.md](microkernel-plan.md), "Decisions"):

> "I don't want to merge the file system with linux. They should be separate things in order to be resilient. In fact later on we'll also split linux into different services."

The plan so far assumed one Linux server (decision 4, design C of [linux-server-design.md](linux-server-design.md)). This document lays the foundation for many services: which services, how the kernel routes a call to the right one, how services call each other quickly, how each one restarts, and what this changes in the plan.

**Who this is for:** the user (technical, not a kernel specialist), and the agents of waves 6 and later. Groups 15 ([display-input-design.md](display-input-design.md)) and 16 ([vfs-design.md](vfs-design.md)) revised their designs for decision 9 at the same time and build on the interface of sections 3–5 (posted in `D:\os-mk-shared\NOTES.md`, "Group 18 ~21:10").

## 0. The answer in brief

- **The key idea: identity in the kernel, objects in the services.**
  - Everything that says *who a process is* stays kernel state, copied into every forwarded call: credentials, process and thread ids, the process tree, process group and session, namespace ids, the current and root directory, the umask, the descriptor table (as a table of handles), and signal state.
  - Services own *objects* (files, sockets, pipes, keys, devices) and *policy*.
  - So no service holds anything a program cannot live without. A service that crashes loses only its own objects, and with a little kept state not even those.
- **Why one server is no longer needed.** The first design chose one server mainly because "the descriptor table is the hub" (`poll`, `dup`, `fork`, `SCM_RIGHTS` work across every kind of descriptor). Since wave 4 the kernel keeps that hub: descriptors are handles to objects of any owner, readiness lives in shared words, and `poll`/`epoll` read them without a call. Group 16's design keeps the table in the kernel for good. With that, splitting the services costs almost nothing (below).
- **The service map** (section 2), each a ring-3 program:
  - **vfs-server**: names, mounts, permissions, `open`, every file change (Group 16);
  - **lx-ipc**: Unix sockets, pipes and FIFOs, eventfd, timerfd, signalfd, pidfd, POSIX and System V IPC (wave 5's Group 13 code);
  - **lx-net**: Internet and netlink sockets as net-server's client (wave 5's Group 12 code);
  - **display, input, sound, terminals**: four device services (Group 15);
  - **lx-sec**: keys and bpf (waves 3–4);
  - **lx-proc**: process and signal *policy*, `/proc`;
  - **linux-server** keeps what is not split yet. Until a piece moves out it stays **co-located** there, so the split can go one piece at a time.
- **Routing** (section 3): the kernel sends each call straight to the owning service. A call can be routed by number, by address family, by the descriptor's owner, by an argument, by a device's major number, or by a "redirect" answer. The forwarding table entry grows from 8 to 32 bits and names a service. It is still **one load per system call**. The direct switch and the lock-free path of wave 4 are unchanged; each service gets its own request table, so there is less lock contention, not more.
- **Calls between services** (section 4): a **direct call** that uses the same direct switch as forwarding (target about 2–2.5 µs, against 9–18 µs for today's Queued call from a ring-3 server). It also covers calls to zfs-server and net-server, and adds one-way posts and **delegation** (the callee acts for the original program, with its credentials, which the kernel supplies).
- **Measured, with exact call counts of eight real workloads** (section 4.6, `tools/services/hops.py`):
  - with the kernel routing to owners, the **full split adds 0.3 ms to a 25 s KDE login** over "linux-server + vfs-server" (+0.001 %), and nothing measurable elsewhere;
  - the calls that cross services at all are rare: a KDE login has 431 (each `execve`, each Unix socket `connect`/`bind` by path) plus 2,187 redirects for `/proc`, `/sys` and `/dev` lookups;
  - **routing through linux-server instead** (a relay) would cost 0.5–1.8 % of the KDE login and up to 3 % of `tar`: kernel routing is what makes the split cheap.
- **Restart without ending programs** (section 5): generic support for every service:
  - a **kept-state object** that survives restarts;
  - three **restart classes**:
    - **Transparent**: callers wait and safe calls are re-sent;
    - **FailObjects**: only that service's descriptors fail;
    - **EndLinux**: today's decision 6;
  - a **ladder**: a service that crashes again soon after a restart drops to the next class;
  - **revalidation keys**, so objects survive their owner's restart.
  - **Every Linux service can reach Transparent or FailObjects.** Decision 6 remains only for linux-server while it hosts pieces whose state is not kept yet.
- **What changes in the plan** (section 6):
  - wave 6 builds the foundation: routing, the direct call, restart support, cheaper argument copies, memory objects, and a first split service (`lx-sec`) as proof;
  - wave 7 the file service (Group 16's plan);
  - wave 8 the device services (Group 15's plan) and splitting `lx-net` and `lx-ipc` out of linux-server;
  - waves 9–10 the rest of the file side, the process policy and the last pieces;
  - the FreeBSD/macOS work moves one wave later and becomes per-service front ends instead of one "POSIX core".
- **Cost in kernel size:** the kernel keeps about 2,500 more lines than the first design planned (the process tree and identity as mechanism), so about 11,000 lines of Linux support stay instead of 6,000. That is the price of programs surviving service crashes.
- **Decisions for the user:** section 8 (nine questions). **Step plan:** section 9, with six groups in wave 6.

## 1. What decision 9 changes

### 1.1 The first design's reasons for one server, revisited

Section 4.3 of [linux-server-design.md](linux-server-design.md) gave five reasons for one Linux server (design C) rather than several (design B, MINIX style):

| Reason (2026-11-17) | Still true? | Why |
|---|---|---|
| 1. **The descriptor table is the hub.** `poll`, `epoll`, `dup`, `fork`, `SCM_RIGHTS`, `close_range` work across every descriptor kind; splitting turns each into a multi-server protocol | **No longer** | Since step 2 (wave 4) the kernel's descriptor table is a table of handles to objects owned elsewhere. Readiness is in shared words, `poll`/`select`/`epoll` read them in the kernel, `dup`/`fork`/close-on-exec/`SCM_RIGHTS` move handles, and the last close is a notification. Groups 12 and 13 built sockets and pipes on it in wave 5. Group 16's design keeps the table in the kernel for good. None of these calls needs a protocol between services |
| 2. **Splitting processes from files gains nothing:** a crash of either ends every program anyway | **No longer, if identity stays in the kernel** | It was true when each server held per-process state (cwd, descriptor table, process tree) that programs cannot live without. Section 2.2 keeps that state in the kernel, so each service holds only objects |
| 3. The hot per-thread calls must not leave the kernel | Yes | Unchanged: memory, futex, signal mask, identity, time (design 5.1) |
| 4. The page cache stays in the kernel | Yes | Unchanged: page faults need it without a hop |
| 5. Isolation already comes from the other servers (zfs-server, net-server, drivers) | Partly | True for parsing outside input, but the user asks for more: a fault in the Linux layer must not take the file system down, and vice versa |

The remaining objection to design B was **hops**: `fork` through three servers in a row, `open` of a socket file through two. Section 4 shows that with owner routing in the kernel, almost no call crosses services, and the few that do are cheap with a direct call.

### 1.2 Where today's code assumes one server

`src/lx/mod.rs` (1,528 lines), `src/lx/obj.rs` (498), `src/lx/copy.rs` (441) at d0d38ab:

| Assumption | Where | In this design |
|---|---|---|
| The forwarding table says "kernel" or "server" (`TABLE: [AtomicU8; 512]`, `T_SERVER`) | `mod.rs` `route`, `set_forwarding` | The entry names a service id (section 3.3) |
| One request table, one worker list, one `ONLINE` flag (`static LX: Mutex<Lx>`, `ONLINE`, `REQ_DONE`, `HAS_WORK`, `WORKER_TIDS`) | `mod.rs` | One per service, in a registry |
| One endpoint (`ENDPOINT_LINUX_SERVER`): window, notification ring, readiness area, doorbell hook | `mod.rs` `ctl`, `note`, `on_signal`; `obj.rs` `online` | Per service, the same layouts in each service's own window |
| A server object names a slot and *the* server's generation | `obj.rs` `ServerObject` | It also names its service |
| The crash policy ends every Linux program (`lx-recover`, `kill_linux_tasks`) | `mod.rs` `recover_task`; `task/supervisor.rs` | A per-service restart class (section 5) |
| The worker loop lives in linux-server's `main.rs` | `userland/drivers/linux-server/src/main.rs` | A shared service runtime in `hydra-rt`, used by every service |
| A ring-3 server's IPC call is Queued unless inside a hand-off (`driver_call_mode`) | `src/ipc/service.rs` | A direct call between servers (section 4) |

Wave 5's Group 12 (`T_FAMILY`, `T_BYFD`, `MOVED_FAMILIES`, `srv_bits`) and Group 14 (a per-CPU table pointer per personality) already built the two routing decisions that generalize best: by address family and by descriptor. This design extends them; it does not replace them.

## 2. The service map

### 2.1 The services

"Lines" are today's kernel files that end up in the service (wave 3–5 pieces already sit in linux-server). Restart classes are explained in section 5.

| Service | Owns (today's code) | Lines | Its own state | Restart class (target) |
|---|---|---:|---|---|
| **vfs-server** (Group 16) | Path walk, name/attribute/link caches, mounts and mount namespaces, permissions (mode, ACL; later Landlock and ABAC checks), `open`, every change, `getdents64`, locks, `tmpfs`, `inotify`/`fanotify`, FUSE (`vfs`, `recent`, `xfer`, `misc`, `extra`, `mount`, `locks`, `acl`, `landlock`, `abac`, `inotify`, `fanotify`, `fuse`) | about 17,000 | Caches (soft), mount tables, lock table, `tmpfs` tree, watches | **Transparent**: mounts, locks, `tmpfs` and watches in kept state |
| **lx-ipc** | Unix sockets, pipes and FIFOs, eventfd, timerfd, signalfd, pidfd, POSIX message queues, System V messages, semaphores and (step 8) shared memory (`unix`, `socket`, `fs/pipe`, `eventfd`, `timerfd`, `signalfd`, `pidfd`, `mqueue`, `sysv`) | about 5,100 | Buffers in flight, connections, socket names (abstract), queues, semaphore sets | **FailObjects** first; **Transparent** once buffers and tables are kept objects (wave 9) |
| **lx-net** | `AF_INET`, `AF_INET6`, `AF_NETLINK` sockets as net-server's client (`inet`, `sockopt`, `rtnetlink`, `netlink`) | about 2,900 | Socket objects, each mapped to a net-server handle; blocked calls; the readiness relay | **Transparent**: the slot-to-handle map in kept state; net-server keeps the connections, and the new instance adopts them instead of resetting them |
| **display** (Group 15) | `drm` plus a native screen core | about 1,600 | KMS objects, GEM handles, buffers | FailObjects: the console appears, the session ends, the login screen returns (Group 15) |
| **input** (Group 15) | `evdev` | about 700 | Per-file queues | FailObjects with device remove/add announcements: input pauses, the desktop keeps running |
| **sound** (Group 15) | `snd` (ALSA) as hda-driver's client | about 2,100 | Streams, mixer | FailObjects with announcements: a gap in the sound |
| **terminals** (Group 15) | `tty`, `pty`, the console terminal | about 1,600 | Line disciplines, pty pairs | FailObjects: programs in terminal windows end; the desktop keeps running |
| **lx-sec** | Keys, `bpf` (`keys`, `bpf`) | about 2,300 | Keyrings, bpf maps and programs | Keys: **Transparent** (keyrings are small, kept). bpf: FailObjects (maps lost; the kernel keeps the device programs it was handed) |
| **lx-proc** | Process and signal *policy*: `setuid` family rules, `prctl`, `unshare`/`setns` orchestration, UTS names, `uname`, ptrace permission, accounting, `/proc` text, `syslog` (`proc` policy part, `process`, `ns`, `limits` policy, `admin`, `ptrace` policy, the `/proc` half of `fs`) | about 4,000 | Little: UTS names, accounting file, `/proc` generation | **Transparent**: its authoritative data are kernel task state (section 2.2) |
| **linux-server** | Everything not split yet; at the end `io_uring` and `aio` (they submit operations on descriptors of every owner) | shrinks to about 2,000 | Rings, contexts | **EndLinux** while it hosts unkept state (decision 6); **FailObjects** at the end |

**Native back ends stay as they are:** zfs-server, net-server, hda-driver, the disk and network drivers, and Group 15's native screen core. Linux services are their clients.

**Why these boundaries.**
- **Each boundary follows an object family that programs reach through descriptors or names.** Calls on a descriptor already go to "the owner of that object" (step 2), so a boundary between object families costs nothing per call.
- **Each service is a separate fault domain with a different blast radius:**
  - a vfs-server bug can lose cached names, but never a pipe;
  - an ipc bug breaks D-Bus connections, never open files;
  - a display bug ends the session, never a download.
- **Each matches a back end, or a team of code that changes together:**
  - lx-net ↔ net-server;
  - vfs-server ↔ zfs-server;
  - sound ↔ hda-driver;
  - lx-ipc is pure Linux semantics with no back end.
- **Boundaries that were rejected:**
  - **Terminals with processes.** Job control needs process groups and sessions, but those are kernel identity (section 2.2), so the terminal service needs no process service.
  - **`/proc` with vfs-server.** `/proc` shows process state. It is lx-proc's file system, reached by a redirect (Group 16, section 4.1).
  - **Unix sockets with vfs-server.** A socket file is a name (vfs-server); the socket is an IPC object (lx-ipc). One call between them at `bind`/`connect` (section 4.1).
  - **Keys with processes.** Keyrings hang off credentials and sessions, but keys are a self-contained object store, already moved and tested on their own.
  - **More, smaller services** (one per descriptor kind: eventfd alone, timerfd alone): no fault-domain gain worth a process each. They share lx-ipc's code (wait queues, readiness).

### 2.2 Shared state: who owns it

The rule: **state that identifies a process or that a program cannot live without is kernel mechanism** (it was mostly in the kernel task already). **Services own objects and decide policy, and change shared state only through kernel primitives.** Every forwarded call carries a copy of the shared state it needs, so a service needs no per-process memory of its own.

| Shared state | Owner (kept where) | Who changes it | Who reads it | Today |
|---|---|---|---|---|
| Credentials: uids, gids, groups, capabilities | **Kernel** (task) | lx-proc via `task_creds` (setuid family, exec of a setuid file) | Every service: in `LxCall` (already today) | Kernel |
| Process and thread ids, the process tree (parent, children, exit status, zombies), `wait4` | **Kernel** (task table) | Kernel (clone, exit) | Services: `LxCall` (`tid`, `tgid`); `/proc` via an info primitive | Kernel (`proc.rs`) |
| Process group and session | **Kernel** (task) | lx-proc decides `setsid`/`setpgid` rules and sets them by primitive | Terminals (job control, on every read/write): `LxCall` `pgid`/`sid` | Kernel |
| PID numbers per PID namespace | **Kernel** (translation table) | Kernel (clone into a namespace) | Services through `LxCall` (caller's view) and an info primitive | Kernel (`ns.rs`) |
| Namespace ids (mount, net, IPC, UTS, user, PID) | **Kernel** (task: a small id per kind) | lx-proc orchestrates `unshare`/`setns`/`clone(CLONE_NEW*)`: asks each owning service to create the namespace object, then sets the ids | Each service reads its kind from `LxCall` (vfs: mount ns; lx-net: net ns; lx-ipc: IPC ns, as `ipc_ns` today) | Kernel |
| The namespace *objects* (mount tables, network views, IPC tables, UTS names) | **The service of that kind** (kept state) | That service | That service | Kernel |
| Descriptor table (numbers → handles, close-on-exec, `dup`, `fork` copy) | **Kernel** (handle table) | Kernel; services install handles (`LX_OBJ_INSTALL`) | Kernel; owners hear of last closes | Kernel |
| Current directory, root, umask | **Kernel** (task, as directory handles; shared on `CLONE_FS`) | vfs-server answers `chdir`/`chroot` and sets the handle by primitive; `umask` is answered in the kernel | vfs-server: `LxCall` `cwd`/`root`/`umask` | Kernel |
| Signal state: handlers, masks, pending, delivery | **Kernel** | Kernel; services post with `sig_post` (to a process, a thread, or a process group) | Kernel; lx-ipc `signalfd` via `sig_take` | Kernel |
| Resource limits | **Kernel** (task: they are enforced at many kernel points: descriptors, stack, address space) | lx-proc decides `prlimit`/`setrlimit` permission and sets them by primitive | Kernel; services in `LxCall` if needed | Kernel |
| `comm`, `exe`, command line | **Kernel** (task) | Kernel (exec), lx-proc (`prctl(PR_SET_NAME)`) | `/proc` via info primitive | Kernel |
| Timers (interval timers, POSIX timers) | **Kernel** (they post signals) | Kernel | | Kernel |
| `seccomp` filters, ptrace stops | **Kernel** | Kernel | | Kernel |
| Address spaces, page cache, file mappings | **Kernel** | Kernel; vfs-server via `obj_*` | | Kernel |

What this changes against the first design (section 5 of the Linux design): it keeps in the kernel, **as mechanism**, the process tree, process groups and sessions, PID translation, namespace ids, resource limits and the cwd/root/umask. The first design moved those into the server in step 7. The policy around them (who may do what) still moves to lx-proc. Estimate: about 2,500 lines of today's `proc.rs`, `process.rs`, `ns.rs` and `limits.rs` stay as mechanism. That is the price of decision 9's resilience, and it is the same choice Zircon and seL4-based systems make for their handle and job tables.

### 2.3 What a crash costs the user, per service

"Programs survive" means no program is ended by the kernel; a program may still see an error on one descriptor and decide by itself to exit.

| Service crashes | Programs survive? | What the user sees (target class) | What it needs |
|---|---|---|---|
| vfs-server | **Yes** | File calls pause about a second; open files, mappings and current directories keep working; a change in flight (`rename`, `write`) gets `EIO` | Kernel file and directory handles (Group 16); kept state for mounts, locks, `tmpfs`; waiting callers; re-sending safe calls |
| lx-net | **Yes** | A pause on network calls; connections keep going (net-server held them) | Kept slot-to-handle map; net-server lets the new instance adopt its client's handles (today Group 12's `reset` closes them) |
| net-server (native) | Yes (today) | Connections reset, downloads fail cleanly, DNS retried (wave 2) | Unchanged |
| lx-ipc, first version | **Yes**, but… | Pipes and Unix sockets fail (`EPIPE`, `ECONNRESET`, end of file). D-Bus and Wayland connections drop, so **the desktop session ends**; console programs, downloads and servers keep running | FailObjects |
| lx-ipc, kept buffers (wave 9) | **Yes** | A pause; nothing lost | Pipe and socket buffers as kept memory objects; connection tables in kept state |
| display / input / sound / terminals | **Yes** | As Group 15's section 3.6: the console appears and the session ends / input pauses / a sound gap / terminal programs end | Group 15's H group: device remove/add announcements |
| lx-sec | **Yes** | Key calls pause; keyrings kept. Programs holding bpf map descriptors get `EBADF` | Kept keyrings |
| lx-proc | **Yes** | `setuid`, `prctl`, `unshare` and similar pause about a second | Section 2.2 (its data are kernel state) |
| linux-server (while it hosts unsplit pieces) | No (decision 6) | Every Linux program ends; login screen; **vfs-server, the file system and the device services stay up** | Today's crash policy |
| A crash loop (the same service again within 30 s of a restart) | Depends | The service drops one class (section 5.2) | The ladder |

**Today's baseline (decision 6):** any fault in the Linux layer ends every Linux program. With this design, from the end of wave 8 on, **no single Linux service crash ends every program** unless the user keeps decision 6 for linux-server's remainder.

## 3. Routing in the kernel to several servers

### 3.1 Today

```text
 syscall ──> personality::CURRENT_TABLE (Group 14: null for Linux)
         ──> fast_syscall (getpid, futex wake: per-CPU cache)
         ──> lx::fast_entry: route(nr) = TABLE[nr] (u8 flags)
               T_FAMILY: socket/socketpair by family bitmask   (Group 12)
               T_BYFD:   srv_bits test, then the object        (Group 12)
               ──> the ONE request table ──> direct switch to an idle linux-server worker
         ──> otherwise the kernel lock and the in-kernel dispatcher
```

### 3.2 Service ids and the registry

- **A service id** (`SvcId`, one byte) names a Linux-facing service; 0 is the kernel.
- **The registry** (`lx::svc::SVC[16]`) holds, per id:
  - the endpoint and generation;
  - the online flag and the restart class;
  - its request table, worker list and syscall pages;
  - its notification ring and its readiness area (in its own window);
  - its kept-state object.
- **Fixed ids** (`LXS_*` in `src/ipc/protocol.rs`):

  | Id | Name | Endpoint |
  |---:|---|---|
  | 1 | `LXS_LINUX` (linux-server) | 0x29 |
  | 2 | `LXS_VFS` (vfs-server) | 0x2D |
  | 3 | `LXS_NET` (lx-net) | 0x29 until split, then 0x2E |
  | 4 | `LXS_IPC` (lx-ipc) | 0x29 until split, then 0x2F |
  | 5 | `LXS_PROC` (lx-proc) | 0x29 until split, then 0x30 |
  | 6 | `LXS_DISPLAY` | 0x23 |
  | 7 | `LXS_INPUT` | 0x2A |
  | 8 | `LXS_SOUND` | 0x2B |
  | 9 | `LXS_TTY` | 0x2C |
  | 10 | `LXS_SEC` (lx-sec) | 0x29 until split, then 0x31 |

- **Co-location.** Several ids may name the same endpoint. Until a piece is split out, its id points at linux-server (0x29), and linux-server's dispatch serves it as today. **Splitting a piece out = start its new program and change one registry entry;** the routing tables do not change. The same switch runs a split service inside linux-server again (`lx.net=linux`), to bisect a split.
- **A worker's service** is its process's registered endpoint. `SYS_LX_CTL(LX_CTL_ATTACH)` needs no new argument. A co-located process serves every id that names its endpoint.

### 3.3 The route entry

The entry grows from 8 to 32 bits, one table per personality (Group 14's per-CPU pointer picks it; the Linux table is today's global one):

| Bits | Meaning |
|---|---|
| 0–7 | Today's flags, meanings unchanged: `T_SERVER` 1 ("not the kernel"), `T_FD0` 2, `T_IPC` 4, `T_UMASK` 8, `T_FDAT1` 16, `T_FAMILY` 32, `T_BYFD` 64 |
| 8–11 | `svc`: the service that answers when the call is routed by number |
| 12–15 | New flags: `T_FSCTX` (carry root and cwd handles), `T_IDEMPOTENT` (may be re-sent to a restarted service), `T_BYARG` (decided by an argument), `T_REDIR` (the answer may be a redirect) |
| 16–31 | The argument for `T_BYARG` (which argument, and an index into a small rule list) |

`lx::route(nr)` stays the one function that turns a number into a route, as Groups 11, 12 and 14 asked. It is still one load.

### 3.4 How a call finds its service

In `lx::by_args(nr, &args) -> Target { svc, obj }`, used by both `forward` and `fast_entry`:

1. **By number:** `svc` from the entry. Path calls go to `LXS_VFS`; `clone`, `prctl`, `setuid` and the like (once moved) to `LXS_PROC`; `keyctl` and `bpf` to `LXS_SEC`; and so on.
2. **By family** (`T_FAMILY`, `socket`/`socketpair`): `FAMILY_SVC[family]`, a 64-byte table replacing Group 12's `FAMILIES` bitmask. `AF_UNIX` goes to `LXS_IPC`; `AF_INET`, `AF_INET6` and `AF_NETLINK` go to `LXS_NET`; unknown families go to the kernel. (A netlink protocol owned elsewhere, such as uevents for Group 15's announcements, can be a `T_BYARG` rule on `args[2]`.)
3. **By descriptor owner** (`T_BYFD`): Group 12's `srv_bits` test stays one bit per descriptor ("not a plain kernel descriptor"). Only a set bit takes the table with `try_lock` (busy: the ordinary path), finds the object, and reads its `svc`.
   - **Server objects** go to their owner.
   - **Kernel file handles** (Group 16) answer the read-type calls in the kernel (`read`, `pread`, `lseek`, `fstat`, `mmap`) and route the change-type calls (`write`, `ftruncate`, `fsync`, `getdents64`, locks) to `LXS_VFS`.
4. **By argument** (`T_BYARG`, later and small): for example `ioctl` with a `SIOC*` request goes to `LXS_NET` whatever the descriptor is; `clone` with `CLONE_NEW*` flags goes to `LXS_PROC` (otherwise `clone` stays in the kernel).
5. **By redirect** (`T_REDIR`, Group 16): a worker may answer `LX_REPLY_REDIRECT` with `(svc, object, tail offset)`. The kernel forwards the same call to that service in the same trap, with `LxCall::redir_obj` set and the rest of the path in the copy area. At most 4 redirects per call (then `ELOOP`). Used for lookups under `/proc` (lx-proc), `/sys` and `/dev` (device services), FIFOs (lx-ipc) and FUSE mounts.
6. **By device number:** `MAJOR_SVC[256]` (character major → service), filled when a service goes online (`LX_SVC_CLAIM_MAJOR`): 226 display, 13 input, 116 sound, 4/5/136 terminals.
   - **Before step 6a,** the kernel's own `open` of a claimed character node forwards the `open` to that service (`LxCall::dev` = the device number), which installs a descriptor it owns.
   - **After step 6a,** vfs-server answers such an `open` with a redirect to `MAJOR_SVC[major]`.

```text
 syscall ──> CURRENT_TABLE[pers] ──> entry = TABLE[nr] (u32: flags | svc | arg)
               T_FAMILY ──> FAMILY_SVC[args[0]]
               T_BYFD   ──> srv_bits? ──> object.svc  (file handle: read-type in the kernel)
               T_BYARG  ──> rule(args[i])
               else     ──> entry.svc
         ──> SVC[svc]: its request table ──> direct switch to its idle worker
               answer REDIRECT(svc', obj, tail) ──> SVC[svc'] in the same trap
```

### 3.5 The direct switch and the lock-free path with several services

Wave 4's measured gains must stay. They do, because nothing on the path grows except one index:
- **`fast_entry`** builds the `LxCall` from the per-CPU identity cache as today, then takes `&SVC[svc]` instead of the single `LX` table. Group 10's rules apply per service unchanged:
  - every place that marks a request Done or Failed sets that service's `REQ_DONE[slot]`;
  - block only under the request table's lock;
  - `try_lock` for the descriptor table.
- **Each service has its own request-table lock.** Two programs calling two different services no longer meet on one lock. That is less contention than today.
- **The direct switch** (`Scheduler::direct_call`) takes a target task; it does not care which process the worker belongs to. The CR3 write stays in `switch_to` (`pcid::load_cr3`). More services mean more address spaces sharing the 4,095 PCIDs per CPU: a dozen more is no pressure.
- **Request ids carry the service** (`id = svc << 56 | sequence`), so `SYS_LX_COMPLETE`, `SYS_LX_READ`/`WRITE`/`READ_STR` and the `LX_OBJ_*` operations find the right table without a new argument.
- **The per-CPU identity cache** (Group 10's `IDENT`, Group 12's cached descriptor table) gains the new context fields (section 3.8). They are filled at the same moment (identity epoch), not per call.
- **Expected cost:** one more dependent load (the registry entry, hot in cache) on the forwarding path, a few nanoseconds against 2,000. The routing group measures `lx_null`, `keyctl` and the step 2–5 calls before and after (budget: within noise), plus a forwarded null call to a second service.

### 3.6 Per-personality tables

Group 14's hook gives each personality its own table, selected through a per-CPU pointer. **Every table uses the same entry format, so a FreeBSD call routes to the same services as a Linux one.** A FreeBSD `stat` goes to vfs-server, a FreeBSD `socket(AF_INET)` to lx-net.
- The services decode by personality (the `pers` field Group 14 plans to append to `LxCall`).
- A `LINUX_AS(n)` entry (Group 14) still routes through `lx::route`.
- Section 6.3 explains why this replaces wave 10's "one POSIX core" with per-service front ends.

### 3.7 The switch back

**Superseded (wave 10, decision 32):** the in-kernel copies are deleted and every word below is ignored with a boot-log line; crashes are handled by restarts. Kept here as the history of how the moves were bisected.

- **`lx=kernel`** (QEMU fw_cfg or boot word) sends every moved call back to the in-kernel code, as today. It clears every `svc` and `FAMILY_SVC` entry.
- **New: `lx.<name>=kernel`** (for example `lx.vfs=kernel`) sends back only that service's calls: bisecting inside one build, per service.
- **New: `lx.<name>=linux`** co-locates a split service back into linux-server (its registry entry points at 0x29). This bisects "the code is wrong" against "the split is wrong".
- The boot log prints one line per service: `[lx] vfs: vfs-server (0x2D)`, `[lx] net: linux-server (co-located)`, `[lx] ipc: in the kernel (lx.ipc=kernel)`.

### 3.8 What travels with a call, notifications, readiness

- **Appended at the end of `LxCall`** (after Group 13's `ino` and Group 14's `pers`/`result2`; about 64 bytes, within the 0x200 the header may use):

  | Field | What |
  |---|---|
  | `root`, `cwd` | Directory-handle keys, for `T_FSCTX` calls |
  | `pgid`, `sid` | Process group and session |
  | `mnt_ns`, `net_ns`, `pid_ns`, `user_ns` | Namespace ids (`ipc_ns` exists already) |
  | `dev` | The device number of a forwarded device `open` |
  | `redir_obj` | The object a redirect names |
  | `on_behalf` | The delegated request (section 4.3) |
  | `from_svc`, `dcall_op` | Who calls, and what, for a call between services |

- **Notifications:** one ring per service, in its own window, with the same layout as today's.
  - `FORK`, `EXEC` and `EXIT` go to each service that subscribed (`LX_SVC_SUBSCRIBE`): lx-proc, lx-ipc (System V undo at exit, pidfd) and lx-sec (keyrings follow processes). vfs-server needs none, since it keeps no per-process state.
  - `INTERRUPT` and `CLOSE` go only to the owner.
  - The `note_seq` in a call is the target service's ring position, so a call never overtakes the events before it (step 1's rule, per service).
- **Readiness:** each service keeps its readiness words, changed bitmap and watched bitmap in its own window, at the same offsets as today. Its doorbell is `SYS_SVC_SIGNAL(own endpoint, LX_SIGNAL_OBJS)`; the kernel's hook finds the service by endpoint. `poll`/`select`/`epoll` read the word of whichever service owns each descriptor, still without a call. Each service has its own 2,048 slots, which also eases Group 12's worry about a browser's many sockets.

### 3.9 Size

Kernel side: about 1,200–1,500 new or changed lines in `src/lx` (a new `svc.rs` registry, per-service tables, routing rules, redirect, device majors, the switch-back words). Server side: the worker loop of `linux-server/src/main.rs` moves into a reusable runtime in `hydra-rt` (about 400 lines), which every new service uses.

## 4. Calls between services

### 4.1 Where they happen

| From | To | Why | How often (section 4.6) |
|---|---|---|---|
| vfs-server | zfs-server | Name and attribute misses, directory listings, writes | Often: 42,000 in a warm `find`, 400,000 in `ls -lR`, 99,000 in a KDE login (Group 16) |
| lx-net | net-server | Every socket operation | As often as socket calls (Group 12's step 3) |
| sound | hda-driver | Stream set-up, start, stop, volume | Rare (Group 15) |
| lx-ipc | vfs-server | `bind`/`connect` of a Unix socket by path: create or find the socket node | At most every `connect`/`bind`: 291 in a KDE login |
| lx-proc (linux-server until then) | vfs-server | `execve`: open the program and its interpreter, with the caller's credentials | Every `execve`: 140 in a KDE login |
| lx-proc | lx-net, lx-ipc, vfs-server | `unshare`/`setns`/`clone(CLONE_NEW*)`: create each namespace object | Rare |
| lx-proc | lx-net | `/proc/net/*` text | Rare |
| vfs-server | lx-proc, the device services, lx-ipc | `/proc`, `/sys`, `/dev` lookups, FIFOs | **Not a call:** a redirect through the kernel (2,187 in a KDE login) |
| Any service | Kernel | Primitives (`task_*`, `sig_post`, `obj_*`, info) | As today |
| Kernel | A service | Requests the kernel makes while holding locks (today `/proc/keys`) | Rare; today's hand-off call to the service's main thread |

**What does not cross services**, because the kernel does it on handles:
- `poll`, `select` and `epoll` over descriptors of several owners;
- `dup`, `fork` and close-on-exec;
- `SCM_RIGHTS` (the kernel moves a handle of any owner: Group 13's pin/install primitive becomes permanent);
- `sendfile` and `splice` between a file handle and a pipe or socket (the kernel reads the page cache and writes to the object with Group 13's kernel-buffer I/O);
- signals between programs.

### 4.2 The direct call

Two halves, one mechanism (the direct switch of step 1):

1. **To a Linux service** (one with forwarding workers): native **70 `SYS_SVC_DCALL(target svc, op, in, in_len, out, out_cap)`**.
   - The kernel picks an idle worker of the target and writes an `LxCall` into its syscall page: `nr = LX_DCALL_NR` (0x6800), `dcall_op = op`, `from_svc`, and the identity of the request being served (section 4.3).
   - It copies `in` straight from the calling server's memory (it is the current address space: no page walk) into the worker's copy area.
   - It switches straight to the worker. The worker answers with `SYS_LX_REPLY_RECV` as for any call, which switches straight back; up to 3 KiB of output returns through the page.
   - **No idle worker:** the call waits in the target's queue (the slow path, as for forwarded calls).
   - **A call that must wait:** the callee answers `PENDING` and completes later with `SYS_LX_COMPLETE`, as for Linux calls.
2. **To a classic service** (zfs-server, net-server, the drivers: one server thread in `SYS_SVC_RECV`): today's `SYS_SVC_CALL` gets the same fast path.
   - If the target's server thread waits in `recv` and the caller holds no kernel lock (a ring-3 caller never does), the call switches straight to it, and its `SYS_SVC_REPLY` switches straight back.
   - There is no machine-wide stop (Handoff's) and no wake-up of another CPU (Queued's). Otherwise it stays Queued.
   - This is Group 16's prerequisite P1. It speeds up net-server for lx-net (wave 5's Group 12 calls it Queued today) and zfs-server's own calls to the disk driver.
3. **One-way posts:** native **71 `SYS_SVC_POST(target svc, op, data, len)`** appends to the target's notification ring and rings its doorbell. Used for events that need no answer: "show this picture", input batches, readiness relays, a session leader's hang-up.
4. **Bulk data:**
   - **inline** in the syscall page, up to 3 KiB;
   - a **shared object** (`LX_SVC_SHARE(peer)`, built on Group 15's memory objects M) mapped into both services once, for steady streams (vfs-server ↔ zfs-server metadata, lx-net ↔ net-server payloads: what Group 12 does today with a part of net-server's window);
   - **page grants** (syscalls 33/34) for one-off large buffers.
   - **File data never passes through a service.** It moves between the page cache and the program (kernel), and between the page cache and zfs-server (kernel), as today.
5. **Permissions:** the supervisor declares which service may call which (`LX_SVC_ALLOW`, settable only by the supervisor). A call along an undeclared edge fails with `EPERM`.

### 4.3 Delegation

A call between services is usually made *for* a Linux program. Example: lx-proc asks vfs-server to open `/usr/bin/bash` for an `execve`. vfs-server must check the permissions of that program, not of lx-proc.
- When a worker serving request R makes a direct call, **the kernel** puts R in `on_behalf` and copies R's credentials, ids and context into the callee's `LxCall`. The caller cannot choose them, so it cannot forge another program's identity.
- While the call lasts, the callee may use R's id like its own request: `SYS_LX_READ`/`WRITE` on the program's memory, and `LX_OBJ_INSTALL` of a descriptor into the program's table.
- The right ends when the call is answered.

This is a fault-containment measure, not protection against a hostile service: a Linux service is trusted with the programs whose calls it serves, as linux-server is today.

### 4.4 No cycles, no stuck workers

- **Synchronous calls go only downward,** in this order:
  - native back ends (zfs-server, net-server, the drivers, the screen core);
  - below vfs-server;
  - below {lx-ipc, lx-net, the device services, lx-sec};
  - below lx-proc;
  - below linux-server.
- **Anything upward is a redirect** (the kernel re-forwards; no service waits for another) **or a post.** All the cases of section 4.1 fit: `/proc` and FIFOs are redirects, a hang-up is a post.
- With the process tree in the kernel (section 2.2), the terminal service asks the kernel, not lx-proc, whether a process group is in a session, so terminals need no upward call either.
- **A service never waits for a lock while it makes a direct call,** and a callee that must wait answers `PENDING`. A worker stuck in a call to a lower service therefore holds up only its own caller.
- Each pool is sized for its callers: vfs-server 4–8 workers, the others 2–4. All are threads, so this is cheap.

### 4.5 Avoiding hops

1. **The kernel routes to the owner** (section 3.4): no Linux call ever passes through linux-server on its way to another service.
2. **Redirects instead of relays** for paths owned elsewhere: one more forward from the kernel (+2.4 µs), only at lookup. Afterwards the descriptor belongs to the right service.
3. **Kernel mechanism instead of protocols** for what crosses every service: poll, descriptor passing, `fork`'s table copy, signals, credentials.
4. **Context in the call** (section 3.8) instead of asking another service: no service asks lx-proc "who is this caller", "what is its cwd", "is this group in that session".
5. **Process events as posts** to subscribers, not calls: `fork` costs one ring post per subscribed service (about 0.3 µs each), with no waiting.

### 4.6 What it costs

**Per operation** (KVM, 2 CPUs; measured values are wave 4's and Group 16's, the rest estimated):

| Operation | Cost | Source |
|---|---:|---|
| Forwarded call, no pointer | +2.0 µs | Measured (design 13.1, vfs-design 3.2) |
| Forwarded path call (path in, `stat` out) | +4.2 µs; about +2.5 with cheaper copies | Measured (vfs-design 3.2); the cheaper copy is wave 6's P3 |
| Redirect (one more forward) | +2.4 µs | Measured forward cost (vfs-design 3.2) |
| Direct call between services | about 2.0–2.5 µs round trip | **Estimate:** the same switch as `lx_null` (2.73 µs total, of which 0.7 is the caller's own trap); the building group measures it |
| Today's call from a ring-3 server (Queued) | 9.0 µs in a loop, 18.8 µs when the other CPU sleeps | Measured (design 13.1, "inside one system call" and "from user") |
| Kernel → zfs-server, today (Handoff) | 5.8 µs | Measured (design 13.1) |
| One more notification ring post | about 0.3 µs | Estimate: a ring append under a lock; the doorbell is shared |
| Routing to one of several services | a few ns | Estimate: one more cached load |

**Per workload.** `tools/services/hops.py` sorts every system call of Group 16's eight profiled workloads by the service that answers it in the target map. The counts are exact (two boots agreed within 0.1 %, vfs-design 2). It then counts what crosses services:
- **redirects:** lookups under `/proc`, `/sys`, `/dev`;
- **direct calls:** `execve` to vfs-server, plus every `connect`/`bind` treated as a Unix socket path (an upper bound);
- **process events:** `fork`, `exec` and `exit` posts.

Where the calls go (forwarded calls only; the rest are answered in the kernel; "proc" includes reads of open pseudo files and of `/dev/null`):

| Workload | Calls | Forwarded | vfs | net | ipc | proc | dev | tty | sec | Redirects | Calls between services | Process events |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `find /usr` (warm) | 84,874 | 24,377 | 23,304 | 0 | 1 | 1,065 | 0 | 7 | 0 | 4 | 1 | 2 |
| `ls -lR /usr/share` | 262,269 | 242,830 | 242,165 | 0 | 13 | 643 | 0 | 9 | 0 | 5 | 5 | 2 |
| `git status` | 19,269 | 14,380 | 14,345 | 0 | 1 | 28 | 0 | 6 | 0 | 3 | 1 | 9 |
| `tar` of `/usr/share/doc` | 41,217 | 18,169 | 13,327 | 0 | 4,793 | 36 | 0 | 13 | 0 | 7 | 6 | 4 |
| `make` of 30 C files | 107,464 | 83,294 | 82,364 | 0 | 1 | 922 | 0 | 7 | 0 | 2 | 91 | 182 |
| `apt-get install hello` | 24,681 | 12,710 | 10,585 | 58 | 889 | 910 | 1 | 267 | 0 | 105 | 63 | 99 |
| Firefox headless start | 19,049 | 8,234 | 3,871 | 289 | 2,429 | 1,215 | 2 | 428 | 0 | 234 | 29 | 123 |
| KDE login | 341,804 | 212,437 | 161,930 | 0 | 42,430 | 3,168 | 4,737 | 172 | 0 | 2,187 | 431 | 484 |

What the split adds, beyond the cost of forwarding itself, which every shape pays and the per-step budgets already count:
- **A:** linux-server + vfs-server, the minimum decision 9 asks for;
- **B:** the full split of section 2, with the kernel routing to owners;
- **C:** the full split, but with linux-server relaying every call of the other Linux services (Group 15's rejected "B1").

| Workload | Time | A | B | C, relay with a direct call (2.5 µs) | C, relay with today's Queued call (9.0 µs) |
|---|---:|---:|---:|---:|---:|
| `find /usr` (warm) | 1.07 s | 0.0 ms | 0.0 ms | 2.7 ms (0.25 %) | 9.7 ms (0.90 %) |
| `ls -lR /usr/share` | 7.92 s | 0.0 ms | 0.0 ms | 1.7 ms (0.02 %) | 6.0 ms (0.08 %) |
| `git status` | 0.58 s | 0.0 ms | 0.0 ms | 0.1 ms (0.02 %) | 0.3 ms (0.06 %) |
| `tar` of `/usr/share/doc` | 1.41 s | 0.0 ms | 0.0 ms | 12.1 ms (0.86 %) | 43.6 ms (3.09 %) |
| `make` of 30 C files | 8.30 s | 0.2 ms | 0.3 ms | 2.7 ms (0.03 %) | 8.7 ms (0.10 %) |
| `apt-get install hello` | 11.8 s | 0.4 ms | 0.5 ms | 5.8 ms (0.05 %) | 19.6 ms (0.17 %) |
| Firefox headless start | 5.05 s | 0.6 ms (0.01 %) | 0.7 ms (0.01 %) | 11.6 ms (0.23 %) | 40.0 ms (0.79 %) |
| KDE login | 25 s | 6.3 ms (0.03 %) | 6.6 ms (0.03 %) | 132.9 ms (0.53 %) | 461.2 ms (1.84 %) |

What this shows:
- **Splitting the Linux layer further costs nothing measurable once the kernel routes to owners.** B is A plus 0.3 ms in a KDE login, the extra process-event posts.
- **The crossing traffic is set by the file-service boundary, which decision 9 already makes.** It is `execve`, Unix socket names and pseudo-file lookups: at most 0.03 % of a KDE login.
- **A relay through linux-server would cost 10–70 times more** (C), up to 3 % of `tar` with today's Queued calls. Owner routing is the part of this design that matters for speed.
- **The large server-to-server traffic is to the native back ends**, and it exists in every shape:
  - vfs-server → zfs-server (Group 16, vfs-design section 9): with today's Queued calls a warm `find` ends up 23 % slower than today in all (forwarding included); with the direct call 3 % *faster*, because the direct call (about 2.5 µs) is cheaper than today's kernel-to-zfs-server Handoff (5.8 µs);
  - lx-net → net-server, the same way.
- **Load per service** (KDE login, about 25 s): vfs-server 6,500 calls a second, lx-ipc 1,700 (mostly eventfd reads and writes: 16,800 of its 42,430), the device services about 200, lx-proc 130. Their worker pools follow these numbers.

Not in these tables: the forwarding cost itself (Group 16's section 9, Group 15's section 3.7, wave 5's step 3 and 4 measurements), and the redirects' own +2.4 µs where A and B both pay it (KDE: 2,187 × 2.4 µs = 5 ms, included in A).

### 4.7 Measured and not measured

- **Measured (exact counts):** the call mix and the crossings above, from Group 16's eight profiled workloads (`linux prof` with counters by descriptor kind and path prefix).
- **Not measured:** the direct call's cost (2.0–2.5 µs is an estimate from the forwarded null call, whose mechanism it reuses). No prototype was built: a meaningful one needs the per-service request tables of section 3, which is most of wave 6's routing group. The building group measures it first, against these targets:
  - `SYS_SVC_DCALL` ≤ 3 µs round trip;
  - `SYS_SVC_CALL` to a waiting classic server ≤ 4 µs (today 9.0 / 18.8).
- **Approximations in the counts:**
  - Unix socket `connect`/`bind` is counted at every call (an upper bound; abstract-namespace sockets need no lookup);
  - for Firefox and `apt-get` a share of the socket calls is assumed to be Internet sockets (30 % and 50 %), since the profile does not split socket calls by family;
  - `/dev/null` writes count as pseudo-file reads and writes (they could even be answered in the kernel).

  None of these changes a total by more than a few tenths of a millisecond.

## 5. Restart support, for every service

### 5.1 The pieces

1. **Kept-state object** (`LX_SVC_KEPT(size)`).
   - The first instance of a service gets a new zeroed memory object; every later instance gets the same one, mapped at the same window offset. The registry owns it, and the supervisor frees it only on a reset (section 5.2).
   - The service keeps there what must outlive a crash, behind a version number, a checksum per record, and a journal for changes of more than one word.
   - A service may also create **kept memory objects** (a flag on Group 15's `obj_anon`), owned by the registry instead of the process: pipe buffers, `tmpfs` data, keyrings.
2. **Waiting instead of failing.** While a Transparent service restarts:
   - calls routed to it sleep on the service's "online" wait queue (interruptible: a signal gives `EINTR`, or a restart for `SA_RESTART` handlers);
   - after 30 s they fail with `EIO`;
   - today's forwarding fails at once (`ENOSYS`/`EIO`).
3. **Re-sending.**
   - Calls that were **queued** (not yet delivered) are delivered to the new instance.
   - Calls answered **pending** are re-sent too: by the step-2 contract a pending call has no effect until it completes (its output is written at completion), so sending it again is safe.
   - Calls **being served** at the crash are re-sent only if their entry says `T_IDEMPOTENT` (`stat`, `open` without `O_CREAT`/`O_TRUNC`, `readlink`, `getdents64`, `getsockopt`, ...). The others get `EIO`, because the service may or may not have done them.
4. **Revalidation.**
   - Every kernel object a service installs carries a 64-bit **key** the service chose: the ZFS objset, object and generation for vfs-server; the net-server handle for lx-net; the kept-object index for lx-ipc.
   - On restart, `LX_SVC_LIST` gives the new instance the (slot, kind, key) of every live object of its service. The instance rebinds each one, or marks it dead (it then polls `POLLERR|POLLHUP` and fails).
   - Until that answer, calls on the objects wait like other calls.
   - This replaces step 2's "a new generation makes every old object stale" for Transparent services.
5. **Re-asserting state held by back ends.** The new vfs-server sends zfs-server the open-file references (`open_ref`) of every live file handle. The new lx-net claims net-server's handles tagged with its client tag (net-server's "reset" becomes "adopt").

### 5.2 Classes and the ladder

| Class | When the service dies | For |
|---|---|---|
| **Transparent** | Callers wait; safe calls are re-sent; objects are revalidated; programs see a pause, and `EIO` only for a change in flight | vfs-server, lx-net, lx-proc, lx-sec (keys), later lx-ipc |
| **FailObjects** | Objects of the old instance fail with a per-kind error (`EBADF`, `ENODEV`, `ECONNRESET`, `EPIPE`); new calls go to the new instance; programs live | The device services, lx-ipc at first, bpf, linux-server's final remainder |
| **EndLinux** | Today's decision 6: every Linux program ends, the login screen returns | linux-server while it hosts pieces with unkept state; available to the user as a policy for any service |

**The ladder:**
- If a service dies again within 30 s of a restart, its kept state is suspect: the supervisor resets it (drops the kept object) and the service drops one class. Transparent becomes FailObjects; FailObjects stays.
- A third crash within 30 s stops restarting it (the supervisor's limit), and its calls fail with `EIO`.
- EndLinux is never reached by the ladder alone. A crash loop costs that service's objects, not every program.

### 5.3 Effort and tests

- **Kernel and supervisor:** about 800 lines (`src/lx/restart.rs`, the supervisor's restart classes, the online wait queue, re-send, list, keys).
- **Each service** then writes its own kept-state layout and its revalidation, as part of its move.
- **Tests:** a test service with a kept counter and objects. Kill it while 8 threads make calls, some blocked and some changing state: the blocked calls complete after the restart, the safe calls are re-sent, the changes get `EIO`, the objects still work, and a second kill within 30 s gives FailObjects.

## 6. Reconciling the plan

### 6.1 The steps of design section 7.2, mapped onto services

| Step (design 7.2) | First home (wave) | Home in this design | What changes |
|---|---|---|---|
| 1. Forwarding, keys | linux-server (3) | lx-sec | Split out in wave 6 as the first proof (section 9) |
| 2. Server objects; mqueue, System V, bpf | linux-server (4) | lx-ipc (mqueue, System V), lx-sec (bpf) | Co-located until split |
| 3. Network sockets, netlink | linux-server (5, Group 12) | lx-net | Co-located until wave 8; the readiness relay and net-server client move as they are; "reset" becomes "adopt" for Transparent restarts |
| 4. Unix sockets, pipes, event descriptors | linux-server (5, Group 13) | lx-ipc | Co-located until wave 8; the temporary `vfs_resolve` becomes a direct call to vfs-server (wave 7); `SCM_RIGHTS` pin/install stays as the permanent handle-move primitive |
| 5. Terminals and devices | linux-server, or a display server (6) | Four device services (Group 15) | Directly routed; in wave 8 (after the file service) |
| 6a. VFS, mounts, pseudo files, descriptor table | linux-server (7) | vfs-server; `/proc` in lx-proc, `/sys` and `/dev` in the device services (Group 16) | The descriptor table stays in the kernel for good; wave 7 |
| 6b. The rest of the file side | linux-server (8) | vfs-server (`inotify`, `fanotify`, FUSE, Landlock, ACLs, ABAC); linux-server (`io_uring`, `aio`) | Wave 9 |
| 7. Processes and signal policy | linux-server (8) | **7a:** the process tree, groups, sessions, PID translation, limits and namespace ids stay as kernel mechanism (tidied); **7b:** lx-proc takes the policy and `/proc` | Smaller than planned; waves 9–10 |
| 8. Debugging, last pieces | linux-server (9) | lx-proc (ptrace permission, perf policy); lx-ipc (System V shared memory on memory objects); kernel (`userfaultfd` stays mechanism) | Wave 10 |

### 6.2 Wave 5's work

- **Group 12 (sockets):** its code becomes lx-net's, co-located in linux-server.
  - `T_FAMILY`, `T_BYFD`, `srv_bits` and `by_args` are the routing this design generalizes. The family bitmask becomes `FAMILY_SVC`, and `ServerObject` gains `svc`.
  - Its net-server client (`netc.rs`) moves into lx-net unchanged in wave 8.
  - The direct call to classic services (section 4.2, half 2) speeds up its requests to net-server.
- **Group 13 (Unix sockets, pipes, event descriptors):** its code becomes lx-ipc's.
  - `timer_arm` (62) and `sig_take` (63) work per service (the timer notification goes to the caller's own ring).
  - Descriptor passing works for objects of any owner, because the kernel moves handles.
  - `vfs_resolve` and `LxCall::ino` go in wave 7 (vfs-server's group 7-5).
  - FIFOs become a redirect from vfs-server to lx-ipc. The `make -j` FIFO bug (Group 16) is fixed before that (P5).
- **Group 14 (personality hook):** the per-personality table is where `svc` lives. Nothing to change in wave 5; the routing group widens the entries.
- **Group 17 (open bugs):** not affected.
- **Groups 15 and 16** adopted this interface (NOTES.md). Their wave plans are sections 7 and 12 of their designs. Section 9 puts them in waves 8 and 7, and takes their prerequisites (Group 15's routing core R and memory objects M; Group 16's P1–P4) into wave 6.

### 6.3 FreeBSD and macOS on shared services

[personality-design.md](personality-design.md) section 3 planned wave 10 as "the core split": linux-server becoming one shared POSIX core with front ends. With several services, the same idea becomes **per-service front ends**:
- **Each service is personality-neutral inside** (paths, mounts, sockets, pipes, processes are the same objects for every system). It decodes the caller's layouts and constants for its own calls, using `LxCall::pers`:
  - vfs-server translates FreeBSD's `stat`, `getdirentries` and `fcntl` layouts;
  - lx-net translates `sockaddr` with `sa_len` and the BSD family numbers;
  - lx-ipc does pipes (bidirectional on BSD) and `cmsghdr`;
  - lx-proc does `sysctl`'s process view, `procctl` and jails.
- **A shared library** (`posix-abi` in `userland/drivers`) holds the neutral types and each personality's encoders, so the translations are written once and linked into each service.
- **`kqueue`** sits where `epoll` sits: in the kernel, over the same readiness words. The non-descriptor filters are fed by their owners: `EVFILT_PROC` by the kernel's process tree, `EVFILT_VNODE` by vfs-server's watches, `EVFILT_TIMER` by kernel timers, `EVFILT_SIGNAL` by kernel signal state.
- **mach-server** (macOS, wave 12 of the old plan) is one more service with its own objects (ports as server objects with readiness words): `EVFILT_MACHPORT` reads its words like any other.
- **Shared Unix sockets** (Wayland, D-Bus) between Linux and FreeBSD programs are the same lx-ipc objects; only the address encoding differs.
- **What this changes:** wave 10's 6–8 agent-days of "core split" become front-end work spread over the services, done by parallel groups (one per service) in the FreeBSD wave, plus about 2–3 agent-days for the shared library. The order (hook → front ends → FreeBSD → macOS) is unchanged. FreeBSD's dynamic linker needs 30 calls, mostly vfs-server and lx-proc, so the first FreeBSD milestone needs only two services' front ends.

### 6.4 The kernel's size at the end

| | First design (section 5.3) | This design |
|---|---:|---:|
| Linux support kept in the kernel | about 6,000 | about 11,000 |
| of which: handle table, file-handle I/O, attributes, poll/epoll (Group 16) | (moved) | about 1,850 |
| of which: process tree, groups, sessions, PID translation, limits, namespace ids as mechanism | (moved) | about 2,500 |
| of which: multi-service routing, direct call, restart support | (1,500 for one server) | about 2,500 |
| Kernel total at the end (estimate) | about 50,000 | about 55,000 |

The extra 5,000 lines are mechanism: tables, handles and ids. No path is parsed, and no protocol or Linux text format is generated in them.

## 7. Recommendation

1. **Adopt the service map of section 2,** with co-location as the way there: each piece is split out of linux-server when its wave comes, by changing one registry entry, and can be put back for bisecting.
2. **Keep identity in the kernel** (section 2.2): credentials, the process tree, process groups and sessions, PID translation, namespace ids, limits, cwd/root/umask, and the descriptor table. It is what lets every Linux service restart without ending programs, at about 2,500 kernel lines.
3. **Route in the kernel to the owner** (section 3), never relay through linux-server: the measurements show this is what keeps the split free (B against C).
4. **Build the direct call in both halves** (section 4.2): to Linux services and to classic services such as zfs-server and net-server. It is a prerequisite for the file service, and speeds up lx-net and zfs-server's own calls too.
5. **Build restart support once, for every service** (section 5): kept state, three classes, the ladder, revalidation. Groups 15 and 16 both need it; building it per service would be done three times.
6. **Split one small service in wave 6 as the proof**, as `keys` proved forwarding in wave 3: lx-sec (keys and bpf), with Transparent restarts for keys.
7. **Order:** foundations (wave 6), the file service (wave 7, the point of decision 9), the device services plus splitting lx-net and lx-ipc out (wave 8), then the rest (section 9).

## 8. Decisions for the user

1. **Which services?** Recommended: the ten of section 2.1. They are vfs-server, lx-ipc, lx-net, four device services, lx-sec, lx-proc, and linux-server for what is left.
   - Fewer would mean bigger fault domains (for example, sockets and pipes together).
   - More would mean a process per descriptor kind, with no real gain.
2. **Should "who a process is" stay in the kernel?** That covers credentials, parent and children, process groups and sessions, namespaces, limits, current directory, and the descriptor table.
   - Recommended: **yes.** Then no single Linux service crash ends every program. It keeps about 2,500 more lines in the kernel than first planned (about 11,000 lines of Linux support instead of 6,000).
   - The alternative moves them into the process service, whose crash would then end every Linux program, as today.
3. **What should happen when a service crashes?**
   - Recommended: the classes of section 5.2. vfs-server, network sockets, keys and the process service restart invisibly (a pause; a change that was in flight returns an error). Pipes and Unix sockets, the devices and bpf fail only their own descriptors (for pipes and Unix sockets that ends the desktop session, until wave 9 keeps their buffers).
   - The ladder: a second crash within 30 s drops to the next class.
   - **Today's decision 6** (every Linux program ends) remains only for linux-server while it still hosts unsplit pieces.
   - Accept?
4. **Should the kernel send every call straight to the service that owns it,** rather than through linux-server? Recommended: **yes.** Relaying would cost 10–70 times more (up to 3 % of a `tar`, 1.8 % of a KDE login) and keep linux-server in every path.
5. **Should a fast call between services be built in wave 6?** It would cover calls to the Linux services and to zfs-server and net-server. Recommended: **yes.** The file service needs it (Group 16: without it a warm `find` ends up 23 % slower than today, over budget on the faster baseline; with it 3 % faster), and it speeds up the network service.
6. **Should a small service be split out first, as proof?** Recommended: **yes, keys and bpf (lx-sec) in wave 6.** It tests routing to a second service, the restart support and the kill tests before the file service depends on them.
7. **In what order should the big moves come?** Recommended: wave 6 the foundations, wave 7 the file service, wave 8 the device services together with splitting the network and IPC services out of linux-server.
   - Alternative: devices in wave 7 and the file service in wave 8. Both orders work; the file service first does decision 9's main point first, and its prerequisites are exactly wave 6's.
   - Not recommended: both in one wave (13 groups, and they would collide on `devices.rs`, the `/dev` and `/sys` code).
8. **FreeBSD and macOS later:** should each service learn to speak FreeBSD (and later macOS) for its own calls, instead of first building one shared "POSIX core" in a separate wave? Recommended: **yes** (section 6.3). The FreeBSD work then splits into parallel groups by service, and it starts one wave later than planned, after the splits.
9. **Should each service also get its own switch back?** For example `lx.vfs=kernel` (back into the kernel) and `lx.net=linux` (back into linux-server), next to today's `lx=kernel`. Recommended: **yes.** They are cheap, and they let a regression be traced to one service, or to the split itself.

## 9. Step plan

Each wave keeps the rules that worked in waves 4 and 5:
- one worktree per group;
- interfaces in NOTES.md on day 1;
- appended, marked blocks in shared files (`src/lx/mod.rs` tables, `src/ipc/protocol.rs`, `task/supervisor.rs`, `userland/drivers/Cargo.toml`);
- the switch back kept until the next wave deletes the in-kernel copies;
- every code group ends with the full suite, `suite_loop` when it touches the trap, the IOMMU suite, host tests, KDE with Firefox and sound, Wine, three fresh logins without a crash, the budget numbers, **and a kill test of every service it touched**.

### 9.1 Wave 6: the foundation (six groups)

| Group | What | Owns | Needs | Agent-days | Tests |
|---|---|---|---|---:|---|
| **R1. Routing core** | Registry and service ids; u32 entries; per-service request tables, workers, pages, rings, readiness, doorbell hook; request ids with the service; `FAMILY_SVC`; `ServerObject.svc`; `MAJOR_SVC` and the forwarded device `open`; redirect; the new `LxCall` fields; per-service switch-back words; the worker loop moved into a `hydra-rt` service runtime; a test service | `src/lx/mod.rs`, `src/lx/obj.rs`, new `src/lx/svc.rs`, `src/ipc/protocol.rs` (block), `hydra-rt` (new `svcrt.rs`), `linux-server/src/main.rs` (uses the runtime), `compat/linux/chardev.rs` (one arm), new `userland/drivers/svc-test` | nothing | 5–6 | New `svcroute` test (calls to two services, objects of both under one `epoll`, `SCM_RIGHTS` across owners, a redirect, a device open by major); `lxbench` `lx_null`/`keyctl`/step 2–5 calls unchanged (budget: noise); a forwarded null call to the second service; the full suite with `lx=kernel` and per-service words |
| **R2. Direct call** | `SYS_SVC_DCALL` (70), `SYS_SVC_POST` (71), delegation, `LX_SVC_ALLOW`; the direct path of `SYS_SVC_CALL` to a waiting classic server; lx-net's (linux-server's) net-server calls use it | new `src/lx/dcall.rs`; `src/ipc/service.rs` (call path); `src/task/scheduler.rs` (reuse of `direct_call`, small); `hydra-rt` wrappers; `linux-server/src/netc.rs` (call site) | R1's interface (day 1) | 4–5 | Probe: dcall and classic call round trips (targets ≤ 3 and ≤ 4 µs); net throughput and `tcp_rtt` before and after; killing the callee during calls (callers get `EIO`, nothing hangs); the IPC suite tests |
| **R3. Restart support** | Kept-state objects, restart classes, the ladder, waiting callers, re-sending, `LX_SVC_LIST` and keys, revalidation hooks; the supervisor's policy per service | new `src/lx/restart.rs`; `src/task/supervisor.rs`; marked hooks in `src/lx/mod.rs` (`server_gone`) | R1's interface (day 1) | 4–5 | Kill tests on the test service (section 5.3); the existing linux-server kill test unchanged (EndLinux) |
| **P3. Cheaper argument copies** (Group 16's) | User copies with a fault fix-up in the trap, straight into the syscall page | `src/lx/copy.rs`, `src/arch/idt.rs` (fix-up table) | nothing | 2–3 | `lxfwd` copy-table cases, `sigstress`, `lxbench add_key`/`keyctl_describe`, vfsbench stubs (path call ≤ +2.5 µs) |
| **M. Memory objects** (Group 15's) | `obj_anon`, `obj_dma`, `mmap` of a server object, objects outliving their service, **kept** objects (registry-owned), `LX_SVC_SHARE` between two services | new `src/lx/mem.rs`; the `mmap` hook in `compat/linux/mm.rs`; `memory/vm.rs` (a `MappedObject`); `hydra-rt/src/mem.rs` | R1's `svc` in objects (day 1) | 3–4 | `srvmap` (Group 15), plus an object kept across a service kill |
| **X1. First split: lx-sec** | keys and bpf out of linux-server into a new `lx-sec` program (endpoint 0x31) on the service runtime; keyrings in kept state (Transparent); bpf FailObjects; `/proc/keys` from it; bpf device-program list re-sent after a restart. Also the FIFO open fix (P5), if Group 13 has not made it | new `userland/drivers/lx-sec`; `linux-server/src/{keys,bpf}.rs` (moved); `task/supervisor.rs` (entry, marked) | R1, R3 (day 1); merges last | 3–4 | `keys`, `keyparent`, `bpf`, `lxfwd hammer` while killing lx-sec (calls pause, then go on; keyrings intact); KDE unaffected by the kill; FIFO test `mkfifo f; (sleep 1; echo x > f) & cat f`; `make -j2` no longer spins |

- **Total:** about 21–27 agent-days, six groups.
- **Order:** day 1, R1 posts the registry, entry and `LxCall` names (as built from this document), and R2, R3, M and X1 work against them.
- **Merge order:** R1 first, then P3 (independent), M, R2, R3, and X1 last.

### 9.2 Wave 7: the file service (Group 16's plan)

Group 16's section 12.2 as written: 7-1 vfs-server core, 7-2 path calls and kernel file handles, 7-3 mounts and `tmpfs`, 7-4 pseudo file systems, 7-5 `execve`, socket files and FIFOs, 7-6 restart, then 7-7 closing. Two changes from this design:
- **7-4's `/proc` goes to `LXS_PROC`, which is co-located in linux-server until wave 10.** Its `/sys` and `/dev` go to linux-server for now, and to the device services in wave 8.
- **7-6 shrinks to vfs-server's own kept-state layout and revalidation** (about 2 agent-days instead of 3–4), since R3 built the generic part.

Total about 24–27 agent-days, six groups in parallel and one closing group.

### 9.3 Wave 8: the device services, and splitting out lx-net and lx-ipc

| Group | What | Agent-days |
|---|---|---:|
| **D, I, S, T, H** | Group 15's section 7 (display, input, sound, terminals, restart and hot-plug), without M (built in wave 6). T asks the kernel for session membership (section 4.4), not a process service | about 21–26 |
| **X2. Split lx-net and lx-ipc** | Their code out of linux-server into two programs on the service runtime; lx-net Transparent (kept slot-to-handle map, adopting net-server's handles), lx-ipc FailObjects | 4–5 |

Total about 25–31 agent-days, six groups. The X2 kill tests are:
- **lx-net:** a download and an ssh session survive.
- **lx-ipc:** console programs survive; the KDE session ends cleanly and SDDM returns.

### 9.4 Wave 9: the rest of the file side, the process mechanism, and lx-ipc's kept buffers

| Group | What | Agent-days |
|---|---|---:|
| **6b-1** | `inotify`, `fanotify` into vfs-server (watches kept) | 3 |
| **6b-2** | FUSE as a vfs-server back end | 3–4 |
| **6b-3** | Landlock, ACLs, ABAC checks in vfs-server (the ABAC policy store as kept state) | 3–4 |
| **6b-4** | `io_uring` and `aio`: each operation is forwarded to its descriptor's owner, with delegation, from linux-server | 3–4 |
| **7a** | The process tree, groups, sessions, PID translation, limits and namespace ids tidied into kernel mechanism with primitives for lx-proc (`task_creds`, `task_pgrp`, `task_limits`, `ns_set`) | 4–5 |
| **X3** | lx-ipc Transparent: pipe and socket buffers as kept objects, connection tables in kept state | 3–4 |

Total about 19–24 agent-days, six groups.

### 9.5 Wave 10: the process service, the last pieces, and the cleanup

| Group | What | Agent-days |
|---|---|---:|
| **7b-1** | lx-proc as its own program: `setuid` family policy, `prctl`, `unshare`/`setns` orchestration (direct calls to each namespace owner), UTS names, accounting, `syslog` | 4–5 |
| **7b-2** | `/proc` moved from linux-server to lx-proc, with the kernel info primitives (`task_info`, `mm_maps`, `sys_stats`) | 3 |
| **8-1** | ptrace and perf policy into lx-proc (the stop mechanism stays in the kernel) | 3–4 |
| **8-2** | System V shared memory into lx-ipc, on memory objects | 2–3 |
| **C** | Closing: in-kernel copies of waves 6–9 deleted after deployment; linux-server reduced to `io_uring`/`aio` (FailObjects); line counts; the final budget run; a kill test of every service under KDE in one session | 3–4 |

Total about 15–19 agent-days, five groups.

**As done (2026-11-24):** wave 10 ran as 7b-1, V1, 8-2, N, then 7b-2, 8-1, V2, then 10-C. 10-C deleted every in-kernel copy and switch-back word (decision 32). The io_uring/aio rings stayed in the kernel as mechanism (decision 34), so linux-server was not reduced to them: it keeps `/sys` (cpu ranges, efivars), exec's front half and the test calls, and is FailObjects now (it hosts no unkept pieces). See `docs/src/linux-server.md`, "What the kernel is after wave 10".

### 9.6 After wave 10: other systems' programs

The old waves 10–13 move one wave later and change shape (section 6.3):
- **Wave 11:** the `posix-abi` library, then the FreeBSD front ends in parallel by service (vfs-server, lx-net, lx-ipc, lx-proc, the kernel's kqueue), the `/freebsd` root and the dynamic linker's 30 calls first.
- **Wave 12:** the rest of FreeBSD, `pkg`, Wine on FreeBSD.
- **Waves 13 and later:** macOS, with mach-server as one more service.

### 9.7 Totals

| Wave | Groups at once | Agent-days |
|---|---:|---:|
| 6 foundation | 6 | 21–27 |
| 7 file service | 6 + 1 | 24–27 |
| 8 devices and two splits | 6 | 25–31 |
| 9 file side, process mechanism, ipc kept buffers | 6 | 19–24 |
| 10 process service, last pieces, cleanup | 5 | 15–19 |
| **Total, waves 6–10** | | **104–128** |

The plan's estimate for waves 6–9 was about 34–41 agent-days for one Linux server. The difference has three causes:
- Group 15's and Group 16's revised designs (four device services, a separate file service: together about 49–59 agent-days);
- the foundation of wave 6 (21–27), which makes every later service cheaper to add;
- restart support per service.

## 10. Risks, and what was not verified

- **The direct call's cost is an estimate.** If it misses the target (≤ 3 µs), the file service misses its budget on metadata tools (Group 16, section 9). In that case, Group 16's F2 fallback is to put the VFS inside zfs-server.
- **Kept state can carry the bug that caused the crash.** The checksums and the ladder limit this to one extra crash, but a corruption that passes the checks would repeat. Each service's kept layout should be small and checked field by field.
- **Re-sending relies on the idempotent marks being right.** A call marked wrongly (one that changes state) could be done twice. The marks are per number and argument, and should be reviewed as carefully as the copy table.
- **More processes:** each service costs a few MB of memory (linux-server's program is 340 KB plus stacks and windows) and a little boot time. Ten services is about 10–30 MB.
- **Programs' recovery is untested.** That KDE survives an input-service restart (Group 15), and that Firefox reconnects after an lx-net restart, are claims to verify in the kill tests, not facts.
- **The process tree as kernel mechanism** is a change of direction from step 7 of the first design. It needs the user's decision (question 2).
- **Nothing here ran.** The routing, the direct call and restarts are designs. The only measurement is the call counting of section 4.6, on exact profiles, with the approximations listed in 4.7.
- **KVM, not the NUC:** as for every earlier measurement.

## Appendix: reproducing

- `python tools/services/hops.py` prints, per workload, the forwarded calls per service, the redirects, the calls between services and the process events, and the added cost of shapes A, B and C. `--table` prints the markdown tables of section 4.6.
  - Options: `--dcall` (direct call, µs, default 2.5), `--queued` (9.0), `--fwd` (redirect forward, 2.4), `--post` (ring post, 0.3), `--extra-rings` (services that take process events besides the first, 2).
- **Data:** `tools/services/data/*.vfs.json` are Group 16's parsed profiles (wave 5, `tools/vfsbench/vfsparse.py` output; from E:\os-16\scratch\g16\logs): `kde25` (KDE login), `vw1` (apt-get, Firefox), `vw2` (find, ls -lR, git status, tar), `vw5` (make of 30 C files).
- **The service map is in the script** (`KERNEL_NR`, `PATH_NR`, `FILE_CHANGE_NR`, `PROC_NR`, `IPC_NR`, `SEC_NR`, `KIND`), so another map can be tried by editing those sets.
