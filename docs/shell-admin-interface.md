# The admin interface: what a ring-3 shell asks the kernel for

Microkernel wave 1, group 4 (shell, part 1). The kernel shell (`src/shell`) moves out of the kernel into the ring-3 program `hydra-shell`. Today the shell's commands call kernel internals directly (see `docs/shell-inventory.md`). In ring 3 they need a small, explicit set of kernel calls instead. This document designs that set, the **admin interface**, and describes the first part that is built.

Code:
- `src/admin/proto.rs`: the whole ABI (operation numbers, the call block, the answer records). It has no dependencies, so ring-3 programs include it as source with `#[path]`, as the drivers do with `src/ipc/protocol.rs`.
- `src/admin/mod.rs`: the kernel side (authorization, copying, the operations), and `launch_shell`, which starts `hydra-shell`.
- `userland/drivers/hydra-shell`: the ring-3 shell (built with the drivers, on `hydra-rt`).
- `src/shell/commands/ushell.rs`: the kernel shell command `ushell`, which runs `hydra-shell` on the console until it exits.

## Shape: one native system call

**Decision:** one native Hydra system call, `SYS_ADMIN` = 40, with an operation number inside a call block.

```
rdi -> struct AdminCall {
    op: u32, flags: u32,          // ADMIN_* operation, flags reserved (0)
    args: [u64; 4],               // numeric arguments
    in_ptr: u64, in_len: u64,     // input bytes: a path or a name (at most 4 KiB)
    out_ptr: u64, out_cap: u64,   // answer buffer
    err_len: u64,                 // out: length of an error message in the answer buffer
}
rax <- answer size (>= 0) or -errno
```

Why a system call and not an IPC endpoint served by the kernel:
- The kernel is the only party that has the answers today (scheduler table, frame allocator, supervisor table, power). An endpoint would add a message copy and a kernel-side receive loop for no gain.
- The block keeps the call number space small: one system call number for the whole family. Operations are grouped by the high nibble: `0x0_` meta, `0x1_` console, `0x2_` tasks, `0x3_` memory, `0x4_` services, `0x5_` storage, `0x7_` power. Part 2 adds groups (network, Linux root, see below).
- The same block can later travel unchanged in an IPC message, if a part of the interface moves to a server (see "Moving parts out later").

Why native and not Linux: Linux processes use the Linux system call table, where 40 is `sendfile`. They cannot reach the admin interface at all, by construction.

## Operations built in part 1

| Op | Name | Input | Answer |
|---|---|---|---|
| 0x01 | `ADMIN_VERSION` | none | `u32` ABI version (1) |
| 0x10 | `ADMIN_CONSOLE_COLOR` | `args[0]` foreground, `args[1]` background (UEFI colours 0-15) | none |
| 0x20 | `ADMIN_TASK_LIST` | none | `TaskListHeader` + `TaskRecord` per task |
| 0x30 | `ADMIN_MEM_INFO` | none | `MemInfo` (frames and kernel heap) |
| 0x40 | `ADMIN_SERVICE_LIST` | none | `ServiceRecord` per supervised service |
| 0x41 | `ADMIN_IRQ_LIST` | none | `IrqRecord` per interrupt line routed to a driver |
| 0x50 | `ADMIN_POOL_STATUS` | none | `PoolStatus` |
| 0x51 | `ADMIN_DIR_LIST` | path | `DirHeader` + `DirRecord` per entry |
| 0x52 | `ADMIN_LOOKUP` | path | `LookupRecord` (object, kind, size) |
| 0x70 | `ADMIN_POWER` | `args[0]`: `POWER_OFF` or `POWER_REBOOT` | does not return on success |

Reading file contents does not need an admin operation: `hydra-shell`'s `cat` uses the native `open`/`read` calls every native program has.

## Authorization

Only the **admin console** may call `SYS_ADMIN`:
- The kernel itself starts the console shell (`admin::launch_shell`) and records its task id. That task is the only authorized caller. When it exits, `ushell` withdraws the authorization (`admin::revoke_console`), so a later process that reuses the id gets nothing.
- The caller must also have the native (Hydra) personality.
- Everything else gets `-EPERM`: Linux processes (they cannot even reach the call, see above), drivers and servers (native, but not the console), and any other native program.
- The user's rights are checked where they are today: the console login admits only administrators (members of `sudo`), and `ushell` starts `hydra-shell` with the session's uid/gid. The part 1 operations need no more than that (in the kernel shell too, any logged-in administrator may power off). Part 2 operations that need root (for example `service restart`) must check the uid the kernel recorded for the console task, never a value the shell sends.

Later (part 2 or after): replace the recorded task id with a **capability** (a right in the console's capability table, `src/capability`), handed out by the kernel when it starts the console. The capability could then be passed on, for example to a remote administration server, without changing the operations.

## Output and errors

- **Answers are records, not text.** The kernel writes fixed-layout `#[repr(C)]` records back to back (names NUL-padded, read with unaligned reads). The shell formats them. This keeps formatting out of the kernel and makes the operations usable by other programs, such as a future `hydra-top`.
- **Size:** the result is the size of the whole answer. The kernel writes `min(answer, out_cap)` bytes. If the answer is larger, the caller retries with a larger buffer (as with `snprintf`). `hydra-shell` starts with 4 KiB and retries once with the size the kernel reported.
- **Errors:** the result is `-errno`: `EPERM` (not the console), `ENOENT` (no such file or object), `EINVAL` (bad argument), `EFAULT` (bad pointer), `ENOSYS` (unknown operation), `EIO` (the operation failed). When the failure has a message for the user, the kernel writes it (UTF-8) into the answer buffer and sets `err_len`. `hydra-shell` prints such messages with the same wording as the kernel shell, for example `[!] Cannot read file '/x': File or directory not found`.

## The console: screen, serial and keyboard

`hydra-shell` uses the same console paths as every native program. No new kernel code was needed for them:
- **Output:** native `write` to fd 1 goes to the kernel console, which draws on the screen and copies to the serial port (COM1), exactly like the kernel shell's `println!`. So the harness sees the same bytes on the serial log.
- **Colours:** `ADMIN_CONSOLE_COLOR`, so prompts and messages have the kernel shell's colours. (ANSI sequences would work on serial but the screen console takes UEFI colours.)
- **Input:** native `read` on fd 0 (the console input: keyboard and serial). It does not block, so `hydra-shell` polls it and sleeps 10 ms when there is nothing. The line editor (echo, backspace, Ctrl+C, Ctrl+D) is in `hydra-shell`.
- **While `hydra-shell` runs,** the kernel shell waits in `ushell` without reading keys (it only checks every 20 ms whether the program is alive), so every key goes to `hydra-shell`.

Part 2 should add a blocking console read (or a wait on console input) instead of polling, and give the line editor the kernel editor's history and cursor keys.

## How the harness keeps working

- **Part 1 changes nothing visible.** The kernel shell stays the default console; `hydra-shell` runs only when someone types `ushell`. The full suite passes unchanged.
- **Part 2 (when `hydra-shell` becomes the console):** `hydra-shell` prints the same login prompts (`login: `, `Password: `, `Logged in as ...`), the same prompt `hydra:<cwd>$ ` (`#` for root) and the same command output. `tools/hydra_run.py` matches only those strings, so it keeps working. Verified in part 1 for the ported commands: the VM test `scratch/ushell_kvm.sh` types the same commands into both shells, and the outputs are the same except for live numbers (ticks, free memory, interrupt counts).
- One known difference: in the kernel shell `exit` is an alias of `shutdown`; in `hydra-shell` it returns to the kernel shell. Part 2 must decide (probably: `exit` logs out, as on Linux, and the test scripts already use `shutdown`/`poweroff -f`).

## Moving parts out later

The Linux compatibility layer will leave the kernel in steps (group 6). The admin interface must not assume it stays:
- **No Linux operations in part 1.** `linux chroot`, `linux rootfs`, `linux prof` and friends are not admin operations. In part 2 they should be requests to the Linux layer (today in the kernel, later its server), in their own operation group (`0x8_`), so the group can become an IPC protocol of the Linux server without touching the others. Example: `ADMIN_LINUX_SPAWN` (start a program in a root, with the console as its terminal) and `ADMIN_LINUX_STATUS`.
- **Storage operations (`0x5_`)** are thin wrappers over the ZFS file server (a ring-3 server already). In part 2 `hydra-shell` can call the file server directly over IPC instead; the kernel operations then go away.
- **Network (`0x6_`, part 2):** the network stack moves to a ring-3 `net-server` in wave 2. The network commands should talk to that server, not to the kernel.
- What should stay in the kernel for good: tasks, memory, services and the supervisor, interrupts, power and the console.

## What part 2 needs

- Operations for the remaining commands (see the inventory): `kill`, `spawn`, service `restart`/`start`/`kill`, capabilities, syscall counters, lock statistics, page-table tools, `exitboot`, the file-writing commands (or native file calls: `create`, `write`, `unlink`, `mkdir`), network, Linux root.
- The console login in ring 3 (it runs PAM's `unix_chkpwd` helper, which `hydra-shell` could start itself through a Linux-root operation).
- The console starting `hydra-shell` instead of the kernel shell, with the kernel shell shrunk to the emergency prompt (when `hydra-shell` cannot start or dies repeatedly).
- A blocking console read.
