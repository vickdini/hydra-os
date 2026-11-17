# The admin interface: what the console shell asks the kernel for

Microkernel wave 1 and 2, group 4 (shell, parts 1 and 2). The console shell is the ring-3 program `hydra-shell`. The kernel has no shell any more, only a tiny emergency prompt. `hydra-shell` reaches the kernel through a small, explicit set of kernel calls: the **admin interface**. This document describes it (version 2) and how the console is started.

Code:
- `src/admin/proto.rs`: the whole ABI (operation numbers, the call block, the records). It has no dependencies, so ring-3 programs include it as source with `#[path]`, as the drivers do with `src/ipc/protocol.rs`.
- `src/admin/mod.rs`: authorization, copying, the dispatcher, and `launch_shell`.
- `src/admin/console.rs`, `session.rs`, `system.rs`, `storage.rs`, `net.rs`, `linux.rs`: the operations, by group.
- `src/admin/boot.rs`: the console after boot (the desktop, then `hydra-shell`, watched; the emergency prompt when it cannot run).
- `src/shell/mod.rs`: the emergency prompt.
- `userland/drivers/hydra-shell`: the console shell.
- `userland/drivers/admin-probe`: a test program (a native process that is not the console).

## Shape: one native system call

One native Hydra system call, `SYS_ADMIN` = 40, with an operation number inside a call block.

```
rdi -> struct AdminCall {
    op: u32, flags: u32,          // ADMIN_* operation, flags reserved (0)
    args: [u64; 4],               // numeric arguments
    in_ptr: u64, in_len: u64,     // input bytes: a path, NUL-separated words, file data (at most 4 MiB)
    out_ptr: u64, out_cap: u64,   // answer buffer
    err_len: u64,                 // out: length of an error message in the answer buffer
}
rax <- answer size (>= 0) or -errno
```

- **Answers are records, not text.** The kernel writes fixed-layout `#[repr(C)]` records back to back (names NUL-padded, read with unaligned reads). The shell formats them.
- **Report operations** are the exception, and are marked as such: for diagnostics that are deep kernel internals whose layout changes often (the Linux profiler, the USB disk tests, the IOMMU, the file server's checks, the page table walk, and the network commands until net-server), the kernel prints on the caller's standard output (fd 1), exactly what the old kernel shell printed. A pipe on fd 1 captures them like any other output, so `linux prof show | grep futex` works.
- **Size:** the result is the size of the whole answer; the kernel writes `min(answer, out_cap)` bytes; the caller retries with a larger buffer.
- **Errors:** `-errno`: `EPERM` (not the console), `EACCES` (not logged in), `ENOENT`, `EINVAL`, `EFAULT`, `ENOSYS` (unknown operation), `EIO` (failed). With a message for the user in the answer buffer and `err_len` when there is one.

Why a system call and not an IPC endpoint served by the kernel: the kernel is the only party that has the answers (scheduler table, frame allocator, supervisor, power, the console), so an endpoint would add a copy and a kernel receive loop for nothing. Why native: Linux processes use the Linux system call table, where 40 is `sendfile`; they cannot reach the admin interface at all.

## Operations (version 2)

Groups by the high nibble. `R` marks report operations.

| Op | Name | Input / args | Answer |
|---|---|---|---|
| **0x0_ meta** | | | |
| 0x01 | `ADMIN_VERSION` | | `u32` ABI version (2) |
| **0x1_ console and session** | | | |
| 0x10 | `ADMIN_CONSOLE_COLOR` | fg, bg (UEFI colours 0-15) | |
| 0x11 | `ADMIN_CONSOLE_READ` | timeout ms, output generation seen | `KeyEvent` (key, special key, timeout, or "other output appeared") |
| 0x12 | `ADMIN_CONSOLE_CTL` | `CTL_*`: cursor get/set, screen size, clear, scrollback, cursor shape, scroll lock, scrollback viewport, output generation | two `u64` |
| 0x18 | `ADMIN_SESSION_INFO` | | `SessionInfo` (uid, gid, name, logged in, protected, live, sudo fresh) |
| 0x19 | `ADMIN_SESSION_LOGIN` | `LOGIN_*` (login, su, sudo, restore, logout); `name\0password` | `LoginResult` |
| **0x2_ tasks** | | | |
| 0x20 | `ADMIN_TASK_LIST` | | `TaskListHeader` + `TaskRecord`s |
| 0x21 | `ADMIN_TASK_KILL` | pid | |
| 0x22 | `ADMIN_TASK_EXEC` | `path\0args...`, background flag | `ExecResult` |
| 0x23 | `ADMIN_SYSCALL_STATS` | | `SyscallStats` (MSRs, counters) |
| 0x24 | `ADMIN_ENDPOINT_LIST` | | `EndpointRecord`s |
| 0x25 | `ADMIN_REQUEST_LIST` | | `RequestHeader` + `RequestRecord`s |
| **0x3_ memory and the CPU** | | | |
| 0x30 | `ADMIN_MEM_INFO` | | `MemInfo` |
| 0x31 | `ADMIN_CPU_STATE` | | `CpuState` (CR0, CR2, CR3, CR4) |
| 0x32 | `ADMIN_RTC_TIME` | | `RtcTime` |
| 0x33 | `ADMIN_TRANSLATE` R | address | page table walk (the caller's address space) |
| 0x34 | `ADMIN_HEAP_TEST` | | the kernel heap's self-test |
| **0x4_ services** | | | |
| 0x40 | `ADMIN_SERVICE_LIST` | | `ServiceRecord`s |
| 0x41 | `ADMIN_IRQ_LIST` | | `IrqRecord`s |
| 0x42 | `ADMIN_SERVICE_CTL` | `SVCCTL_*` (restart, kill, start, tick); name | pid `u64` |
| 0x43 | `ADMIN_IOMMU` R | status, faults, rogue-DMA test | |
| **0x5_ storage** (wrappers over the ZFS file server) | | | |
| 0x50 | `ADMIN_POOL_STATUS` | | `PoolStatus` |
| 0x51 | `ADMIN_DIR_LIST` | path | `DirHeader` + `DirRecord`s |
| 0x52 | `ADMIN_LOOKUP` | path | `LookupRecord` |
| 0x53 | `ADMIN_FS_OP` | `FS_*` (mkdir, mkdir -p, rmdir, unlink, copy, rename, touch, write, append, sync, snapshot); `path[\0second]` | txg `u64` |
| 0x54 | `ADMIN_FILE_STAT` | path | `StatRecord` |
| 0x55 | `ADMIN_DATASET_LIST` | | `DatasetHeader` + `DatasetRecord`s |
| 0x56 | `ADMIN_ZFS_DIAG` R | selftest, verify, fsck (repair); dir | |
| 0x57 | `ADMIN_DISK_INFO` | | `DiskInfo` |
| 0x58 | `ADMIN_USBDISK` R | list, test, speed | |
| **0x6_ network** (temporary, until net-server) | | | |
| 0x60 | `ADMIN_NET` R | `NET_*` (ifconfig, dhcp, dns, ping, wget); NUL-separated arguments | |
| **0x7_ power and fault tests** | | | |
| 0x70 | `ADMIN_POWER` | off, reboot, halt | does not return |
| 0x71 | `ADMIN_FAULT_TEST` | panic (now or after N s), breakpoint trap | |
| **0x8_ the Linux root** | | | |
| 0x80 | `ADMIN_LINUX_STATUS` | | `LinuxStats` |
| 0x81 | `ADMIN_LINUX_RUN` | `RUN_CHROOT` (`root\0program\0args`) or `RUN_FILE` (`path\0args`), `RUN_FOREGROUND` | `RunResult` |
| 0x82 | `ADMIN_LINUX_WAIT` | pid (the console's foreground process only) | `WaitResult` |
| 0x83 | `ADMIN_LINUX_TEST` R | | |
| 0x84 | `ADMIN_LINUX_TRACE` | on/off; name filter | |
| 0x85 | `ADMIN_LINUX_PROF` R | `PROF_*` | |
| 0x86 | `ADMIN_LINUX_PLASMA` R | root, nologin | |

File contents are read with the native `open`/`read` calls every native program has; pipes use the native `pipe`/`dup2`.

## Authorization and the login

- **Only the admin console** may call `SYS_ADMIN`: the process the kernel itself started as the console shell (`admin::launch_shell`, recorded by task id), with the native personality. Everything else gets `-EPERM`: other native programs (tested with `admin-probe`), drivers and servers, and Linux processes (they reach `sendfile` instead; tested with `tests/linux/admin_perm_test.c`). When the console process ends, its authorization is withdrawn before the next one starts.
- **The login is the kernel's** (`src/admin/session.rs`, moved from the old kernel shell's `login.rs`): `hydra-shell` only draws the prompts and passes what was typed to `ADMIN_SESSION_LOGIN`. The kernel runs PAM's `unix_chkpwd` in the installed system with the password on its standard input, checks that the account is root or a member of `sudo`/`admin`, and records the console's user (and sets the console task's credentials). The shell never tells the kernel who it is. `su` (the target's password; none when the console is root), `sudo` (the user's own password, remembered 5 minutes) and the return after `sudo command` follow the same rules as before.
- **Before a login** the kernel refuses every operation (`-EACCES`, "not logged in") except the version, the console's own and the session's. So a broken console program cannot do anything before somebody logged in.
- Rules unchanged from the kernel shell: only root and `sudo`/`admin` members may log in at the console; no installed system with accounts means an unprotected console (as before); the live session is root without a password (as before).
- Programs the console starts (`linux chroot`, `linux run`, `elf`) run as the console's user, which the kernel recorded.

## The console: screen, keyboard and the line editor

- **Output:** native `write` to fd 1 goes to the kernel console (screen and serial port), as before.
- **Input:** `ADMIN_CONSOLE_READ` sleeps on the console input queue (the PS/2 interrupt and USB input wake it), with a timeout; no polling in ring 3. It returns special keys too (arrows, Home, End, Delete, PgUp, PgDn, F12, Esc), and "other output appeared" so the editor can draw its prompt again after a background message, as the kernel editor did.
- **The line editor** (`hydra-shell/src/editor.rs`) is the kernel editor's, in ring 3: history (Up/Down, Ctrl+P/N, `!!`, `history`), cursor keys, Ctrl+A/E/B/F/U/K/W/L, Tab completion of commands and pool paths, Ctrl+C (cancel the line), Ctrl+D (end the session on an empty line), the scrollback (PgUp/PgDn, Ctrl+S/F12 scroll lock, Esc).
- **A Linux program in the foreground** (`linux chroot ...`) gets the console as its terminal (`RUN_FOREGROUND` attaches its session to the console tty in the same kernel call that starts it, as before), and `hydra-shell` does not read keys until `ADMIN_LINUX_WAIT` returns, so Ctrl+C goes to the Linux program.

## What `exit` means

`exit`, `logout` and Ctrl+D on an empty line **end the session**: `hydra-shell` prints `logout`, the kernel forgets the user, and the login prompt comes back (as on a Linux console). Power is `shutdown`/`poweroff`, `reboot` and `halt`. (In the old kernel shell `exit` was an alias of `shutdown`; no test script used it.)

## The console after boot, and the emergency prompt

`src/admin/boot.rs` runs on the kernel's main thread (task 0) at the end of boot:
1. The desktop starts (`linux plasma`), unless a key was pressed during boot or QEMU's `opt/hydra/boot` asks for the console; then `[*] Hydra shell (...)` is printed, as before (the test harness waits for that line).
2. `hydra-shell` runs on the console. When it ends, it is started again (a new session: login first).
3. **The emergency prompt** (`src/shell/mod.rs`, inside the kernel) takes the console when:
   - `hydra-shell` cannot be started (a broken image, no memory);
   - `hydra-shell` ended 3 times in a row, each within 30 seconds of its start (a crash loop);
   - it was asked for at boot: the boot entry's option word `emergency`, a file `\hydra\emergency` on the EFI partition, or QEMU's `-fw_cfg name=opt/hydra/boot,string=emergency`.

   For tests, QEMU's `-fw_cfg name=opt/hydra/console,string=crash` makes `hydra-shell` end at once, which leads to the emergency prompt after the third try.

The emergency prompt asks for the same login (the kernel's rules) when passwords can be checked. Its commands: `help`, `cd`, `ls`, `cat`, `cp`, `ps`, `kill`, `mem`, `service` (status, `restart`, `start`), `zpool`, `linux chroot`, `ushell` (back to `hydra-shell`), `shutdown`/`poweroff`, `reboot`, `halt`. Its output is short and plain; it is for repairs, not for scripts.

## How the test harness keeps working

`hydra-shell` prints what the kernel shell printed: the boot line `[*] Hydra shell (...)`, `login: `, `Password: `, `[+] Logged in as ...`, the prompt `hydra:<cwd>$ ` (`#` for root), the same command output (`[+] Copied ...`, `[+] Linux process N exited with status S.`, `[*] Powering down system...`), `[sudo] password for ...` and `[+] Switched to superuser ...` for `sudo -s`. The suite, the power tests and the KDE scripts run unchanged.

## Moving parts out later

- **The Linux root group (`0x8_`)** is apart on purpose: when the Linux layer leaves the kernel (group 6), `ADMIN_LINUX_RUN`/`WAIT`/`STATUS`/`TRACE`/`PROF`/`PLASMA` become requests to the Linux server with the same records. The password check of the login runs a program of the installed system too (`unix_chkpwd`); it would become a request to the Linux server as well, while the decision (who may log in, who the console's user is) stays in the kernel's session.
- **Network (`0x6_`)** is temporary: `hydra-shell/src/net.rs` is the only user; when the ring-3 net-server exists, that module talks to it and `src/admin/net.rs` is deleted.
- **Storage (`0x5_`)** wraps the ZFS file server (already a ring-3 server); `hydra-shell` could call it over IPC directly, and the kernel operations would go away.
- **Report operations** could become records when their layout settles.
- What stays in the kernel for good: tasks, memory, services and the supervisor, interrupts, power, the console and the console session.
- Later: replace the recorded console task id by a capability handed out by the kernel when it starts the console, so it could be passed on (for example to a remote administration server).
