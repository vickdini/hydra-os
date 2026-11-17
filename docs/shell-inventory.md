# Kernel shell: command inventory

Microkernel wave 1, group 4 (shell, part 1). This lists every command of the in-kernel shell (`src/shell`, about 10,200 lines), grouped by what it needs from the kernel. It is the work list for part 2, when the commands move to the ring-3 `hydra-shell` and `src/shell` shrinks to the emergency prompt.

How to read the tables:
- **Calls into** names the kernel modules the command uses directly (`crate::...`). Every one of them needs an admin operation (see `docs/shell-admin-interface.md`) or another ring-3 path before the command can move.
- **E** marks the commands the **emergency prompt** keeps. The emergency prompt is the tiny in-kernel prompt that stays for when user space is broken (user decision, 2026-11-17).
- **H** marks the commands `hydra-shell` already has in part 1, through the admin interface or native system calls.

## Shell core (not commands)

| Part | Lines | Calls into | Notes |
|---|---|---|---|
| `mod.rs` (main loop, autostart) | 406 | `arch::fwcfg`, `compat::linux` (autostart of KDE, live session), `task` | Starts the desktop or the console. The emergency prompt keeps a small loop. |
| `login.rs` | 257 | `fs::ZfsClient` (reads `/etc/passwd` and friends in the pool), `compat::linux::abac`, `compat::linux::proc`, `task::spawn_linux_chroot` (PAM's `unix_chkpwd`) | Console login: administrators only. In part 2 the ring-3 shell can run the same helper itself. |
| `editor.rs`, `history.rs`, `pager.rs` | 1,197 | `console` (keys, cursor, scrolling, `draw_scroll_viewport`) | Line editor and pager. Ring 3 needs only bytes on fd 0/1 plus ANSI cursor sequences. |
| `pipeline.rs`, `command.rs`, `state.rs` | 717 | `task::with_current_fds_mut` (redirects) | Pipes and `>` redirects into pool files. |
| `fs.rs` | 589 | `fs::bootfs`, `fs::client` | Path helpers and the boot-file re-exports. The boot-file code itself moved to `src/fs/bootfs.rs` in part 1. |

## Commands by what they need

### Shell state and console only (no kernel internals except the console)

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `help` (`?`) | help.rs | console | E | H |
| `info` (`version`, `about`) | info.rs | console | | |
| `history` (`hist`) | history_cmd.rs | console | | |
| `clear` (`cls`) | misc.rs | console | E | |
| `color` | misc.rs | console | | |
| `echo` | misc.rs | console | E | H |
| `cursor` | misc.rs | console (cursor shape) | | |
| `scroll` (`scrolllock`, `slock`) | misc.rs | console (scroll lock) | | |
| `sh` (`source`, `.`) | script.rs | `fs::client` (script file) | | |
| `true`, `false`, `seq`, `yes`, `sleep` | gnu_sys.rs | `arch::pit`, console | | |
| `basename`, `dirname` | gnu_text.rs | none | | |
| `whoami` (`id`) | gnu_sys.rs | shell state | E | |
| `su`, `sudo` | gnu_sys.rs + login.rs | login helper (`task::spawn_linux_chroot`, `compat::linux`) | | |

### Files: the pool (through the file server) and the boot volume

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `pwd`, `cd` (`chdir`) | gnu_fs.rs | `fs::client` (resolve) | E | H |
| `ls` (`dir`) | fs_cmds.rs | `fs::client`, `fs::zfs::types` | E | H |
| `cat` (`type`) | fs_cmds.rs | `fs::client`, `task::with_current_fds_mut` | E | H (first 4 KiB) |
| `write` (`append`) | fs_cmds.rs | `fs::client` | | |
| `touch`, `mkdir`, `rmdir`, `rm` (`unlink`), `cp` (`copy`), `mv` (`rename`), `stat`, `df`, `du` | gnu_fs.rs | `fs::client`, `fs::zfs::types` | `cp` | |
| `head`, `tail`, `wc`, `grep`, `more` (`less`, `page`) | gnu_text.rs | `fs::client`, `task::with_current_fds_mut`, console | | |
| `efifs` (`ls`, `cat`, `run`) | efifs.rs | `fs::bootfs` (UEFI boot volume; only before `exitboot`) | | |

`cp /bin/x.elf /ubuntu/tmp/x.elf` (boot file to pool) is what every test script does, so the emergency prompt keeps `cp`.

### Tasks and programs

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `ps` (`tasks`, `threads`) | task_cmds.rs | `task` (scheduler table), `admin::DEMO_WORKER_COUNTER` | E | H |
| `spawn` | task_cmds.rs | `task` (kernel and ring-3 demo tasks), `syscall`, `ipc::endpoint` | | |
| `kill` | task_cmds.rs | `task` | E | |
| `syscalls` (`sys`, `syscall`) | task_cmds.rs | `arch::syscall` (counters) | | |
| `sync` (`locks`, `waiters`) | task_cmds.rs | `sync` (lock and wait-queue statistics) | | |
| `elf` (`elf64`, `runelf`) | elf_cmd.rs | `task::elf`, `fs::client`, `arch::boot_services` | | |
| `ushell` | ushell.rs | `admin::launch_shell`, `task` | | (starts it) |

### Memory and the CPU

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `mem` (`memory`) | mem.rs | `memory` (frame allocator, heap, memory map) | E | H |
| `alloc`, `heap` | mem.rs | `memory::heap` | | |
| `translate` (`v2p`), `map`, `unmap` | translate.rs | `memory::paging` | | |
| `cpu` | cpu.rs | `arch::cpu` (CPUID) | | |
| `time` (`date`) | time.rs | `memory::paging` (RTC/TSC readout) | | |
| `status` | status.rs | `memory`, `capability::table` | | |

### Services, IPC and capabilities

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `service` (`rs`, `daemon`, `daemons`): `status`/`list` | service_cmd.rs | `task::supervisor`, `ipc::service` | E | H |
| `service restart`, `kill`, `start`, `tick` | service_cmd.rs | `task::supervisor` | E (`restart`) | |
| `ipc` | ipc.rs | `ipc` (endpoint ping-pong) | | |
| `caps` (`cspace`), `cap_insert`, `cap_revoke` | caps.rs | `capability` | | |

### Storage: ZFS and disks

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `zpool` `status`, `list` | zfs_cmds.rs | `fs::zfs` | E (`status`) | H |
| `zfs` `list`, `snap`, `cat`, `selftest`, `verify`, `fsck`, `write`, `repair` | zfs_cmds.rs | `fs::zfs`, `fs::client` | | |
| `disks` (`storage`, `lsblk`, `fdisk`) | zfs_cmds.rs | `fs::zfs` (block devices) | | |
| `usbdisk` `list`, `test`, `speed` | usbdisk.rs | `ipc::service`, `ipc::protocol`, `fs::zfs::POOL_ON_USB`, `arch::pit` | | |

### Network

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `ifconfig` (`ip`, `netstat`) | net_cmds.rs | `net` (interface) | | |
| `dhcp` (`dhclient`, `renew`), `dns` (`nslookup`, `host`, `resolve`), `ping` | net_cmds.rs | `net` | | |
| `wget` (`fetch`, `curl`) | net_cmds.rs | `net::http`, `fs::client` (saves the file) | | |

The network stack moves to a ring-3 `net-server` in wave 2 (group 2). These commands should then talk to that server, not to the kernel.

### Linux root and chroot

| Command | File | Calls into | E | H |
|---|---|---|---|---|
| `linux chroot <root> <prog> [args]` | linux_cmd.rs | `task::spawn_linux_chroot`, `compat::linux` (tty session), `task::wait` | E | |
| `linux status`/`info`, `test`, `run` | linux_cmd.rs | `compat::linux`, `task::spawn_linux_elf`, `fs` | | |
| `linux trace`, `prof` (`on`, `off`, `reset`, `tune`, `waits`, `sample`) | linux_cmd.rs | `compat::linux` (tracing and profiler) | | |
| `linux plasma` | linux_cmd.rs | `compat::linux`, `video::splash`, `arch::smp` | | |
| `linux rootfs` (`install`, `show`, ...) | linux_cmd.rs | `pkg::rootfs`, `fs` | | |
| `linux wayland`, `linux click` | linux_cmd.rs | `wayland`, mouse | | (group 3 removes them) |

These commands are clients of the Linux layer, which will itself move out of the kernel in steps (group 6). In part 2 they should become requests to that layer's server, not admin operations of the kernel (see the admin interface design, "Linux-root operations").

### Graphics and the desktop (group 3)

| Command (aliases) | File | Calls into | Notes |
|---|---|---|---|
| `video` (`gop`, `fb`) | video.rs | `video` | Group 3 deletes it. |
| `plasma` (`startplasma`, `wayland`, `gui`, `desktop`) | plasma_cmd.rs | `video`, `arch::mouse`, `task::spawn_linux_elf` | Group 3 deletes it. |

### Boot, hardware and fault tests

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `exitboot` (`takeover`, `baremetal`, `hwmode`) | exitboot.rs | `arch::boot_services` | E | |
| `panic` | misc.rs | (kernel panic on purpose) | | |
| `trap` (`int3`, `breakpoint`) | misc.rs | `arch` (breakpoint exception) | | |

### Power

| Command (aliases) | File | Calls into | E | H |
|---|---|---|---|---|
| `shutdown` (`poweroff`, `exit`, `logout`) | power.rs | `arch::power` | E | H (`shutdown`, `poweroff`) |
| `reboot` (`restart`) | power.rs | `arch::power` | E | H |
| `halt` | power.rs | `arch::power` | E | |

Note: in the kernel shell `exit` is an alias of `shutdown`. In `hydra-shell` `exit` (and Ctrl+D) leaves `hydra-shell` and returns to the kernel shell. This difference is deliberate in part 1, so `ushell` can be left; part 2 must decide what `exit` means once `hydra-shell` is the console.

## The emergency prompt (proposal)

Kept in the kernel after part 2: `help`, `echo`, `clear`, `whoami`, `pwd`, `cd`, `ls`, `cat`, `cp`, `ps`, `kill`, `mem`, `service status` and `service restart`, `zpool status`, `exitboot`, `linux chroot` (to start the Linux root by hand), `shutdown`, `reboot`, `halt`. About 20 commands. It needs only the console, the scheduler table, the supervisor, the file server and power, which are all in the kernel anyway. Everything else moves to `hydra-shell`.

## What `hydra-shell` has in part 1

`help`, `echo`, `pwd`, `cd`, `ls`, `cat` (first 4 KiB), `uname`, `ps`, `mem`, `service` (`status`, `list`), `zpool` (`status`, `list`), `shutdown`/`poweroff`, `reboot`, `exit`. The output text is copied from the kernel commands, so the same command prints the same lines (numbers that change from moment to moment aside).

## Other kernel code that used the shell

Before part 1, kernel code outside `src/shell` called into it:
- `fs/client.rs`, `task/elf.rs`, `task/scheduler.rs`, `arch/bootdisk.rs`: the boot-file helpers (`read_boot_file`, `open_root_volume`, `path_to_cstr16`, `fw_read`). Now in `src/fs/bootfs.rs`.
- `fs/zfs/mod.rs`, `task/supervisor.rs`: `usbdisk::POOL_ON_USB`. Now `fs::zfs::POOL_ON_USB`.

After part 1, `grep -rn "crate::shell" src --include=*.rs` outside `src/shell` finds nothing. The only remaining link is `main.rs` calling `shell::run()` to start the console.
