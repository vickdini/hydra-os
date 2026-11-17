# The console shell and the emergency prompt

- **Console shell:** [`userland/drivers/hydra-shell/`](../../userland/drivers/hydra-shell/) (ring 3)
- **Its kernel side:** [`src/admin/`](../../src/admin/) (the admin interface, `SYS_ADMIN` = 40)
- **Emergency prompt:** [`src/shell/mod.rs`](../../src/shell/mod.rs) (ring 0)

---

## Overview

Hydra's console shell used to live in the kernel (`src/shell`, about 10,000 lines). Since microkernel wave 2 (group 4) it is the ring-3 program `hydra-shell`, a native program on `hydra-rt` like the drivers. The kernel embeds it and starts it as the console at the end of boot (`src/admin/boot.rs`), starts it again whenever it ends, and authorizes only that process to use the admin interface. The design of the interface, the login rules and the start-up are in [`docs/shell-admin-interface.md`](../shell-admin-interface.md); what happened to each old command is in [`docs/shell-inventory.md`](../shell-inventory.md).

## hydra-shell

| File | What |
|---|---|
| `main.rs` | session, command table, pipes (`|`), redirects (`>`, `>>`), `!!`, scripts, programs of the pool |
| `editor.rs` | line editor: history, cursor keys, Readline control keys, Tab completion, scrollback |
| `history.rs`, `parse.rs` | command history ring (32 entries) and number parsers (host-tested) |
| `login.rs` | console login, `su`, `sudo`, `whoami` (the kernel decides; this asks) |
| `sys.rs` | system calls: `SYS_ADMIN`, native `open`/`read`/`pipe`/`dup2`; colours |
| `fs.rs` | pwd cd ls cat write touch mkdir rmdir rm cp mv stat df du |
| `text.rs` | echo head tail wc grep more basename dirname seq yes true false sleep |
| `system.rs` | info status clear color cursor scroll sync uname uptime ps kill syscalls elf mem heap cpu translate time service iommu shutdown reboot halt panic trap |
| `storage.rs` | zpool zfs disks usbdisk |
| `net.rs` | ifconfig dhcp dns ping wget (the only module that reaches the network) |
| `linux.rs` | linux status, test, run, chroot, plasma, trace, prof |

The prompt is `hydra:<cwd>$ ` (`#` for root), the output of each command is the old kernel shell's, and the test harness types into it unchanged. `exit`, `logout` and Ctrl+D end the session (back to `login:`).

## The emergency prompt

`src/shell/mod.rs` is the tiny in-kernel console for when user space is broken. It runs when `hydra-shell` cannot start or dies 3 times in a row within 30 s, or when asked for at boot (boot option `emergency`, file `\hydra\emergency` on the EFI partition, QEMU `-fw_cfg name=opt/hydra/boot,string=emergency`). It asks for the console login (when passwords can be checked) and offers `help`, `cd`, `ls`, `cat`, `cp`, `ps`, `kill`, `mem`, `service`, `zpool`, `linux chroot`, `ushell` (back to hydra-shell), `shutdown`, `reboot` and `halt`.
