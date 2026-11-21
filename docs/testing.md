# Testing Hydra

Hydra is tested at two levels: **host unit tests** of the kernel's own source files, and
**system tests** that boot the kernel in QEMU.

## Host unit tests

The kernel (`src/`, all Rust) is compiled for the build machine, file by file, into ordinary
Rust test crates. Each crate includes kernel files with `#[path]` and stands in for what those
files call outside themselves (other kernel modules, hardware) with fakes.

| Crate | Covers |
|---|---|
| `tests/host` | The first crate (memory, exec, ELF, many Linux-layer modules, net-server's protocols, the shell parser) |
| `tests/host-t26` | Linux file layer: VFS, mounts, FUSE, inotify/fanotify, locks, ACLs, aio |
| `tests/host-t27` | Linux sockets, netlink, io_uring, select/epoll, timers, signalfd/pidfd/eventfd |
| `tests/host-t28` | Linux devices: the device table, DRM, ALSA sound, evdev, tty/pty |
| `tests/host-t29` | Linux processes: the syscall table, the process table, ptrace, execve, namespaces, limits, futexes |
| `tests/host-t30` | The forwarding core (`src/lx`) and IPC (`src/ipc`), on a simulated CPU |
| `tests/host-t31` | Tasks and the scheduler, sync primitives, native syscalls, capabilities |
| `tests/host-t32` | `src/arch` and `src/memory`, with a fake CPU (ports, MSRs, control registers) |
| `tests/host-t33` | fs, the ZFS client (against an in-memory server), personalities, packages, Linux security modules |
| `tests/host-t34` | The admin interface, video, the kernel's net-server client, the console, boot glue, the emergency shell |

Each crate is self-contained: its own `Cargo.toml`, `.cargo/config.toml` (target = the host),
`shim/` (an `x86_64` crate replacement whose privileged instructions act on a per-thread fake
CPU) and fakes. **Run a crate from its own directory**, because cargo reads that directory's
`.cargo/config.toml`:

```
cd tests/host-t30 && cargo test --offline
```

Run all of them: `python tools/host_tests_all.py` (one line per crate plus the total).

Some kernel files contain small host-only twins of hardware code
(`#[cfg(not(target_os = "uefi"))]`) and test hooks (`#[cfg(test)]`); the kernel build
(`target_os = "uefi"`) never compiles them.

Known bugs that are not fixed yet are tests marked `#[ignore = "BUG: ..."]`; list them with
`cargo test --offline -- --ignored`.

Code that cannot run on the host (the first instructions of a trap, firmware calls, the jump
to the high half) is listed per crate in `tests/host-tNN/UNTESTABLE.md`, with the reason.

## Coverage

`python tools/host_coverage.py` builds every crate with LLVM coverage (`-C
instrument-coverage`, into `<crate>/target/cov`), runs the tests and reports line coverage per
kernel file and per subsystem; a file several crates compile counts with its best number.
Options: `--files` (one line per file), `--filter src/lx`, `--crates host-t30`, `--json
out.json`, `--no-build` (re-read the last run). It needs the rustup component `llvm-tools`.

At the end of the test wave (2026-11-20): 95.0 % of the kernel's code lines (54,488 of
57,351); every file with code is compiled into a crate; only `fs/bootfs.rs`,
`arch/boot_services.rs` and `fs/firstboot.rs` are under 70 %, the rest of each being UEFI
firmware code. Before the wave: 13.8 %.

## System tests

The regression suite boots the ISO in QEMU (KVM in WSL) on an overlay of the pool and runs
the C test programs of `tests/linux/` inside the Ubuntu chroot: `scratch/suite_kvm.sh 2`
(85 tests), `scratch/suite_q35.sh 2 iommu "--iommu"` (with VT-d), `scratch/suite_loop.sh
TREE N` (N runs, with a task dump if a run stalls). The harness is `tools/hydra_run.py`.
