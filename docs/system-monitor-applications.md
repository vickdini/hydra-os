# KDE System Monitor's Applications view on Hydra (design note, wave 11 Group D)

**Status:** not implemented. System Monitor shows "Applications view is unsupported on
your system". This note says why, what it needs, and how Hydra could provide it.

## What System Monitor checks

The Applications page (plasma-systemmonitor, libksysguard's `ApplicationDataModel`, a
`CGroupDataModel`) is built on cgroup v2 and systemd's per-application units:

1. Its root is the user's systemd manager group:
   `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service` (or under
   `/sys/fs/cgroup/unified` on a hybrid hierarchy). If that directory does not exist the
   model reports "unavailable" and the page shows the message.
2. Under it, every application is a group of its own, named as systemd and KDE name them:
   `app.slice/app-<desktop id>-<random>.scope` or `app-<desktop id>@<random>.service`.
   The model lists the directories, reads each one's `cgroup.procs` for its processes,
   and turns the desktop id into a name and an icon (`KService`). CPU and memory per
   application are summed from the per-process data System Monitor already has (it does
   not need `cpu.stat` or `memory.current`, though it reads them when present).
3. The groups are made when an application starts: KDE's launcher (`KProcessRunner`)
   asks the **systemd user manager** on the session bus (`org.freedesktop.systemd1`,
   `StartTransientUnit`) to create the scope (with the new PID) or the service.

Hydra has a cgroup2 mount at `/sys/fs/cgroup` and per-process groups (moved by writing
`cgroup.procs`, as login managers do; root only), but no `user@<uid>.service` group, no
systemd user manager on the session bus, so KDE starts programs with a plain fork and no
group is ever made.

## Options

**A. A systemd user-manager shim (preferred).** A small D-Bus service on the session bus
named `org.freedesktop.systemd1` (like `hydra-logind` stands in for logind) that
implements only what KDE uses: `StartTransientUnit` for `app-*.scope` (properties
`PIDs`, `Description`, `Slice`) and the unit lookups (`GetUnit`, `GetUnitByPID`, the
unit's `Id`/`Description` properties), and emits `JobRemoved`. It creates the group under
`/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/app.slice/` and moves the
PID into it. Needs from the kernel/services: `mkdir`/`rmdir` of cgroup directories by the
user's own manager (delegation: the user owns its `user@<uid>.service` subtree, as
systemd delegates it), `cgroup.procs` writes by that owner for its own processes, an
empty group removed when its last process exits (or by the shim on `cgroup.events`
"populated 0"). Children stay in their parent's group (already so: fork inherits).
Effort: about 2–3 agent-days (shim, delegation rules in the cgroup code, tests), more
than this wave's 1.5-day budget.

**B. A synthetic read-only tree.** `/sys/fs/cgroup/.../app.slice/app-<name>-<pid>.scope`
made up from the process table: every process started by plasmashell, krunner or kwin
(a desktop launcher) heads an application with its descendants. No D-Bus, but names are
guesses (no desktop id), groups cannot be written, and it breaks programs that trust
`/proc/<pid>/cgroup` to match the tree. Not recommended.

## Where the code would go

The cgroup files are served with the other `/sys` and `/proc` files (Group K of wave 11
is moving the kernel's remaining copy of these out); the shim would be a userland
program in the image started by the session (an autostart or D-Bus activation file
for `org.freedesktop.systemd1` on the session bus).

## The Disks view ("Basic data partition")

System Monitor's disk sensors (ksystemstats' disk plugin) list the storage volumes Solid
knows that are mounted, named by their label or else their GPT partition name. Hydra's
root is a ZFS dataset (`hydrapool/...`), not a block device Solid knows, so the system
disk is never listed: in QEMU the Disks box is empty. On the NUC the one entry is a
mounted FAT partition whose GPT name is Windows' default "Basic data partition" (on the
live stick that is the stick's data partition; not checked on the machine). So the entry
itself is right as far as Solid goes, but the list misses the disk that matters. Showing
it needs the root pool's partition reported as the volume mounted at `/` (on Linux,
UDisks2 does this through libblockdev's ZFS support, which Hydra does not have); left
for later.
