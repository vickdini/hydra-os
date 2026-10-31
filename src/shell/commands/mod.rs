//! # Shell Commands: Built-in Command Registry & Dispatcher Table
//!
//! Aggregates all built-in shell commands, POSIX/GNU Coreutils implementations, and
//! microkernel diagnostic utilities into the global `COMMANDS` lookup table.
//!
//! ## Architectural Role & Design Rationale
//! Centralizing command registration in a static slice of `&'static dyn Command` references
//! enables zero-allocation command lookup (`find_command`), automatic `help` manual
//! generation, and Tab auto-completion across all built-in utilities.
//!
//! ## Key Types & Interfaces
//! - `COMMANDS`: Static registry slice containing every built-in [`Command`] implementation.
//! - `all_commands`: Returns the full slice of registered commands.
//! - `find_command`: Resolves a command by its primary name or any registered alias.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Dispatches to subsystem-specific commands
//! - Concurrency: Immutable static slice (`Sync`) safe for concurrent read access

/// Capability table (`CSpace`) inspection, insertion, and revocation commands.
pub mod caps;
/// CPU control register (`CR0`, `CR2`, `CR3`, `CR4`) diagnostic command.
pub mod cpu;
/// Low-level UEFI Simple File System boot partition diagnostic command.
pub mod efifs;
/// Standalone 64-bit ELF binary header inspector and Ring 3 runner.
pub mod elf_cmd;
/// UEFI `ExitBootServices` and bare-metal hardware takeover command.
pub mod exitboot;
/// Core ZFS file listing (`ls`), reading (`cat`), and Copy-on-Write writing (`write`) commands.
pub mod fs_cmds;
/// GNU Coreutils-compatible filesystem navigation and manipulation utilities.
pub mod gnu_fs;
/// GNU Coreutils-compatible system identity, privilege switching, and timing utilities.
pub mod gnu_sys;
/// GNU Coreutils-compatible text filtering, counting, and pagination utilities.
pub mod gnu_text;
/// Interactive manual and categorized command reference (`help`).
pub mod help;
/// Session command history viewer and re-execution utility (`history`).
pub mod history_cmd;
/// Architectural and microkernel subsystem overview (`info`).
pub mod info;
/// Synchronous capability-checked IPC ping-pong benchmark and test command (`ipc`).
pub mod ipc;
/// Physical memory map, frame allocator, and kernel heap diagnostic commands.
pub mod mem;
/// Console appearance, echo, scrollback, and hardware exception test commands.
pub mod misc;
/// System power management (`reboot`, `shutdown`, `halt`) commands.
pub mod power;
/// POSIX/Bash-compatible shell script interpreter (`sh`).
pub mod script;
/// Consolidated real-time system health dashboard (`status`).
pub mod status;
/// UEFI Real-Time Clock (RTC) and hardware timestamp counter (`RDTSC`) command.
pub mod time;
/// Virtual-to-physical 4-level page table walker and dynamic page mapper commands.
pub mod translate;
/// Preemptive task scheduler inspection (`ps`), spawning (`spawn`), and signaling (`kill`) commands.
pub mod task_cmds;
/// UEFI GOP framebuffer resolution mode switcher and test pattern generator (`video`).
pub mod video;
/// KDE Plasma 6 Wayland desktop compositor launcher (`plasma`).
pub mod plasma_cmd;
/// VirtIO-Net / e1000 network interface configuration, DHCP, DNS, ICMP ping, and HTTP `wget` commands.
pub mod net_cmds;
/// OpenZFS storage pool (`zpool`), dataset (`zfs`), and block device (`disks`) management commands.
pub mod zfs_cmds;
/// Linux ABI (`SYSCALL`/`SYSRET`) Ring 3 compatibility test suite command (`linux`).
pub mod linux_cmd;

use crate::shell::command::Command;

pub use caps::{CapInsertCommand, CapRevokeCommand, CapsCommand};
pub use cpu::CpuCommand;
pub use efifs::EfifsCommand;
pub use elf_cmd::ElfCommand;
pub use exitboot::ExitBootCommand;
pub use fs_cmds::{CatCommand, LsCommand, WriteCommand};
pub use gnu_fs::{
    CdCommand, CpCommand, DfCommand, DuCommand, MkdirCommand, MvCommand, PwdCommand, RmCommand,
    RmdirCommand, StatCommand, TouchCommand,
};
pub use gnu_sys::{
    FalseCommand, SeqCommand, SleepCommand, SuCommand, SudoCommand, TrueCommand, UnameCommand, UptimeCommand, WhoamiCommand, YesCommand,
};
pub use gnu_text::{
    BasenameCommand, DirnameCommand, GrepCommand, HeadCommand, MoreCommand, TailCommand, WcCommand,
};
pub use help::HelpCommand;
pub use history_cmd::HistoryCommand;
pub use info::InfoCommand;
pub use ipc::IpcCommand;
pub use mem::{AllocCommand, HeapCommand, MemCommand};
pub use misc::{ClearCommand, ColorCommand, CursorCommand, EchoCommand, PanicCommand, ScrollLockCommand, TrapCommand};
pub use power::{HaltCommand, RebootCommand, ShutdownCommand};
pub use script::ShCommand;
pub use status::StatusCommand;
pub use task_cmds::{KillCommand, PsCommand, SpawnCommand, SyncCommand, SyscallsCommand};
pub use time::TimeCommand;
pub use translate::{MapCommand, TranslateCommand, UnmapCommand};
pub use video::VideoCommand;
pub use plasma_cmd::PlasmaCommand;
pub use net_cmds::{DhcpCommand, DnsCommand, IfconfigCommand, PingCommand, WgetCommand};
pub use zfs_cmds::{DisksCommand, ZfsCommand, ZpoolCommand};
pub use linux_cmd::LinuxCommand;

/// Static registry of all built-in shell commands and integrated kernel utilities.
pub static COMMANDS: &[&dyn Command] = &[
    // Help and Shell State
    &HelpCommand,
    &InfoCommand,
    &StatusCommand,
    &HistoryCommand,
    &ClearCommand,
    &ColorCommand,
    &EchoCommand,
    &CursorCommand,
    &ScrollLockCommand,
    // Script Runner (Bash/POSIX)
    &ShCommand,
    // GNU Coreutils - Filesystem
    &PwdCommand,
    &CdCommand,
    &LsCommand,
    &CatCommand,
    &WriteCommand,
    &TouchCommand,
    &MkdirCommand,
    &RmdirCommand,
    &RmCommand,
    &CpCommand,
    &MvCommand,
    &StatCommand,
    &DfCommand,
    &DuCommand,
    // GNU Coreutils - Text & Inspection
    &HeadCommand,
    &TailCommand,
    &MoreCommand,
    &WcCommand,
    &GrepCommand,
    &BasenameCommand,
    &DirnameCommand,
    // GNU Coreutils - System & Scripting
    &UnameCommand,
    &WhoamiCommand,
    &SuCommand,
    &SudoCommand,
    &UptimeCommand,
    &SleepCommand,
    &SeqCommand,
    &YesCommand,
    &TrueCommand,
    &FalseCommand,
    // Kernel & Hardware Diagnostics
    &CpuCommand,
    &MemCommand,
    &AllocCommand,
    &HeapCommand,
    &TranslateCommand,
    &MapCommand,
    &UnmapCommand,
    &VideoCommand,
    &PlasmaCommand,
    &CapsCommand,
    &CapInsertCommand,
    &CapRevokeCommand,
    &IpcCommand,
    &TimeCommand,
    &DisksCommand,
    &IfconfigCommand,
    &DhcpCommand,
    &DnsCommand,
    &PingCommand,
    &WgetCommand,
    &ZpoolCommand,
    &ZfsCommand,
    &EfifsCommand,
    &PanicCommand,
    &TrapCommand,
    &ExitBootCommand,
    // Multitasking & Thread Management
    &PsCommand,
    &SpawnCommand,
    &KillCommand,
    &SyscallsCommand,
    &SyncCommand,
    &ElfCommand,
    &LinuxCommand,
    // Power Management
    &RebootCommand,
    &ShutdownCommand,
    &HaltCommand,
];

/// Returns the static slice of all registered built-in shell commands.
///
/// # Returns
///
/// A static slice of trait object references (`&'static [&'static dyn Command]`).
pub fn all_commands() -> &'static [&'static dyn Command] {
    COMMANDS
}

/// Searches the `COMMANDS` registry for a command matching `name` or any of its aliases.
///
/// # Arguments
///
/// * `name` - Command keyword or alias to look up.
///
/// # Returns
///
/// * `Some(&'static dyn Command)` - Matching command trait object.
/// * `None` - If no registered command or alias matches `name`.
pub fn find_command(name: &str) -> Option<&'static dyn Command> {
    for &cmd in COMMANDS {
        if cmd.name() == name || cmd.aliases().contains(&name) {
            return Some(cmd);
        }
    }
    None
}
