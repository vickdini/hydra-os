pub mod caps;
pub mod cpu;
pub mod efifs;
pub mod elf_cmd;
pub mod exitboot;
pub mod fs_cmds;
pub mod gnu_fs;
pub mod gnu_sys;
pub mod gnu_text;
pub mod help;
pub mod history_cmd;
pub mod info;
pub mod ipc;
pub mod mem;
pub mod misc;
pub mod power;
pub mod script;
pub mod status;
pub mod time;
pub mod translate;
pub mod task_cmds;
pub mod video;
pub mod zfs_cmds;

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
    FalseCommand, SeqCommand, SleepCommand, TrueCommand, UnameCommand, UptimeCommand, WhoamiCommand, YesCommand,
};
pub use gnu_text::{
    BasenameCommand, DirnameCommand, GrepCommand, HeadCommand, MoreCommand, TailCommand, WcCommand,
};
pub use help::HelpCommand;
pub use history_cmd::HistoryCommand;
pub use info::InfoCommand;
pub use ipc::IpcCommand;
pub use mem::{AllocCommand, HeapCommand, MemCommand};
pub use misc::{ClearCommand, ColorCommand, EchoCommand, PanicCommand, ScrollLockCommand, TrapCommand};
pub use power::{HaltCommand, RebootCommand, ShutdownCommand};
pub use script::ShCommand;
pub use status::StatusCommand;
pub use task_cmds::{KillCommand, PsCommand, SpawnCommand, SyncCommand, SyscallsCommand};
pub use time::TimeCommand;
pub use translate::{MapCommand, TranslateCommand, UnmapCommand};
pub use video::VideoCommand;
pub use zfs_cmds::{ZfsCommand, ZpoolCommand};

/// Static registry of all built-in commands and integrated programs.
/// To integrate a new command or program, instantiate it in this slice!
pub static COMMANDS: &[&dyn Command] = &[
    // Help and Shell State
    &HelpCommand,
    &InfoCommand,
    &StatusCommand,
    &HistoryCommand,
    &ClearCommand,
    &ColorCommand,
    &EchoCommand,
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
    &CapsCommand,
    &CapInsertCommand,
    &CapRevokeCommand,
    &IpcCommand,
    &TimeCommand,
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
    // Power Management
    &RebootCommand,
    &ShutdownCommand,
    &HaltCommand,
];

/// Returns all registered commands in the system.
pub fn all_commands() -> &'static [&'static dyn Command] {
    COMMANDS
}

/// Finds a command by name or alias.
pub fn find_command(name: &str) -> Option<&'static dyn Command> {
    for &cmd in COMMANDS {
        if cmd.name() == name || cmd.aliases().contains(&name) {
            return Some(cmd);
        }
    }
    None
}
