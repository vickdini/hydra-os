//! # Shell Subsystem: Interactive Session State & Credential Context
//!
//! Defines [`ShellState`], the per-session context holding the shell's capability table,
//! IPC endpoint, working directory, command history, exit status, and active POSIX user/group
//! credentials.
//!
//! ## Architectural Role & Design Rationale
//! Instead of scattering mutable global variables across built-in shell commands, all session
//! state is encapsulated within a single [`ShellState`] struct passed by mutable reference to
//! every [`crate::shell::Command::execute`] invocation. When the user switches identities (e.g.
//! via `su` or `sudo`), [`ShellState::set_user`] synchronizes the shell's UID/GID directly with
//! the underlying kernel task's credential block.
//!
//! ## Key Types & Interfaces
//! - [`ShellState`]: Encapsulates capabilities, IPC endpoint, `cwd`, `History`, `last_status`, and UID/GID identity.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (reads `CR3` via [`crate::arch::cpu::read_state`] to seed initial address-space capability)
//! - Hardware Interaction: Reads architectural CPU state on initialization; synchronizes with [`crate::task`]
//! - Concurrency: Owned by the interactive shell task and passed mutably down the command call stack

use uefi::proto::console::text::Color;

use crate::arch;
use crate::capability::table::CapabilityTable;
use crate::capability::{CapType, Capability, Rights};
use crate::ipc::Endpoint;
use crate::shell::history::History;

/// Persistent session state for the Hydra interactive shell.
///
/// # Concurrency & Thread Safety
/// Owned exclusively by the interactive shell loop (`shell::run`) and passed via `&mut ShellState`
/// to built-in commands. Synchronizes UID/GID mutations with the current kernel task via
/// [`crate::task::with_current_task_mut`].
///
/// # Lifetime & Cleanup
/// Instantiated once at shell startup via [`ShellState::new()`] and lives for the duration of
/// the interactive console session.
pub struct ShellState {
    /// Capability table holding object capabilities owned by the shell session.
    pub cap_table: CapabilityTable,
    /// Default synchronous IPC endpoint used by shell diagnostic commands.
    pub endpoint: Endpoint,
    /// Console foreground color used when rendering the interactive prompt.
    pub prompt_color: Color,
    /// Fixed-size buffer storing the current working directory path as UTF-8 bytes.
    pub cwd: [u8; 64],
    /// Number of valid UTF-8 bytes currently stored in `cwd`.
    pub cwd_len: usize,
    /// Circular ring buffer of recent commands entered during this session.
    pub history: History,
    /// Exit status code (`$?`) of the most recently executed command (`0` indicates success).
    pub last_status: i32,
    /// Active POSIX User ID (UID) of the shell session (`0` for `root`, `1000` for `hydra`).
    pub current_uid: u32,
    /// Active POSIX Group ID (GID) of the shell session.
    pub current_gid: u32,
    /// Fixed-size buffer storing the active username as UTF-8 bytes.
    pub username: [u8; 32],
    /// Number of valid UTF-8 bytes currently stored in `username`.
    pub username_len: usize,
}

impl ShellState {
    /// Initializes a new [`ShellState`] with default capabilities, `/bin` working directory, and `hydra` (UID 1000) credentials.
    ///
    /// Populates `cap_table` with root `AddressSpace` and `Endpoint` capabilities and
    /// synchronizes the running kernel task's UID/GID to `1000`.
    ///
    /// # Returns
    ///
    /// A fully initialized [`ShellState`] ready for the interactive REPL loop.
    pub fn new() -> Self {
        let mut cap_table = CapabilityTable::new();

        // Initialize root capabilities
        let cpu = arch::cpu::read_state();
        let _ = cap_table.insert(Capability::new(
            CapType::AddressSpace {
                root_cr3: cpu.cr3_frame.as_u64(),
            },
            Rights::ALL,
        ));
        let _ = cap_table.insert(Capability::new(
            CapType::Endpoint { endpoint_id: 1 },
            Rights(Rights::READ.0 | Rights::WRITE.0 | Rights::CALL.0),
        ));

        let mut cwd = [0u8; 64];
        let default_cwd = b"/bin";
        cwd[..default_cwd.len()].copy_from_slice(default_cwd);

        let mut username = [0u8; 32];
        let default_user = b"hydra";
        username[..default_user.len()].copy_from_slice(default_user);

        // Sync initial kernel task credentials to standard user hydra (UID 1000)
        crate::task::with_current_task_mut(|t| {
            t.uid = 1000;
            t.gid = 1000;
            t.euid = 1000;
            t.egid = 1000;
            t.suid = 1000;
            t.sgid = 1000;
        });

        Self {
            cap_table,
            endpoint: Endpoint::new(1),
            prompt_color: Color::LightGreen,
            cwd,
            cwd_len: default_cwd.len(),
            history: History::new(),
            last_status: 0,
            current_uid: 1000,
            current_gid: 1000,
            username,
            username_len: default_user.len(),
        }
    }

    /// Returns the current working directory as a UTF-8 string slice.
    pub fn cwd_str(&self) -> &str {
        core::str::from_utf8(&self.cwd[..self.cwd_len]).unwrap_or("/bin")
    }

    /// Updates the current working directory path stored in `self.cwd`.
    ///
    /// # Arguments
    ///
    /// * `new_cwd` - Normalized UTF-8 directory path (truncated if longer than 64 bytes).
    pub fn set_cwd(&mut self, new_cwd: &str) {
        let bytes = new_cwd.as_bytes();
        let len = bytes.len().min(self.cwd.len());
        self.cwd[..len].copy_from_slice(&bytes[..len]);
        self.cwd_len = len;
    }

    /// Returns `true` if the shell is currently running with superuser (`UID == 0`) privileges.
    pub fn is_root(&self) -> bool {
        self.current_uid == 0
    }

    /// Returns the active username as a UTF-8 string slice.
    pub fn username_str(&self) -> &str {
        core::str::from_utf8(&self.username[..self.username_len]).unwrap_or("root")
    }

    /// Switches the active shell user identity, updates the prompt color, and synchronizes kernel task credentials.
    ///
    /// # Arguments
    ///
    /// * `name` - New username string.
    /// * `uid` - New real, effective, and saved User ID.
    /// * `gid` - New real, effective, and saved Group ID.
    pub fn set_user(&mut self, name: &str, uid: u32, gid: u32) {
        self.current_uid = uid;
        self.current_gid = gid;
        let bytes = name.as_bytes();
        let len = bytes.len().min(self.username.len());
        self.username[..len].copy_from_slice(&bytes[..len]);
        self.username_len = len;

        // Also update prompt color: LightCyan for root, LightGreen for normal user
        if uid == 0 {
            self.prompt_color = Color::LightCyan;
        } else {
            self.prompt_color = Color::LightGreen;
        }

        // Sync kernel task credentials
        crate::task::with_current_task_mut(|t| {
            t.uid = uid;
            t.gid = gid;
            t.euid = uid;
            t.egid = gid;
            t.suid = uid;
            t.sgid = gid;
        });
    }

    /// Formats the interactive prompt (e.g., `hydra:/bin# ` for root or `hydra:/bin$ ` for standard user) into `out`.
    ///
    /// Appends `[SCROLL]` before the prompt sigil when console scroll-lock mode is active.
    ///
    /// # Arguments
    ///
    /// * `out` - Scratch byte buffer used to assemble the formatted prompt string.
    ///
    /// # Returns
    ///
    /// A UTF-8 string slice referencing `out` (or a static fallback if `out` is too small).
    pub fn format_prompt<'a>(&self, out: &'a mut [u8]) -> &'a str {
        let prefix = b"hydra:";
        let symbol: &[u8] = if self.is_root() {
            if crate::console::is_scroll_lock_active() {
                b" [SCROLL]# "
            } else {
                b"# "
            }
        } else {
            if crate::console::is_scroll_lock_active() {
                b" [SCROLL]$ "
            } else {
                b"$ "
            }
        };

        let total = prefix.len() + self.cwd_len + symbol.len();
        if total <= out.len() {
            out[..prefix.len()].copy_from_slice(prefix);
            out[prefix.len()..prefix.len() + self.cwd_len].copy_from_slice(&self.cwd[..self.cwd_len]);
            out[prefix.len() + self.cwd_len..total].copy_from_slice(symbol);
            core::str::from_utf8(&out[..total]).unwrap_or(if self.is_root() { "hydra# " } else { "hydra$ " })
        } else {
            if self.is_root() { "hydra# " } else { "hydra$ " }
        }
    }
}
