use uefi::proto::console::text::Color;

use crate::arch;
use crate::capability::table::CapabilityTable;
use crate::capability::{CapType, Capability, Rights};
use crate::ipc::Endpoint;
use crate::shell::history::History;

pub struct ShellState {
    pub cap_table: CapabilityTable,
    pub endpoint: Endpoint,
    pub prompt_color: Color,
    pub cwd: [u8; 64],
    pub cwd_len: usize,
    pub history: History,
    pub last_status: i32,
    pub current_uid: u32,
    pub current_gid: u32,
    pub username: [u8; 32],
    pub username_len: usize,
}

impl ShellState {
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

    /// Returns the current working directory as a string slice.
    pub fn cwd_str(&self) -> &str {
        core::str::from_utf8(&self.cwd[..self.cwd_len]).unwrap_or("/bin")
    }

    /// Updates the current working directory.
    pub fn set_cwd(&mut self, new_cwd: &str) {
        let bytes = new_cwd.as_bytes();
        let len = bytes.len().min(self.cwd.len());
        self.cwd[..len].copy_from_slice(&bytes[..len]);
        self.cwd_len = len;
    }

    /// Returns true if the shell is currently running with superuser (UID 0) privileges.
    pub fn is_root(&self) -> bool {
        self.current_uid == 0
    }

    /// Returns the active username.
    pub fn username_str(&self) -> &str {
        core::str::from_utf8(&self.username[..self.username_len]).unwrap_or("root")
    }

    /// Switches the active shell user identity and synchronizes kernel credentials.
    pub fn set_user(&mut self, name: &str, uid: u32, gid: u32) {
        self.current_uid = uid;
        self.current_gid = gid;
        let bytes = name.as_bytes();
        let len = bytes.len().min(self.username.len());
        self.username[..len].copy_from_slice(&bytes[..len]);
        self.username_len = len;

        // Also update prompt color: LightRed for root, LightGreen for normal user
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

    /// Formats the interactive prompt (e.g. `hydra:/bin# ` for root, `hydra:/bin$ ` for standard user) into `out`.
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
