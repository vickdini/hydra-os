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

        Self {
            cap_table,
            endpoint: Endpoint::new(1),
            prompt_color: Color::LightCyan,
            cwd,
            cwd_len: default_cwd.len(),
            history: History::new(),
            last_status: 0,
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

    /// Formats the interactive prompt (e.g. `hydra:/bin> ` or `hydra:/bin [SCROLL]> `) into `out`.
    pub fn format_prompt<'a>(&self, out: &'a mut [u8]) -> &'a str {
        let prefix = b"hydra:";
        let scroll_suffix: &[u8] = if crate::console::is_scroll_lock_active() {
            b" [SCROLL]> "
        } else {
            b"> "
        };
        let total = prefix.len() + self.cwd_len + scroll_suffix.len();
        if total <= out.len() {
            out[..prefix.len()].copy_from_slice(prefix);
            out[prefix.len()..prefix.len() + self.cwd_len].copy_from_slice(&self.cwd[..self.cwd_len]);
            out[prefix.len() + self.cwd_len..total].copy_from_slice(scroll_suffix);
            core::str::from_utf8(&out[..total]).unwrap_or("hydra> ")
        } else {
            "hydra> "
        }
    }
}
