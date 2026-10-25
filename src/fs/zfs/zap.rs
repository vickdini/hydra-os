use super::types::DnodeType;

pub const MAX_ZAP_ENTRIES: usize = 32;

/// A directory entry in the ZFS Attribute Processor (ZAP).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZapEntry {
    pub name: [u8; 32],
    pub object_id: u64,
    pub obj_type: DnodeType,
    pub is_valid: bool,
}

impl ZapEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            object_id: 0,
            obj_type: DnodeType::None,
            is_valid: false,
        }
    }

    pub fn set(&mut self, name: &str, object_id: u64, obj_type: DnodeType) {
        let bytes = name.as_bytes();
        let len = if bytes.len() > 31 { 31 } else { bytes.len() };
        for i in 0..len {
            self.name[i] = bytes[i];
        }
        self.name[len] = 0;
        self.object_id = object_id;
        self.obj_type = obj_type;
        self.is_valid = true;
    }

    pub fn name_str(&self) -> &str {
        let mut len = 0;
        while len < self.name.len() && self.name[len] != 0 {
            len += 1;
        }
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// Micro-ZAP structure for directory and property lookups
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZapDirectory {
    pub entries: [ZapEntry; MAX_ZAP_ENTRIES],
    pub count: usize,
}

impl ZapDirectory {
    pub const fn new() -> Self {
        Self {
            entries: [ZapEntry::empty(); MAX_ZAP_ENTRIES],
            count: 0,
        }
    }

    pub fn insert(&mut self, name: &str, object_id: u64, obj_type: DnodeType) -> Result<(), &'static str> {
        // Check if existing entry with same name exists
        for entry in self.entries.iter_mut() {
            if entry.is_valid && entry.name_str() == name {
                entry.set(name, object_id, obj_type);
                return Ok(());
            }
        }

        // Find empty slot
        for entry in self.entries.iter_mut() {
            if !entry.is_valid {
                entry.set(name, object_id, obj_type);
                self.count += 1;
                return Ok(());
            }
        }

        Err("ZAP directory full (max 32 entries per directory)")
    }

    pub fn lookup(&self, name: &str) -> Option<&ZapEntry> {
        for entry in self.entries.iter() {
            if entry.is_valid && entry.name_str() == name {
                return Some(entry);
            }
        }
        None
    }

    pub fn remove(&mut self, name: &str) -> bool {
        for entry in self.entries.iter_mut() {
            if entry.is_valid && entry.name_str() == name {
                entry.is_valid = false;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }
}
