//! A model of the firmware's variable services for `efivars.rs` (put in place by
//! [`crate::fake::setup`]): variables in memory, `GetNextVariableName` order by insertion,
//! and statuses a test can force.

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use uefi::runtime::{VariableAttributes, VariableVendor};
use uefi::{CStr16, Guid, Status};

use crate::compat::linux::efivars::VarServices;

pub struct Fw {
    pub vars: Mutex<Vec<(String, Guid, u32, Vec<u8>)>>,
    /// A status every call fails with (`None`: they work).
    pub fail: Mutex<Option<Status>>,
    /// A status only `SetVariable` fails with.
    pub fail_set: Mutex<Option<Status>>,
    /// The size `GetNextVariableName` asks for once (to test the retry).
    pub name_too_small: Mutex<Option<usize>>,
}

pub static FW: Fw = Fw { vars: Mutex::new(Vec::new()), fail: Mutex::new(None), fail_set: Mutex::new(None), name_too_small: Mutex::new(None) };

pub fn reset() {
    FW.vars.lock().clear();
    *FW.fail.lock() = None;
    *FW.fail_set.lock() = None;
    *FW.name_too_small.lock() = None;
    crate::compat::linux::efivars::set_services(&FW);
}

/// Adds variable `name` of `guid`.
pub fn add(name: &str, guid: Guid, attrs: u32, data: &[u8]) {
    FW.vars.lock().push((String::from(name), guid, attrs, data.to_vec()));
}

/// The variable `name` of `guid`, if set.
pub fn get(name: &str, guid: Guid) -> Option<(u32, Vec<u8>)> {
    FW.vars.lock().iter().find(|v| v.0 == name && v.1 == guid).map(|v| (v.2, v.3.clone()))
}

fn name_of(n: &CStr16) -> String {
    let mut s = String::new();
    for c in n.iter() {
        s.push(char::from(*c));
    }
    s
}

impl VarServices for Fw {
    fn get(&self, name: &CStr16, vendor: &VariableVendor, buf: &mut [u8]) -> Result<(usize, u32), (Status, Option<usize>)> {
        if let Some(s) = *self.fail.lock() {
            return Err((s, None));
        }
        let n = name_of(name);
        let vars = self.vars.lock();
        let Some(v) = vars.iter().find(|v| v.0 == n && v.1 == vendor.0) else { return Err((Status::NOT_FOUND, None)) };
        if buf.len() < v.3.len() {
            return Err((Status::BUFFER_TOO_SMALL, Some(v.3.len())));
        }
        buf[..v.3.len()].copy_from_slice(&v.3);
        Ok((v.3.len(), v.2))
    }

    fn set(&self, name: &CStr16, vendor: &VariableVendor, attrs: VariableAttributes, data: &[u8]) -> Result<(), Status> {
        if let Some(s) = *self.fail.lock() {
            return Err(s);
        }
        if let Some(s) = *self.fail_set.lock() {
            return Err(s);
        }
        let n = name_of(name);
        let mut vars = self.vars.lock();
        let at = vars.iter().position(|v| v.0 == n && v.1 == vendor.0);
        if data.is_empty() {
            return match at {
                Some(i) => {
                    vars.remove(i);
                    Ok(())
                }
                None => Err(Status::NOT_FOUND),
            };
        }
        match at {
            Some(i) => vars[i] = (n, vendor.0, attrs.bits(), data.to_vec()),
            None => vars.push((n, vendor.0, attrs.bits(), data.to_vec())),
        }
        Ok(())
    }

    fn next(&self, name: &mut [u16], vendor: &mut VariableVendor) -> Result<(), (Status, Option<usize>)> {
        if let Some(s) = *self.fail.lock() {
            return Err((s, None));
        }
        if let Some(need) = self.name_too_small.lock().take() {
            return Err((Status::BUFFER_TOO_SMALL, Some(need)));
        }
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let cur = String::from_utf16_lossy(&name[..len]);
        let vars = self.vars.lock();
        let next = if cur.is_empty() {
            0
        } else {
            match vars.iter().position(|v| v.0 == cur && v.1 == vendor.0) {
                Some(i) => i + 1,
                None => return Err((Status::INVALID_PARAMETER, None)),
            }
        };
        let Some(v) = vars.get(next) else { return Err((Status::NOT_FOUND, None)) };
        let wide: Vec<u16> = v.0.encode_utf16().chain(core::iter::once(0)).collect();
        if wide.len() > name.len() {
            return Err((Status::BUFFER_TOO_SMALL, Some(wide.len())));
        }
        name[..wide.len()].copy_from_slice(&wide);
        vendor.0 = v.1;
        Ok(())
    }
}
