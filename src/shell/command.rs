//! # Shell Subsystem: Command Trait & Numeric Argument Parsers
//!
//! Defines the polymorphic [`Command`] interface implemented by all built-in shell commands
//! and provides overflow-checked integer parsing utilities for command-line arguments.
//!
//! ## Architectural Role & Design Rationale
//! By standardizing every built-in utility behind the [`Command`] trait (`Sync`), the shell
//! can store a static registry of trait object references (`&'static dyn Command`) without
//! heap allocation. Shared numeric parsers (`parse_hex`, `parse_u64`, `parse_u32`, `parse_usize`)
//! avoid code duplication across hardware inspection and memory management commands.
//!
//! ## Key Types & Interfaces
//! - [`Command`]: Core trait defining command metadata (`name`, `aliases`, `description`, `usage`) and execution (`execute`).
//! - `parse_hex`: Parses hexadecimal strings (with optional `0x`/`0X` prefix) into `u64`.
//! - `parse_u64`: Parses decimal or `0x`-prefixed hexadecimal strings into `u64`.
//! - `parse_u32`: Parses decimal or hexadecimal strings into `u32`.
//! - `parse_usize`: Parses decimal or hexadecimal strings into `usize`.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (pure string parsing and trait dispatch)
//! - Concurrency: Trait objects require `Sync` for static immutable registration

use crate::shell::state::ShellState;

/// Common interface that all built-in shell commands and integrated programs implement.
///
/// Implementations are stateless unit structs stored in a global static slice and invoked
/// synchronously by the shell dispatcher.
pub trait Command: Sync {
    /// Returns the primary invocation keyword (e.g., `"mem"`, `"help"`, `"alloc"`).
    fn name(&self) -> &'static str;

    /// Returns alternative invocation names (e.g., `["?"]` for `help`, `["memory"]` for `mem`).
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// Returns a brief one-line description shown in the `help` manual listing.
    fn description(&self) -> &'static str;

    /// Returns the command syntax and argument usage pattern.
    fn usage(&self) -> &'static str {
        ""
    }

    /// Executes the command with the parsed argument slice and mutable shell session state.
    ///
    /// # Arguments
    ///
    /// * `args` - Slice of command-line arguments excluding the command name itself.
    /// * `state` - Mutable reference to the active [`ShellState`].
    fn execute(&self, args: &[&str], state: &mut ShellState);
}

/// Parses an ASCII hexadecimal string (with or without a `0x`/`0X` prefix) into a 64-bit unsigned integer.
///
/// Trims leading and trailing whitespace, strips any `0x` or `0X` prefix, and accumulates
/// hexadecimal digits using checked arithmetic to prevent silent integer overflow.
///
/// # Arguments
///
/// * `s` - Input string slice containing hexadecimal digits.
///
/// # Returns
///
/// * `Some(val)` - The parsed 64-bit unsigned integer.
/// * `None` - If the string is empty, contains non-hexadecimal characters, or overflows `u64`.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    for &b in s.as_bytes() {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return None,
        };
        val = val.checked_mul(16)?.checked_add(digit)?;
    }
    Some(val)
}

/// Parses a decimal or `0x`-prefixed hexadecimal string into a 64-bit unsigned integer.
///
/// Automatically delegates strings starting with `0x` or `0X` to `parse_hex`, and parses
/// all other strings as base-10 unsigned integers using checked arithmetic.
///
/// # Arguments
///
/// * `s` - Input string slice representing a decimal or hexadecimal number.
///
/// # Returns
///
/// * `Some(val)` - The parsed `u64` value.
/// * `None` - If the string is empty, contains invalid characters, or overflows `u64`.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn parse_u64(s: &str) -> Option<u64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        parse_hex(s)
    } else {
        let mut val: u64 = 0;
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        for &b in s.as_bytes() {
            if !(b'0'..=b'9').contains(&b) {
                return None;
            }
            val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        }
        Some(val)
    }
}

/// Parses a decimal or `0x`-prefixed hexadecimal string into a 32-bit unsigned integer.
///
/// # Arguments
///
/// * `s` - Input string slice representing a decimal or hexadecimal number.
///
/// # Returns
///
/// * `Some(val)` - The parsed `u32` value if it fits within `0..=u32::MAX`.
/// * `None` - If parsing fails or the value exceeds `u32::MAX`.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn parse_u32(s: &str) -> Option<u32> {
    parse_u64(s).and_then(|v| u32::try_from(v).ok())
}

/// Parses a decimal or `0x`-prefixed hexadecimal string into a pointer-sized unsigned integer (`usize`).
///
/// # Arguments
///
/// * `s` - Input string slice representing a decimal or hexadecimal number.
///
/// # Returns
///
/// * `Some(val)` - The parsed `usize` value.
/// * `None` - If parsing fails or the value overflows `usize`.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn parse_usize(s: &str) -> Option<usize> {
    parse_u64(s).and_then(|v| usize::try_from(v).ok())
}
