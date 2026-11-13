//! Tests for the shell's argument parsers (`src/shell/command.rs`) and the
//! command-history ring (`src/shell/history.rs`).

use hydra_hosttests::shell::command::{parse_hex, parse_u32, parse_u64, parse_usize};
use hydra_hosttests::shell::history::{History, MAX_CMD_LEN, MAX_HISTORY};

// ----------------------------------------------------------------- parsers

#[test]
fn parse_hex_accepts_prefix_case_and_whitespace() {
    assert_eq!(parse_hex("0x1F"), Some(0x1F));
    assert_eq!(parse_hex("0XdeadBEEF"), Some(0xDEAD_BEEF));
    assert_eq!(parse_hex("ff"), Some(0xFF), "prefix is optional");
    assert_eq!(parse_hex("  0x10  "), Some(0x10));
    assert_eq!(parse_hex("0xFFFFFFFFFFFFFFFF"), Some(u64::MAX));
}

#[test]
fn parse_hex_rejects_bad_input() {
    for s in ["", "0x", "   ", "0xG", "12 34", "-1", "0x10000000000000000", "0x0x1"] {
        assert_eq!(parse_hex(s), None, "{s:?}");
    }
}

#[test]
fn parse_u64_decimal_and_hex() {
    assert_eq!(parse_u64("0"), Some(0));
    assert_eq!(parse_u64("4096"), Some(4096));
    assert_eq!(parse_u64(" 42 "), Some(42));
    assert_eq!(parse_u64("0x1000"), Some(4096));
    assert_eq!(parse_u64("18446744073709551615"), Some(u64::MAX));
}

#[test]
fn parse_u64_rejects_bad_input() {
    for s in ["", " ", "12a", "+1", "-1", "1.5", "18446744073709551616", "ff"] {
        assert_eq!(parse_u64(s), None, "{s:?}");
    }
}

#[test]
fn parse_u64_trims_before_detecting_hex() {
    assert_eq!(parse_u64(" 0x10"), Some(16));
}

#[test]
fn parse_u32_and_usize_bounds() {
    assert_eq!(parse_u32("4294967295"), Some(u32::MAX));
    assert_eq!(parse_u32("4294967296"), None);
    assert_eq!(parse_u32("0xFFFFFFFF"), Some(u32::MAX));
    assert_eq!(parse_u32("0x100000000"), None);
    assert_eq!(parse_usize("123"), Some(123));
    assert_eq!(parse_usize("x"), None);
}

// ----------------------------------------------------------------- History

fn history_of(cmds: &[&str]) -> History {
    let mut h = History::new();
    for c in cmds {
        h.add(c);
    }
    h
}

#[test]
fn history_starts_empty() {
    let h = History::new();
    assert!(h.is_empty());
    assert_eq!((h.len(), h.total_count(), h.start_session_index()), (0, 0, 0));
    assert_eq!(h.get_from_latest(0), None);
    assert_eq!(h.get_by_index(0), None);
    assert_eq!(h.get_by_index(1), None);
}

#[test]
fn history_newest_first_and_by_index() {
    let h = history_of(&["ls", "cd /", "zfs list"]);
    assert_eq!(h.len(), 3);
    assert_eq!(h.get_from_latest(0), Some("zfs list"));
    assert_eq!(h.get_from_latest(2), Some("ls"));
    assert_eq!(h.get_from_latest(3), None);
    assert_eq!(h.get_by_index(1), Some("ls"), "indices are 1-based like bash");
    assert_eq!(h.get_by_index(3), Some("zfs list"));
    assert_eq!(h.get_by_index(4), None);
    assert_eq!(h.start_session_index(), 1);
}

#[test]
fn history_trims_and_skips_blank_bang_bang_and_repeats() {
    let h = history_of(&["  ls  ", "", "   ", "!!", "ls", "pwd", "ls"]);
    assert_eq!(h.total_count(), 3);
    assert_eq!(h.get_by_index(1), Some("ls"));
    assert_eq!(h.get_by_index(2), Some("pwd"));
    assert_eq!(h.get_by_index(3), Some("ls"), "only consecutive repeats are dropped");
}

#[test]
fn history_ring_evicts_oldest() {
    let mut h = History::new();
    let total = MAX_HISTORY + 5;
    for i in 1..=total {
        h.add(&format!("cmd {i}"));
    }
    assert_eq!(h.len(), MAX_HISTORY);
    assert_eq!(h.total_count(), total);
    assert_eq!(h.start_session_index(), 6);
    assert_eq!(h.get_by_index(5), None, "evicted");
    assert_eq!(h.get_by_index(6), Some("cmd 6"));
    assert_eq!(h.get_by_index(total), Some(format!("cmd {total}").as_str()));
    assert_eq!(h.get_from_latest(0), Some(format!("cmd {total}").as_str()));
    assert_eq!(h.get_from_latest(MAX_HISTORY - 1), Some("cmd 6"));
    assert_eq!(h.get_from_latest(MAX_HISTORY), None);
}

#[test]
fn history_shorter_entry_overwrites_longer_slot_cleanly() {
    let mut h = History::new();
    h.add("a very long command that fills the slot");
    for i in 0..MAX_HISTORY - 1 {
        h.add(&format!("{i}"));
    }
    h.add("x"); // lands in the slot that held the long command
    assert_eq!(h.get_from_latest(0), Some("x"));
}

#[test]
fn history_truncates_overlong_ascii_commands() {
    let long = "a".repeat(MAX_CMD_LEN + 100);
    let h = history_of(&[&long]);
    assert_eq!(h.get_from_latest(0).map(str::len), Some(MAX_CMD_LEN));
}

#[test]
fn history_keeps_utf8() {
    let h = history_of(&["echo héllo wörld ✓"]);
    assert_eq!(h.get_from_latest(0), Some("echo héllo wörld ✓"));
}

#[test]
fn history_truncation_respects_char_boundaries() {
    let cmd = format!("{}é", "a".repeat(MAX_CMD_LEN - 1)); // 'é' straddles the limit
    let h = history_of(&[&cmd]);
    assert!(h.get_from_latest(0).is_some(), "entry lost after truncation");
}
