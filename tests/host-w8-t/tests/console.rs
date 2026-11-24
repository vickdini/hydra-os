//! The kernel's `src/lx/console.rs`: device numbers, key and `stat` encodings.

use hydra_hosttests_w8_t::lx::console::*;
use hydra_hosttests_w8_t::proto::LX_CONS_KEY_SPECIAL;

#[test]
fn paths_name_device_numbers() {
    assert_eq!(path_rdev("/dev/ptmx"), Some(5 << 8 | 2));
    assert_eq!(path_rdev("/dev/tty"), Some(5 << 8));
    assert_eq!(path_rdev("/dev/pts/0"), Some(136 << 8));
    assert_eq!(path_rdev("/dev/pts/3"), Some(136 << 8 | 3));
    assert_eq!(path_rdev("/dev/pts/256"), Some(137 << 8), "a second major after 255");
    assert_eq!(path_rdev("/dev/pts/"), None);
    assert_eq!(path_rdev("/dev/pts/x"), None);
    assert_eq!(path_rdev("/dev/pts/-1"), None);
    assert_eq!(path_rdev("/dev/tty1"), None, "the console's VTs stay the kernel's");
    assert_eq!(path_rdev("/dev/console"), None);
    assert_eq!(path_rdev("/dev/pts/00"), None, "no leading zeros (devpts has no such name)");
    assert_eq!(path_rdev("/dev/pts/2047"), Some(makedev(143, 255)));
    assert_eq!(path_rdev("/dev/pts/2048"), None, "Linux's eight slave majors");
    assert_eq!(path_rdev("/dev/pts/1015042"), None, "never wraps into another major (it was /dev/ptmx's)");
    assert_eq!(pts_index("12"), Some(12));
    assert_eq!(pts_index("+1"), None);
}

#[test]
fn makedev_matches_linux() {
    assert_eq!(makedev(136, 5), 0x8805);
    assert_eq!(makedev(4, 1), 0x401);
    // minors above 255 go to bits 20 and up
    assert_eq!(makedev(1, 0x100), (1 << 8) | (0x100 << 12));
    assert_eq!(pts_rdev(300), makedev(137, 44));
}

#[test]
fn key_marker_matches_the_protocol() {
    assert_eq!(KEY_SPECIAL, LX_CONS_KEY_SPECIAL);
}

#[test]
fn keys() {
    assert_eq!(encode_key(Some('a'), 0), 'a' as u32);
    assert_eq!(encode_key(None, 1), LX_CONS_KEY_SPECIAL | 1);
    assert_eq!(encode_key(Some('\u{8}'), 0), 8);
}

#[test]
fn stat_answer_round_trips() {
    for (m, u, g) in [(0o620, 1000, 5), (0o600, 0, 0), (0o7777, 0x7FFF_FFFF, 0xF_FFFF), (0o644, 65534, 65534)] {
        let v = pack_stat(m, u, g);
        assert!(v >= 0, "never mistaken for an error");
        assert_eq!(unpack_stat(v), (m, u, g));
    }
    assert_eq!(unpack_stat(pack_stat(0o100620, 1, 2)).0, 0o620, "only the permission bits travel");
}

#[test]
fn hangup_answer() {
    assert_eq!(unpack_hangup((7u64 | 9u64 << 32) as i64), (7, 9));
    assert_eq!(unpack_hangup(0), (0, 0));
}

#[test]
fn tty_server_may_post_only_terminal_signals() {
    for sig in [1, 2, 3, 18, 20, 21, 22, 28] {
        assert!(tty_group_signal(sig), "{}", sig);
    }
    for sig in [9, 15, 19, 0, 64, 10, 11] {
        assert!(!tty_group_signal(sig), "{}", sig);
    }
    assert!(tty_leader_signal(1) && tty_leader_signal(18));
    assert!(!tty_leader_signal(2) && !tty_leader_signal(9));
}

#[test]
fn console_keys_while_tty_server_is_down() {
    assert_eq!(fallback_signal(Some('\u{3}')), Some(2));
    assert_eq!(fallback_signal(Some('\u{1c}')), Some(3));
    assert_eq!(fallback_signal(Some('\u{1a}')), Some(20));
    assert_eq!(fallback_signal(Some('a')), None);
    assert_eq!(fallback_signal(None), None);
}

// wave11 GR: a console read tty-server died serving is sent again (at most 3 times)
#[test]
fn console_read_sent_again_only_when_tty_server_died() {
    const EIO: i64 = -5;
    const ENOSYS: i64 = -38;
    assert!(read_again(EIO, true, 0), "died under the read: EIO is sent again");
    assert!(read_again(ENOSYS, true, 2), "no instance there: sent again");
    assert!(!read_again(EIO, true, 3), "at most 3 times");
    assert!(!read_again(EIO, false, 0), "a live tty-server's EIO (hang-up) is the caller's");
    assert!(!read_again(5, true, 0), "data read: never again");
    assert!(!read_again(0, true, 0), "end of file: never again");
    assert!(!read_again(-11, true, 0), "EAGAIN is the caller's");
}
