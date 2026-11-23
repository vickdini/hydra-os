//! The public pure parts that other crates compile too (so no test module inside them):
//! `ipc/message.rs`, `ipc/protocol.rs`'s functions, `lx/restart_policy.rs`.

use hydra_hosttests_t30::capability::Capability;
use hydra_hosttests_t30::ipc::message::{Message, MAX_INLINE_WORDS};
use hydra_hosttests_t30::ipc::protocol::*;
use hydra_hosttests_t30::lx::restart_policy::*;

#[test]
fn messages_carry_words_and_a_capability() {
    let m = Message::new(7);
    assert_eq!((m.label, m.args, m.capability), (7, [0; MAX_INLINE_WORDS], None));
    let m = Message::with_args(8, [1, 2, 3, 4]).with_cap(Capability(9));
    assert_eq!((m.label, m.args, m.capability), (8, [1, 2, 3, 4], Some(Capability(9))));
}

#[test]
fn protocol_helpers() {
    for (h, pg, ro) in [(1u32, 0u64, false), (0x7FFF, 0x7FFF_FFFF_FFFF, true), (5, 3, true)] {
        assert_eq!(lx_mmap_parts(lx_mmap_answer(h, pg, ro)), (h, pg, ro));
    }
    assert_eq!(lx_req_svc((LXS_TEST as u64) << LX_REQ_SVC_SHIFT | 77), LXS_TEST);
    let c = LxCall::EMPTY;
    assert_eq!((c.obj, c.nr), (LX_OBJ_NONE, 0));
    assert_eq!(LxCopy::EMPTY.in_off, [0; 6]);
}

#[test]
fn classes_parse_name_and_lower() {
    for c in [RestartClass::Transparent, RestartClass::FailObjects, RestartClass::EndLinux] {
        assert_eq!(RestartClass::parse(c.name().as_bytes()), Some(c));
        assert_eq!(RestartClass::from_u8(c as u8), Some(c));
    }
    assert_eq!(RestartClass::parse(b"x"), None);
    assert_eq!(RestartClass::from_u8(9), None);
    assert_eq!(RestartClass::Transparent.lowered(), RestartClass::FailObjects);
    assert_eq!(RestartClass::EndLinux.lowered(), RestartClass::EndLinux);
}

#[test]
fn the_ladder() {
    let mut l = Ladder::new(RestartClass::Transparent);
    let d = l.crash(1000);
    assert!(d.restart && !d.reset_kept && d.class == RestartClass::Transparent);
    l.restarted(1000);
    let d = l.crash(2000);
    assert!(d.restart && d.reset_kept && d.class == RestartClass::FailObjects);
    l.restarted(2000);
    let d = l.crash(3000);
    assert!(!d.restart);
    // A crash long after: the configured class again
    let mut l = Ladder::new(RestartClass::EndLinux);
    l.restarted(0);
    l.crash(10);
    l.restarted(10);
    assert!(l.crash(20).restart, "EndLinux keeps restarting");
    let d = l.deliberate(30);
    assert!(d.restart && l.current == RestartClass::EndLinux);
    l.restarted(30);
    assert!(!l.crash(30 + LADDER_WINDOW_MS).reset_kept);
    l.reset();
    assert_eq!(l.crashes, 0);
}

#[test]
fn stale_errors_and_idempotent_calls() {
    assert_eq!(stale_errno(16), -32);
    assert_eq!(stale_errno(18), -104);
    assert_eq!(stale_errno(64), -19);
    assert_eq!(stale_errno(2), -9);
    let a = |v: [u64; 6]| v;
    assert!(idempotent(LX_NULL_NR, &a([4, 0, 0, 0, 0, 0])));
    assert!(!idempotent(LX_NULL_NR, &a([3, 0, 0, 0, 0, 0])));
    assert!(idempotent(LX_TEST_NR, &a([21, 0, 0, 0, 0, 0])));
    assert!(idempotent(250, &a([11, 0, 0, 0, 0, 0])));
    assert!(idempotent(250, &a([10, 0, 0, 0, 0, 0])));
    assert!(!idempotent(250, &a([10, 0, 0, 0, 5, 0])));
    assert!(!idempotent(250, &a([30, 0, 0, 0, 0, 0])));
    assert!(idempotent(249, &a([0; 6])));
    assert!(idempotent(245, &a([0; 6])));
    assert!(idempotent(64, &a([5, 1, 0, 0, 0, 0])) && !idempotent(64, &a([0, 1, 0, 0, 0, 0])));
    assert!(idempotent(68, &a([5, 0, 0, 0, 0, 0])));
    assert!(idempotent(66, &a([0, 0, 0x102, 0, 0, 0])));
    assert!(idempotent(71, &a([0, 2, 0, 0, 0, 0])));
    assert!(idempotent(321, &a([1, 0, 0, 0, 0, 0])));
    assert!(idempotent(51, &a([0; 6])));
    assert!(idempotent(45, &a([0, 0, 0, 2, 0, 0])) && idempotent(47, &a([0, 0, 2, 0, 0, 0])));
    assert!(idempotent(16, &a([0, 0x5401, 0, 0, 0, 0])) && !idempotent(16, &a([0, 0x5402, 0, 0, 0, 0])));
    assert!(idempotent(4, &a([0; 6])) && idempotent(17, &a([0; 6])));
    assert!(idempotent(2, &a([0, 0, 0, 0, 0, 0])) && !idempotent(2, &a([0, 0o1000 | 1, 0, 0, 0, 0])));
    // wave10 GV1: a create-if-missing is sent again (it opens what the first try made);
    // O_EXCL, O_TRUNC and O_TMPFILE are not
    assert!(idempotent(2, &a([0, 0o100, 0, 0, 0, 0])) && idempotent(257, &a([0, 0, 0o100 | 2, 0, 0, 0])));
    assert!(!idempotent(257, &a([0, 0, 0o100 | 0o200 | 2, 0, 0, 0])) && !idempotent(257, &a([0, 0, 0o100 | 0o1000 | 1, 0, 0, 0])));
    assert!(!idempotent(257, &a([0, 0, 0o20200000 | 2, 0, 0, 0])));
    assert!(idempotent(257, &a([0; 6])));
    assert!(idempotent(63, &a([0; 6])) && idempotent(302, &a([0; 6])) && !idempotent(302, &a([0, 0, 1, 0, 0, 0])));
    assert!(!idempotent(1, &a([0; 6])));
    assert_eq!(after_crash(LX_RESEND, 1, &a([0; 6])), Ok(()));
    assert_eq!(after_crash(LX_RESEND_MAYBE, 4, &a([0; 6])), Ok(()));
    assert_eq!(after_crash(LX_RESEND_MAYBE, 1, &a([0; 6])), Err(-5));
    assert_eq!(after_crash(-5, 4, &a([0; 6])), Err(-5));
}
