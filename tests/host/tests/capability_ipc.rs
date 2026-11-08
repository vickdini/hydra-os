//! Tests for the object-capability model (`src/capability`) and the IPC
//! message format and label registry (`src/ipc/message.rs`, `protocol.rs`).
//! Endpoint rendezvous and the service loop block on the scheduler and are
//! left to the in-kernel tests.

use hydra_hosttests::capability::table::{CapabilityTable, MAX_CAPABILITIES};
use hydra_hosttests::capability::{CapType, Capability, Rights};
use hydra_hosttests::ipc::message::{Message, MAX_INLINE_WORDS};
use hydra_hosttests::ipc::protocol::*;

fn endpoint(id: u32, rights: Rights) -> Capability {
    Capability::new(CapType::Endpoint { endpoint_id: id }, rights)
}

// ------------------------------------------------------------------ Rights

#[test]
fn rights_bits_are_distinct_and_all_covers_them() {
    let each = [Rights::READ, Rights::WRITE, Rights::EXECUTE, Rights::GRANT, Rights::CALL];
    let mut seen = 0u32;
    for r in each {
        assert_eq!(r.0.count_ones(), 1);
        assert_eq!(seen & r.0, 0, "overlapping bit {:#x}", r.0);
        seen |= r.0;
        assert!(Rights::ALL.contains(r));
    }
    assert_eq!(seen, Rights::ALL.0);
}

#[test]
fn rights_contains_is_subset_test() {
    let rw = Rights(Rights::READ.0 | Rights::WRITE.0);
    assert!(rw.contains(Rights::READ));
    assert!(rw.contains(rw));
    assert!(!rw.contains(Rights::EXECUTE));
    assert!(!rw.contains(Rights(Rights::READ.0 | Rights::EXECUTE.0)), "partial overlap is not containment");
    assert!(Rights(0).contains(Rights(0)), "everything contains the empty set");
    assert!(!Rights(0).contains(Rights::READ));
}

// ---------------------------------------------------------- CapabilityTable

#[test]
fn table_starts_empty() {
    let t = CapabilityTable::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.get(0).is_none());
}

#[test]
fn table_insert_get_revoke() {
    let mut t = CapabilityTable::new();
    let a = t.insert(endpoint(1, Rights::READ)).unwrap();
    let b = t.insert(endpoint(2, Rights::ALL)).unwrap();
    assert_ne!(a, b);
    assert_eq!(t.len(), 2);
    assert_eq!(t.get(b).unwrap().cap_type, CapType::Endpoint { endpoint_id: 2 });

    let revoked = t.revoke(a).unwrap();
    assert_eq!(revoked.cap_type, CapType::Endpoint { endpoint_id: 1 });
    assert!(t.get(a).is_none());
    assert!(t.revoke(a).is_none(), "double revoke yields nothing");
    assert_eq!(t.len(), 1);
}

#[test]
fn table_does_not_reuse_a_revoked_slot_immediately() {
    // The next-free cursor advances, so a stale slot number is less likely
    // to alias a freshly granted capability.
    let mut t = CapabilityTable::new();
    let first = t.insert(endpoint(1, Rights::READ)).unwrap();
    t.revoke(first);
    let second = t.insert(endpoint(2, Rights::READ)).unwrap();
    assert_ne!(first, second);
}

#[test]
fn table_fills_up_then_wraps_into_freed_slots() {
    let mut t = CapabilityTable::new();
    for i in 0..MAX_CAPABILITIES {
        assert_eq!(t.insert(endpoint(i as u32, Rights::READ)), Ok(i));
    }
    assert_eq!(t.len(), MAX_CAPABILITIES);
    assert!(t.insert(endpoint(999, Rights::READ)).is_err(), "table full");

    t.revoke(17);
    assert_eq!(t.insert(endpoint(1000, Rights::READ)), Ok(17), "search wraps around");
    assert!(t.insert(endpoint(1001, Rights::READ)).is_err());
}

#[test]
fn table_out_of_range_slots_are_rejected() {
    let mut t = CapabilityTable::new();
    t.insert(endpoint(1, Rights::ALL)).unwrap();
    for slot in [MAX_CAPABILITIES, MAX_CAPABILITIES + 1, usize::MAX] {
        assert!(t.get(slot).is_none());
        assert!(t.revoke(slot).is_none());
        assert!(!t.check_rights(slot, Rights(0)));
    }
}

#[test]
fn table_check_rights() {
    let mut t = CapabilityTable::new();
    let slot = t.insert(endpoint(1, Rights(Rights::READ.0 | Rights::CALL.0))).unwrap();
    assert!(t.check_rights(slot, Rights::READ));
    assert!(t.check_rights(slot, Rights::CALL));
    assert!(!t.check_rights(slot, Rights::WRITE));
    assert!(!t.check_rights(slot, Rights::ALL));
    assert!(!t.check_rights(slot + 1, Rights(0)), "empty slot grants nothing");
}

#[test]
fn cap_types_compare_by_payload() {
    assert_eq!(CapType::Thread { thread_id: 3 }, CapType::Thread { thread_id: 3 });
    assert_ne!(CapType::Thread { thread_id: 3 }, CapType::Thread { thread_id: 4 });
    assert_ne!(CapType::Thread { thread_id: 3 }, CapType::HardwareDevice { device_id: 3 });
}

// ----------------------------------------------------------------- Message

#[test]
fn message_constructors() {
    let m = Message::new(MSG_FS_OPEN);
    assert_eq!((m.label, m.args), (MSG_FS_OPEN, [0; MAX_INLINE_WORDS]));
    assert!(m.capability.is_none());

    let m = Message::with_args(MSG_BLOCK_READ, [1, 2, 3, u64::MAX]);
    assert_eq!(m.args, [1, 2, 3, u64::MAX]);

    let cap = Capability::new(CapType::MemoryFrame { physical_addr: 0x1000 }, Rights::READ);
    let m = m.with_cap(cap);
    assert_eq!(m.capability.unwrap().cap_type, CapType::MemoryFrame { physical_addr: 0x1000 });
    assert_eq!(m.label, MSG_BLOCK_READ, "attaching a cap keeps the payload");
}

#[test]
fn message_is_small_enough_to_copy_by_value() {
    assert!(std::mem::size_of::<Message>() <= 96);
}

// ---------------------------------------------------------------- protocol

#[test]
fn well_known_endpoints_are_distinct() {
    let eps = [ENDPOINT_ZFS_SERVER, ENDPOINT_BLOCK_DEV, ENDPOINT_NET_DEV, ENDPOINT_DISPLAY_DEV, ENDPOINT_SUPERVISOR];
    let mut v = eps.to_vec();
    v.sort();
    v.dedup();
    assert_eq!(v.len(), eps.len());
}

#[test]
fn message_labels_are_unique_and_grouped_by_service() {
    let families: [(u32, &[u32], u32); 5] = [
        (0x2, &[MSG_BLOCK_READ, MSG_BLOCK_WRITE, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE], MSG_BLOCK_REPLY),
        (0x3, &[MSG_FS_OPEN, MSG_FS_READ, MSG_FS_WRITE, MSG_FS_CLOSE, MSG_FS_STAT, MSG_FS_SYNC], MSG_FS_REPLY),
        (0x4, &[MSG_NET_TRANSMIT, MSG_NET_RECEIVE, MSG_NET_GET_MAC, MSG_NET_GET_STATUS], MSG_NET_REPLY),
        (0x5, &[MSG_FB_GET_INFO, MSG_FB_FLUSH, MSG_FB_INPUT_EVENT], MSG_FB_REPLY),
        (
            0x6,
            &[MSG_SUPERVISOR_PING, MSG_SUPERVISOR_PONG, MSG_SUPERVISOR_STATUS, MSG_SUPERVISOR_RESTART],
            MSG_SUPERVISOR_REPLY,
        ),
    ];
    let mut all = Vec::new();
    for (family, requests, reply) in families {
        for &l in requests.iter().chain([reply].iter()) {
            assert_eq!(l >> 12, family, "label {l:#x} outside family {family:#x}");
            all.push(l);
        }
        assert_eq!(reply & 0xF, 0xF, "replies end in F");
        assert!(requests.iter().all(|r| r & 0xF != 0xF), "requests never collide with the reply slot");
    }
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), n, "duplicate label");
}
