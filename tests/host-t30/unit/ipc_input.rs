//! Tests of `src/ipc/input.rs` (wave 8, Group I): the raw input ring's set-up, routing (the
//! release record when it goes off), records in time order, the full ring, the consumer
//! notification, the kernel copy's drain (none while forwarded), the `SYS_LX_OBJ` ops'
//! checks, the status line.

use super::*;
use crate::ipc::protocol::*;
use crate::world::serial;

/// Every record waiting, read straight from the ring (the service's view).
fn waiting() -> Vec<InputRec> {
    let mut v = Vec::new();
    if let Some(r) = ring() {
        r.take(|x| v.push(x));
    }
    v
}

fn fresh() {
    init();
    set_routing(false);
    let _ = waiting();
}

#[test]
fn init_once_formats_the_ring() {
    let _g = serial();
    init();
    let a = RING.load(Ordering::Acquire);
    assert_ne!(a, 0);
    init();
    assert_eq!(RING.load(Ordering::Acquire), a, "set up once");
    assert!(ring().unwrap().valid());
    assert!(RING_OBJ.lock().as_ref().is_some_and(|o| o.pages() == (INPUT_RING_BYTES / 4096) as u64));
}

#[test]
fn nothing_is_queued_while_the_console_has_the_keyboard() {
    let _g = serial();
    fresh();
    assert!(!routing());
    push_scancode(0x1E);
    push_mouse(1, 2, 0, 0);
    push_abs(5, 6, 0, 0);
    assert!(!pending());
    assert!(waiting().is_empty());
}

#[test]
fn records_while_routed_in_order_with_their_time() {
    let _g = serial();
    fresh();
    set_routing(true);
    push_scancode(0x1E);
    push_mouse(70_000, -70_000, 300, 0b101);
    push_abs(0x1234, 0x8000, -1, 2);
    assert!(pending());
    let v = waiting();
    assert_eq!(v.len(), 3);
    assert_eq!((v[0].kind, v[0].code), (INPUT_REC_KEY, 0x1E));
    // Clamped to the record's range
    assert_eq!((v[1].kind, v[1].x as i16, v[1].y as i16, v[1].wheel, v[1].buttons), (INPUT_REC_REL, i16::MAX, i16::MIN, 127, 0b101));
    assert_eq!((v[2].kind, v[2].x, v[2].y, v[2].wheel, v[2].buttons), (INPUT_REC_ABS, 0x1234, 0x8000, -1, 2));
    assert!(v[0].time <= v[1].time && v[1].time <= v[2].time);
    set_routing(false);
}

#[test]
fn routing_off_queues_one_release_record() {
    let _g = serial();
    fresh();
    set_routing(true);
    set_routing(true); // no change: nothing queued
    assert!(waiting().is_empty());
    set_routing(false);
    let v = waiting();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].kind, INPUT_REC_RELEASE);
    set_routing(false); // already off: nothing more
    assert!(waiting().is_empty());
}

#[test]
fn a_full_ring_drops_and_counts() {
    let _g = serial();
    fresh();
    let (h0, _, d0) = counters();
    set_routing(true);
    for _ in 0..INPUT_RING_RECS + 10 {
        push_scancode(0x10);
    }
    let (h1, t1, d1) = counters();
    assert_eq!(h1 - h0, INPUT_RING_RECS as u64);
    assert_eq!(d1 - d0, 10);
    assert_eq!(h1 - t1, INPUT_RING_RECS as u64);
    set_routing(false); // (the release record is dropped too: the ring is full)
    assert_eq!(counters().2 - d0, 11);
    assert_eq!(waiting().len(), INPUT_RING_RECS);
}

#[test]
fn forwarded_input_is_the_services() {
    let _g = serial();
    fresh();
    // (the registry's default: input forwarded to 0x2A)
    assert!(forwarded());
    assert!(crate::ipc::service::service(ENDPOINT_INPUT_SERVER).is_some(), "0x2A is a system endpoint");
    set_routing(true);
    push_scancode(0x1E);
    // The kernel copy does not consume what is the service's
    assert_eq!(drain(|_| panic!("not the kernel's")), 0);
    assert!(pending());
    assert_eq!(waiting().len(), 1);
    set_routing(false);
    let _ = waiting();
}

#[test]
fn object_ops_check_their_caller() {
    let _g = serial();
    init();
    let input_host = crate::lx::svc::host_of(LXS_INPUT);
    // Another service's host may not ask
    assert_eq!(obj_op(input_host.wrapping_add(1), LX_OBJ_INPUT_RING, 0, 0, 0), EPERM);
    assert_eq!(obj_op(input_host, LX_OBJ_INPUT_CTL, 0, 0, 0), forwarded() as i64);
    assert_eq!(obj_op(input_host, LX_OBJ_INPUT_CTL, 1, 0, 0), EINVAL);
    assert_eq!(obj_op(input_host, 999, 0, 0, 0), EINVAL);
    // Without a calling service there is nobody to give the handle to
    if crate::task::current_service().is_none() {
        assert_eq!(obj_op(input_host, LX_OBJ_INPUT_RING, 0, 0, 0), EPERM);
    }
}

#[test]
fn summary_names_the_consumer() {
    let _g = serial();
    init();
    let s = summary();
    assert!(s.starts_with("input ring: "), "{s}");
    assert!(s.contains(if forwarded() { "input-server" } else { "kernel evdev" }), "{s}");
}

#[test]
fn hot_key_hooks_reach_the_display_side() {
    let _g = serial();
    // (the host's drm stub: no session)
    hotkey_switch(false);
    assert!(!session_hidden());
}
