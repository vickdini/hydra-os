mod common;
use common::*;
use hydra_hosttests_t31::task::{self, TaskPriority, TaskState};

#[test]
fn boots_and_round_robins() {
    let _w = booted();
    let a = task::spawn("a", noop, TaskPriority::Normal).0;
    let b = task::spawn("b", noop, TaskPriority::Normal).0;
    assert_eq!(current_on(0), 0);
    assert_eq!(yield_on(0), a);
    assert_eq!(yield_on(0), b);
    assert_eq!(yield_on(0), 0);
    assert_eq!(state(a), Some(TaskState::Ready));
}
