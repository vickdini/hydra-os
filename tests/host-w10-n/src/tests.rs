use crate::marks::Marks;

#[test]
fn nothing_is_live_before_the_first_round() {
    let m = Marks::new(8);
    assert!((0..8).all(|s| !m.live(s)));
}

#[test]
fn a_mark_counts_in_its_round_only() {
    let mut m = Marks::new(8);
    m.next_round();
    m.mark(3);
    assert!(m.live(3));
    assert!(!m.live(4));
    m.next_round();
    assert!(!m.live(3), "last round's mark is not this round's");
    m.mark(4);
    assert!(m.live(4));
}

#[test]
fn marks_in_one_round_are_independent() {
    let mut m = Marks::new(16);
    m.next_round();
    for s in [0, 5, 15] {
        m.mark(s);
    }
    let live: Vec<usize> = (0..16).filter(|&s| m.live(s)).collect();
    assert_eq!(live, vec![0, 5, 15]);
}

#[test]
fn wrapping_round_numbers_clear_old_marks() {
    let mut m = Marks::at_round(4, u32::MAX - 1);
    m.next_round(); // the last round number
    m.mark(2);
    assert!(m.live(2));
    m.next_round(); // wraps past 0 to 1: every mark is cleared
    assert!(!m.live(2));
    m.mark(1);
    assert!(m.live(1));
    // A slot marked in the last round number does not count after the wrap
    let mut w = Marks::at_round(4, u32::MAX);
    w.mark(3); // a slot marked in round u32::MAX
    w.next_round();
    assert!(!w.live(3));
}
