use crate::sockcall::*;

#[test]
fn socket_calls_on_a_pipe_are_not_a_socket() {
    // send (sendto), recvfrom, sendmsg, recvmsg, getsockopt, setsockopt, shutdown, ...
    for nr in SOCKET_FD_CALLS {
        assert!(is_socket_fd_call(nr));
        assert!(not_a_socket(nr, true, false), "{nr}");
        // a Unix socket of ours answers them itself
        assert!(!not_a_socket(nr, true, true), "{nr}");
        // no object of ours: not this rule's
        assert!(!not_a_socket(nr, false, false), "{nr}");
    }
}

#[test]
fn other_calls_are_left_alone() {
    // read, write, ioctl, readv, writev, socket, socketpair, close, pipe2, eventfd2
    for nr in [0u64, 1, 16, 19, 20, 41, 53, 3, 293, 290] {
        assert!(!is_socket_fd_call(nr), "{nr}");
        assert!(!not_a_socket(nr, true, false), "{nr}");
    }
}

use crate::shmrec::{self, SegRec};

fn seg() -> SegRec {
    SegRec { next_seq: 7, id: 0x1_8003, ns: 0xffff_8000_1234_5678, perm: [0x1234, 1000, 100, 0, 0, 0o1600, 3], size: 1 << 20, ctime: 1_764_000_000, cpid: 4242 }
}

#[test]
fn a_segment_record_round_trips() {
    let r = seg();
    let b = shmrec::encode(&r);
    assert_eq!(b.len(), shmrec::LEN);
    assert!(b.len() <= 288, "fits one kept record");
    assert_eq!(b[0], shmrec::K_SHMSEG);
    assert_eq!(shmrec::decode(&b), Some(r));
    // negative ids, keys and times survive
    let n = SegRec { id: -1, ctime: -5, perm: [u32::MAX, 0, 0, 0, 0, 0, 0], ..r };
    assert_eq!(shmrec::decode(&shmrec::encode(&n)), Some(n));
}

#[test]
fn other_records_are_not_segments() {
    let mut b = shmrec::encode(&seg());
    assert_eq!(shmrec::decode(&b[..b.len() - 1]), None, "short");
    b.push(0);
    assert_eq!(shmrec::decode(&b), None, "long");
    let mut b = shmrec::encode(&seg());
    b[0] = 9; // the tables' record
    assert_eq!(shmrec::decode(&b), None);
    assert_eq!(shmrec::decode(&[]), None);
}

#[test]
fn the_next_sequence_number_after_a_restart() {
    assert_eq!(shmrec::later_seq(5, 9), 9);
    assert_eq!(shmrec::later_seq(9, 5), 9);
    assert_eq!(shmrec::later_seq(7, 7), 7);
    // across the wrap: 2 comes after 0xfffe
    assert_eq!(shmrec::later_seq(0xfffe, 2), 2);
    assert_eq!(shmrec::later_seq(2, 0xfffe), 2);
}
