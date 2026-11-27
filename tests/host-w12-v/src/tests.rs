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
