//! The kernel's restart decisions for the sound service (`lx/restart_policy.rs`).

use hydra_hosttests_w8_s::ipc::protocol::{LX_OBJ_KIND_SND_CTL, LX_OBJ_KIND_SND_PCM};
use hydra_hosttests_w8_s::restart_policy::{alsa_resendable, idempotent, stale_errno};

fn ioctl(req: u64) -> [u64; 6] {
    [5, req, 0x7fff_0000, 0, 0, 0]
}

#[test]
fn queries_and_sync_ptr_are_sent_again() {
    for req in [0xC088_4123u64, 0x8098_4120, 0xC098_4124, 0x8008_4121, 0x4122, 0xC4C8_5512, 0xC120_5531] {
        assert!(idempotent(16, &ioctl(req)), "{:#x}", req);
    }
    // Sign-extended as libasound's `int` request may arrive
    assert!(idempotent(16, &ioctl(0xFFFF_FFFF_C088_4123)));
    assert!(alsa_resendable(0xC110_5511));
}

#[test]
fn what_changes_the_stream_is_not() {
    // HW_PARAMS, PREPARE, START, DROP, DRAIN, WRITEI, READI, REWIND, ELEM_WRITE, SUBSCRIBE,
    // PCM_NEXT_DEVICE (it overwrites its argument)
    for req in [0xC004_5530u64, 0x8004_5530, 0xC260_4111, 0x4140, 0x4142, 0x4143, 0x4144, 0x4018_4150, 0x8018_4151, 0x4008_4146, 0xC4C8_5513, 0xC004_5516] {
        assert!(!idempotent(16, &ioctl(req)), "{:#x}", req);
    }
}

#[test]
fn stale_sound_devices_are_enodev() {
    assert_eq!(stale_errno(LX_OBJ_KIND_SND_CTL), -19);
    assert_eq!(stale_errno(LX_OBJ_KIND_SND_PCM), -19);
}
