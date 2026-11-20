//! `snd.rs` without a sound card: what the rest of the system sees, and the ways
//! `start` gives up (driver offline, no description, no playback direction).
//! (Its own test binary: the card, once found, stays for the process.)

mod common;

use hydra_hosttests_t28::compat::linux::snd;
use hydra_hosttests_t28::fake;
use hydra_hosttests_t28::ipc::protocol::{MSG_SND_INFO, MSG_SND_REPLY};
use hydra_hosttests_t28::ipc::Message;

#[test]
fn without_a_card_nothing_shows_and_start_gives_up() {
    let _g = common::serial();
    assert!(!snd::present());
    assert!(!snd::has_dir(0));
    snd::set_controller(0xfebf_0000, "0000:00:1b.0".into(), 0x8086, 0x293e, 0x1af4_1100);
    assert!(snd::controller().is_none(), "no card: no controller for sysfs");
    assert!(snd::proc_text("cards").is_none());
    assert!(!snd::is_proc_file("/proc/asound/cards"));
    assert!(!snd::is_proc_file("/proc/cpuinfo"));
    for minor in [0, 16, 24, 3] {
        assert_eq!(snd::open(minor, false).err(), Some(-19));
    }

    // The driver is not running: nothing asked
    fake::sound(|s| s.online = false);
    snd::start();
    assert!(fake::sound(|s| s.calls.is_empty()));

    // Running, but it does not answer / answers with an error
    fake::sound(|s| s.online = true);
    snd::start();
    assert_eq!(fake::sound(|s| s.calls.len()), 1);
    fake::sound(|s| s.responder = Some(Box::new(|_, _| Ok(Message::with_args(MSG_SND_REPLY, [5, 0, 0, 0])))));
    snd::start();
    fake::sound(|s| s.responder = Some(Box::new(|_, _| Ok(Message::with_args(0x1234, [0, 0, 0, 0])))));
    snd::start();
    assert!(!snd::present());

    // A card with capture only: the buffers are allocated, but without playback no card
    fake::sound(|s| {
        s.window = Some(Box::leak(vec![0u8; 4096].into_boxed_slice()));
        s.responder = Some(Box::new(|_, m| {
            assert_eq!(m.label, MSG_SND_INFO);
            Ok(Message::with_args(MSG_SND_REPLY, [0, 0x10ec_0269, 0b10, 0]))
        }))
    });
    fake::IOMMU_FAILS.set(true);
    snd::start();
    assert!(!snd::present());
    assert_eq!(fake::spawned("snd-position"), 0);
}
