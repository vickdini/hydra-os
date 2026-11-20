use hydra_hosttests_t33::fakefs;
use hydra_hosttests_t33::fs::ZfsClient;

#[test]
fn pool_round_trip() {
    let root = fakefs::pool();
    assert_eq!(ZfsClient::root_ino(), root);
    let d = fakefs::test_dir("smoke");
    let f = fakefs::with_fs(|fs| fs.put(d, "a/b.txt", b"hello"));
    assert_eq!(ZfsClient::resolve(0, b"/smoke/a/b.txt", true), Ok(f));
    let mut buf = [0u8; 16];
    assert_eq!(ZfsClient::read_at(f, 0, &mut buf), Ok(5));
    assert_eq!(&buf[..5], b"hello");
}
