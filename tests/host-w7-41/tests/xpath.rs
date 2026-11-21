//! vfs-server's `xpath.rs`: the path `/proc/self/exe` shows, on 7-1's fake file system.

use hydra_hosttests_w7_41::ctx::Node;
use hydra_hosttests_w7_41::fake::{Fake, ROOT};
use hydra_hosttests_w7_41::xpath::{real_path, served_by_name};

fn root() -> Node {
    Node::new(0, ROOT)
}

/// /usr/bin/firefox -> ../lib/firefox/firefox; /usr/lib/firefox/firefox (a file).
fn tree() -> (Fake, u64) {
    let f = Fake::new();
    let usr = f.mkdir(ROOT, "usr", 0o755);
    let bin = f.mkdir(usr, "bin", 0o755);
    let lib = f.mkdir(usr, "lib", 0o755);
    let ff = f.mkdir(lib, "firefox", 0o755);
    let prog = f.file(ff, "firefox", 0o755);
    f.symlink(bin, "firefox", "../lib/firefox/firefox");
    f.symlink(bin, "abs", "/usr/lib/firefox/firefox");
    f.symlink(bin, "py", "python3");
    f.file(bin, "python3", 0o755);
    f.symlink(ROOT, "lib64", "usr/lib");
    f.symlink(bin, "loop", "loop");
    (f, prog)
}

#[test]
fn links_are_resolved() {
    let (f, prog) = tree();
    assert_eq!(real_path(&f, root(), b"/usr/bin/firefox", prog).as_deref(), Some(&b"/usr/lib/firefox/firefox"[..]));
    assert_eq!(real_path(&f, root(), b"/usr/bin/abs", prog).as_deref(), Some(&b"/usr/lib/firefox/firefox"[..]));
    // A link in a directory component, with . and ..
    assert_eq!(real_path(&f, root(), b"/lib64/./firefox/../firefox/firefox", prog).as_deref(), Some(&b"/usr/lib/firefox/firefox"[..]));
}

#[test]
fn lexical_kept_when_nothing_to_resolve() {
    let (f, prog) = tree();
    // No link: None (the caller keeps its lexical path)
    assert_eq!(real_path(&f, root(), b"/usr/lib/firefox/firefox", prog), None);
    // Ends somewhere else than the program
    assert_eq!(real_path(&f, root(), b"/usr/bin/firefox", prog + 100), None);
    // Relative, missing, a loop, pseudo trees
    assert_eq!(real_path(&f, root(), b"usr/bin/firefox", prog), None);
    assert_eq!(real_path(&f, root(), b"/usr/bin/nothing", prog), None);
    assert_eq!(real_path(&f, root(), b"/usr/bin/loop", prog), None);
    assert_eq!(real_path(&f, root(), b"/proc/self/exe", prog), None);
}

#[test]
fn pseudo_trees_by_name() {
    assert!(served_by_name(b"/proc"));
    assert!(served_by_name(b"/proc/self/exe"));
    assert!(served_by_name(b"/dev/null"));
    assert!(served_by_name(b"/sys/fs"));
    assert!(!served_by_name(b"/procx"));
    assert!(!served_by_name(b"/usr/proc"));
    assert!(!served_by_name(b"/"));
}
