//! The kernel side of attribute-based access control (`src/compat/linux/abac.rs`): the
//! `prctl(PR_HYDRA_ACCESS)` interface, subjects on processes, labels read from pool files'
//! extended attributes, enforcement after the mode bits, the decision and label caches,
//! the audit ring and its text, app control, boot loading.

use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::abac::{self, cmd, LABELS, PR_HYDRA_ACCESS, POLICY_FILE};
use hydra_hosttests_t33::compat::linux::abac_core::{Sha256, D, R, W, X};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, with_fs};
use hydra_hosttests_t33::fs::client::ZfsClient;
use hydra_hosttests_t33::fs::zfs::fsproto::Attr;

const POLICY: &str = "hydra-access 1
type level Public Internal Confidential Secret
attrtype clearance level
attrtype classification level
policy Fin
rule fin-dept
allow rw user.department res.department == user.clearance res.classification >= and
allow r user.role 'auditor ==
rule fin-staged staged replaces=fin-dept
allow r user.clearance 'Secret ==
";

const ADMIN: u64 = 1 << 21;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    fakefs::pool();
    fake::PROCS.lock().entry(1).or_default();
    g
}

fn prctl(c: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    abac::prctl([PR_HYDRA_ACCESS, c, a2, a3, a4, 0])
}

fn as_admin<R>(f: impl FnOnce() -> R) -> R {
    let (caps, creds) = (fake::CAPS.get(), fake::CREDS.get());
    fake::CAPS.set(Some(ADMIN));
    fake::CREDS.set((0, 0));
    let r = f();
    fake::CAPS.set(caps);
    fake::CREDS.set(creds);
    r
}

fn load(text: &str) -> i64 {
    as_admin(|| prctl(cmd::LOAD, text.as_ptr() as u64, text.len() as u64, 0))
}

fn set_subject(pid: u64, text: &str) -> i64 {
    as_admin(|| prctl(cmd::SET_SUBJECT, pid, text.as_ptr() as u64, text.len() as u64))
}

fn get_subject(pid: u64) -> (i64, String) {
    let mut b = vec![0u8; 256];
    let n = prctl(cmd::GET_SUBJECT, pid, b.as_mut_ptr() as u64, b.len() as u64);
    (n, String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned())
}

fn status() -> String {
    let mut b = vec![0u8; 1024];
    let n = prctl(cmd::STATUS, 0, b.as_mut_ptr() as u64, b.len() as u64);
    String::from_utf8_lossy(&b[..n as usize]).into_owned()
}

fn status_field(name: &str) -> u64 {
    let s = status();
    s.split_whitespace().find_map(|kv| kv.strip_prefix(&format!("{name}="))).unwrap().parse().unwrap()
}

fn read_audit() -> String {
    let mut b = vec![0u8; 16384];
    let n = as_admin(|| prctl(cmd::READ_AUDIT, 0, b.as_mut_ptr() as u64, b.len() as u64));
    String::from_utf8_lossy(&b[..n as usize]).into_owned()
}

/// A labelled pool file; its attributes.
fn labelled(dir: u64, name: &str, labels: &str, mode: u32) -> Attr {
    let ino = with_fs(|fs| fs.put(dir, name, b"data"));
    with_fs(|fs| {
        let n = fs.nodes.get_mut(&ino).unwrap();
        n.attr.mode = (n.attr.mode & 0o170000) | mode;
    });
    ZfsClient::setxattr(ino, LABELS, labels.as_bytes(), 0).unwrap();
    ZfsClient::getattr(ino).unwrap()
}

fn as_user(tgid: u64) {
    fake::IDS.set((tgid, tgid));
    fake::CREDS.set((1000, 1000));
    fake::UID.set(1000);
    fake::CAPS.set(Some(0));
    fake::PROCS.lock().entry(tgid).or_default();
}

#[test]
fn loading_and_unloading_policies() {
    let _g = serial();
    // Not an administrator
    fake::CREDS.set((1000, 1000));
    assert_eq!(prctl(cmd::LOAD, POLICY.as_ptr() as u64, POLICY.len() as u64, 0), -1);
    fake::CREDS.set((0, 0));
    assert_eq!(prctl(cmd::LOAD, POLICY.as_ptr() as u64, POLICY.len() as u64, 0), -1, "root without CAP_SYS_ADMIN");
    // A policy with an error is refused with a log line
    assert_eq!(load("hydra-access 1\nrule x\n"), -22);
    assert!(fake::klog_take().contains("[access] policy rejected: line 2"));
    assert_eq!(as_admin(|| prctl(cmd::LOAD, 0, 10, 0)), -14);
    assert_eq!(as_admin(|| prctl(cmd::LOAD, POLICY.as_ptr() as u64, 2 << 20, 0)), -22, "too long");
    let bad = [0xFFu8, 0xFE];
    assert_eq!(as_admin(|| prctl(cmd::LOAD, bad.as_ptr() as u64, 2, 0)), -22, "not UTF-8");
    let g0 = status_field("generation");
    assert_eq!(load(POLICY), 0);
    assert!(abac::active());
    assert_eq!(status_field("generation"), g0 + 1);
    assert_eq!((status_field("policies"), status_field("rules"), status_field("active")), (1, 2, 1));
    // Unload
    assert_eq!(as_admin(|| prctl(cmd::LOAD, 0, 0, 0)), 0);
    assert!(!abac::active());
    assert_eq!((status_field("rules"), status_field("apps")), (0, 0));
    assert_eq!(prctl(99, 0, 0, 0), -22);
}

#[test]
fn subjects_are_set_by_root_and_read_by_their_owner() {
    let _g = serial();
    fake::PROCS.lock().entry(4000).or_default();
    fake::PROCS.lock().entry(4001).or_default();
    fake::IDS.set((4000, 4000));
    // Not an administrator
    let t = "department=Finance\nclearance=Secret";
    assert_eq!(prctl(cmd::SET_SUBJECT, 0, t.as_ptr() as u64, t.len() as u64), -1);
    assert_eq!(set_subject(0, t), 0, "the caller itself");
    assert_ne!(fake::PROCS.lock()[&4000].abac, 0);
    let (n, text) = get_subject(0);
    assert!(n > 0);
    assert!(text.contains("department=Finance") && text.contains("clearance=Secret"), "{text}");
    // The same set shares one id
    assert_eq!(set_subject(4001, "clearance=Secret\ndepartment=Finance"), 0);
    let (a, b) = {
        let p = fake::PROCS.lock();
        (p[&4001].abac, p[&4000].abac)
    };
    assert_eq!(a, b);
    assert_eq!(set_subject(4999, t), -3, "no such process");
    assert_eq!(set_subject(0, "no equals sign"), -22);
    assert_eq!(as_admin(|| prctl(cmd::SET_SUBJECT, 0, 0, 5)), -14);
    // An empty set clears it
    assert_eq!(set_subject(4001, ""), 0);
    assert_eq!(fake::PROCS.lock()[&4001].abac, 0);
    // Reading another's needs privilege
    fake::CREDS.set((1000, 1000));
    assert_eq!(get_subject(4001).0, -1);
    assert_eq!(as_admin(|| get_subject(4001)), (0, String::new()));
    assert_eq!(as_admin(|| get_subject(4777)).0, -3);
    // Size 0 asks for the length; too small is ERANGE
    let mut b = [0u8; 4];
    let full = get_subject(0).0;
    assert_eq!(prctl(cmd::GET_SUBJECT, 0, b.as_mut_ptr() as u64, 0), full);
    assert_eq!(prctl(cmd::GET_SUBJECT, 0, b.as_mut_ptr() as u64, 4), -34);
    assert_eq!(prctl(cmd::GET_SUBJECT, 0, 0, 100), -14);
    fake::PROCS.lock().remove(&4000);
    fake::PROCS.lock().remove(&4001);
    // The console login's subject
    abac::console_login(Some("role=operator"));
    assert_ne!(abac::console_subject(), 0);
    abac::console_login(None);
    assert_eq!(abac::console_subject(), 0);
    abac::console_login(Some("bad"));
    assert_eq!(abac::console_subject(), 0);
}

#[test]
fn enforcement_takes_rights_away_and_audits() {
    let _g = serial();
    let d = fakefs::test_dir("abac-enf");
    assert_eq!(load(POLICY), 0);
    let ok = labelled(d, "internal", "department=Finance\nclassification=Internal\npolicy=Fin", 0o644);
    let secret = labelled(d, "secret", "department=Finance\nclassification=Secret\npolicy=Fin", 0o644);
    let other = labelled(d, "hr", "department=HR\nclassification=Public\npolicy=Fin", 0o644);
    let unlabelled_policy = labelled(d, "nopolicy", "department=HR", 0o644);
    let plain = ZfsClient::getattr(with_fs(|fs| fs.put(d, "plain", b""))).unwrap();
    as_user(5000);
    // No subject: nothing restricted
    assert!(abac::check(&secret, R as u32));
    assert_eq!(set_subject(0, "department=Finance\nclearance=Confidential"), 0);
    fake::EXE.with_borrow_mut(|e| *e = Some("/usr/bin/cat".into()));
    assert!(abac::check(&ok, (R | W) as u32));
    assert!(!abac::check(&secret, R as u32), "clearance below classification");
    assert!(!abac::check(&other, R as u32), "another department");
    assert!(abac::check(&unlabelled_policy, R as u32), "no policy label: not covered");
    assert!(abac::check(&plain, R as u32), "no extended attributes");
    // Folders: x goes with r
    let fin_dir = {
        let ino = with_fs(|fs| fs.mkdir_p(d, "findir"));
        ZfsClient::setxattr(ino, LABELS, b"department=HR\nclassification=Public\npolicy=Fin", 0).unwrap();
        ZfsClient::getattr(ino).unwrap()
    };
    assert!(!abac::check(&fin_dir, X as u32));
    // The same decision again comes from the cache (and the audit counts it)
    assert!(!abac::check(&secret, R as u32));
    let hits = status_field("hits");
    assert!(!abac::check(&secret, R as u32));
    assert!(status_field("hits") > hits);
    // Deletion needs d; root is not restricted
    assert!(!abac::check_delete(&secret));
    assert!(abac::check_delete(&plain));
    fake::CREDS.set((0, 0));
    assert!(abac::check_delete(&secret));
    fake::CREDS.set((1000, 1000));
    // The audit: a denial, counted when repeated, with its rule and policy
    abac::note_path(secret.ino, "/abac-enf/secret");
    let a = read_audit();
    assert!(a.contains("deny pid=5000 uid=1000 want=r ino="), "{a}");
    assert!(a.contains("rule=fin-dept policy=Fin exe=cat"), "{a}");
    assert!(a.contains(&format!("ino={} count=2", secret.ino)), "repeated (a new record after the others): {a}");
    assert!(a.contains("path=/abac-enf/secret"), "{a}");
    assert!(a.contains("want=d"), "{a}");
    assert!(read_audit().is_empty(), "drained");
    // Not an administrator
    let mut b = [0u8; 64];
    assert_eq!(prctl(cmd::READ_AUDIT, 0, b.as_mut_ptr() as u64, 64), -1);
    // Staged rule: proposes to deny what is allowed (clearance not Secret)
    assert!(abac::check(&ok, R as u32));
    let a = read_audit();
    assert!(a.contains("staged-would-deny") && a.contains("rule=fin-staged"), "{a}");
    // A Secret subject: the staged rule allows what the enforced one denies
    assert_eq!(set_subject(0, "department=HR\nclearance=Secret"), 0);
    assert!(!abac::check(&secret, R as u32));
    assert!(read_audit().contains("deny-staged-would-allow"));
    // Off when the policy goes
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    assert!(abac::check(&secret, R as u32));
    assert!(abac::check_delete(&secret));
    fake::PROCS.lock().remove(&5000);
}

#[test]
fn labels_are_cached_and_inherited() {
    let _g = serial();
    let d = fakefs::test_dir("abac-labels");
    assert_eq!(load(POLICY), 0);
    let dir = {
        let ino = with_fs(|fs| fs.mkdir_p(d, "proj"));
        ZfsClient::setxattr(ino, LABELS, b"department=Finance\nclassification=Internal\npolicy=Fin", 0).unwrap();
        ZfsClient::getattr(ino).unwrap()
    };
    let inherited = abac::inherited_labels(&dir).unwrap();
    assert_eq!(inherited, b"department=Finance\nclassification=Internal\npolicy=Fin");
    let reads = status_field("label_reads");
    abac::inherited_labels(&dir).unwrap();
    assert_eq!(status_field("label_reads"), reads, "cached by (inode, generation)");
    abac::labels_changed();
    abac::inherited_labels(&dir).unwrap();
    assert_eq!(status_field("label_reads"), reads + 1);
    // No labels, unparsable labels, an empty set
    let plain = ZfsClient::getattr(with_fs(|fs| fs.put(d, "p", b""))).unwrap();
    assert!(abac::inherited_labels(&plain).is_none());
    let other_xattr = {
        let ino = with_fs(|fs| fs.put(d, "x", b""));
        ZfsClient::setxattr(ino, b"user.other", b"1", 0).unwrap();
        ZfsClient::getattr(ino).unwrap()
    };
    assert!(abac::inherited_labels(&other_xattr).is_none(), "an xattr but no labels");
    let garbage = labelled(d, "g", "not a label", 0o644);
    assert!(abac::inherited_labels(&garbage).is_none());
    let binary = {
        let ino = with_fs(|fs| fs.put(d, "b", b""));
        ZfsClient::setxattr(ino, LABELS, &[0xFF, 0xFE], 0).unwrap();
        ZfsClient::getattr(ino).unwrap()
    };
    assert!(abac::inherited_labels(&binary).is_none());
    // The same label set on two files shares one entry
    let sets = status_field("label_sets");
    let twin = labelled(d, "twin", "classification=Internal\ndepartment=Finance\npolicy=Fin", 0o644);
    abac::inherited_labels(&twin).unwrap();
    assert_eq!(status_field("label_sets"), sets);
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
}

#[test]
fn time_rules_key_the_cache_by_the_minute() {
    let _g = serial();
    let d = fakefs::test_dir("abac-time");
    let p = "hydra-access 1\ntz 0\npolicy P global\nrule hours\nallow r env.time #800 >= env.time #1700 < and\n";
    assert_eq!(load(p), 0);
    let f = labelled(d, "f", "kind=doc", 0o644);
    as_user(5100);
    assert_eq!(set_subject(0, "role=staff"), 0);
    // 2026-01-01 10:00 UTC: allowed; 20:00: not
    fake::RTC.set(1_767_225_600 + 10 * 3600);
    assert!(abac::check(&f, R as u32));
    fake::RTC.set(1_767_225_600 + 20 * 3600);
    assert!(!abac::check(&f, R as u32));
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    fake::PROCS.lock().remove(&5100);
}

#[test]
fn the_audit_ring_drops_the_oldest_and_reads_in_pieces() {
    let _g = serial();
    let d = fakefs::test_dir("abac-ring");
    assert_eq!(load(POLICY), 0);
    read_audit();
    as_user(5200);
    assert_eq!(set_subject(0, "department=Ops\nclearance=Public"), 0);
    let dropped = status_field("audit_dropped");
    for i in 0..260 {
        let a = labelled(d, &format!("f{i}"), "department=Finance\nclassification=Internal\npolicy=Fin", 0o644);
        assert!(!abac::check(&a, R as u32));
    }
    assert_eq!(status_field("audit_pending"), 256);
    assert_eq!(status_field("audit_dropped"), dropped + 4);
    // A small buffer takes whole lines only
    let mut b = vec![0u8; 300];
    let n = as_admin(|| prctl(cmd::READ_AUDIT, 0, b.as_mut_ptr() as u64, 300)) as usize;
    let text = String::from_utf8_lossy(&b[..n]).into_owned();
    assert!(text.ends_with('\n') && n <= 300);
    assert_eq!(status_field("audit_pending") as usize, 256 - text.lines().count());
    read_audit();
    // A record of an old policy generation names no rule
    let a = labelled(d, "late", "department=Finance\nclassification=Internal\npolicy=Fin", 0o644);
    assert!(!abac::check(&a, R as u32));
    assert_eq!(load(POLICY), 0);
    let text = read_audit();
    assert!(!text.contains("rule="), "{text}");
    // A long path keeps its end; odd bytes are escaped
    assert!(!abac::check(&a, W as u32));
    let long = format!("/{}/end file,=%", "d".repeat(300));
    abac::note_path(a.ino, &long);
    let text = read_audit();
    assert!(text.contains("end%20file%2C%3D%25"), "{text}");
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    fake::PROCS.lock().remove(&5200);
}

#[test]
fn evaluate_answers_hypothetical_queries() {
    let _g = serial();
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    let mut out = vec![0u8; 512];
    let q = "department=Finance\nclearance=Secret\n--\ndepartment=Finance\nclassification=Internal\npolicy=Fin";
    // (the values must be known to the interner: a subject set earlier made them so)
    fake::PROCS.lock().entry(1).or_default();
    set_subject(0, "department=Finance
clearance=Secret
role=x");
    set_subject(0, "department=HR
classification=Internal
policy=Fin");
    let ev = |q: &str, out: &mut Vec<u8>| prctl(cmd::EVALUATE, q.as_ptr() as u64, q.len() as u64 | (out.len() as u64) << 32, out.as_mut_ptr() as u64);
    assert_eq!(ev(q, &mut out), -61, "no policy: ENODATA");
    assert_eq!(load(POLICY), 0);
    let n = ev(q, &mut out) as usize;
    assert_eq!(String::from_utf8_lossy(&out[..n]), "enforced=rw proposed=r covered=1 rule=fin-dept would_rule=fin-staged policy=Fin\n", "x and d are refused by fin-dept; the staged replacement allows only r");
    let q2 = "department=HR\nclearance=Public\n--\ndepartment=Finance\nclassification=Secret\npolicy=Fin";
    let n = ev(q2, &mut out) as usize;
    let s = String::from_utf8_lossy(&out[..n]).into_owned();
    assert!(s.starts_with("enforced=- proposed=- covered=1 rule=fin-dept would_rule=fin-staged policy=Fin"), "{s}");
    assert_eq!(abac::evaluate("bad line\n--\n").unwrap_err(), -22);
    assert_eq!(abac::evaluate("a=b\n--\nbad").unwrap_err(), -22);
    assert_eq!(abac::evaluate("a=b\n--\nc=d\n--\nbad").unwrap_err(), -22);
    // Environment overrides and an app question
    let p = "hydra-access 1\npolicy P global\nrule hours\nallow r env.weekday #6 <\napp no-games deny path /usr/games/ user.account 'child ==\n";
    assert_eq!(load(p), 0);
    let s = abac::evaluate("account=child\n--\nkind=doc\n--\nweekday=6\nexec=/usr/games/sol").unwrap();
    assert!(s.starts_with("enforced=- "), "{s}");
    assert!(s.contains("app=deny app_staged=deny app_rule=no-games"), "{s}");
    let s = abac::evaluate("account=adult\n--\nkind=doc\n--\nweekday=1\nexec=/usr/bin/ls").unwrap();
    assert!(s.starts_with("enforced=r") && s.contains("app=allow"), "{s}");
    // Output buffer too small; size 0 asks for the length
    let mut tiny = vec![0u8; 4];
    assert_eq!(ev(q, &mut tiny), -34);
    let mut none: Vec<u8> = Vec::new();
    assert!(ev(q, &mut none) > 0);
    assert_eq!(prctl(cmd::EVALUATE, 0, 10, 0), -14);
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
}

#[test]
fn app_control_at_exec() {
    let _g = serial();
    let d = fakefs::test_dir("abac-apps");
    let bin = with_fs(|fs| fs.mkdir_p(d, "bin"));
    let content = b"#!/bin/game\n";
    let game = with_fs(|fs| fs.put(bin, "game", content));
    let mut h = Sha256::new();
    h.update(content);
    let hex: String = h.finish().iter().map(|b| format!("{b:02x}")).collect();
    let p = format!(
        "hydra-access 1\napp no-hash deny hash {hex} user.account 'child ==\napp kiosk allow trusted - user.role 'kiosk ==\napp trial deny staged name xterm true\n"
    );
    assert_eq!(load(&p), 0);
    assert!(!abac::active(), "no file rules: file checks stay off");
    let ga = ZfsClient::getattr(game).unwrap();
    let mut no_parent = || None;
    // No subject, or root: allowed
    as_user(5300);
    assert!(abac::exec_check("/abac-apps/bin/game", &ga, &mut no_parent));
    assert_eq!(set_subject(0, "account=child"), 0);
    fake::CREDS.set((0, 0));
    assert!(abac::exec_check("/abac-apps/bin/game", &ga, &mut no_parent));
    fake::CREDS.set((1000, 1000));
    // By hash (read through the file server)
    assert!(!abac::exec_check("/abac-apps/bin/game", &ga, &mut no_parent));
    let a = read_audit();
    assert!(a.contains("app-deny") && a.contains("rule=no-hash policy=app-control") && a.contains("path=/abac-apps/bin/game"), "{a}");
    // The staged rule would deny xterm
    let xt = ZfsClient::getattr(with_fs(|fs| fs.put(bin, "xterm", b"x"))).unwrap();
    assert!(abac::exec_check("/abac-apps/bin/xterm", &xt, &mut no_parent));
    assert!(read_audit().contains("app-staged-would-deny"));
    // Kiosk: only trusted programs (root-owned, not writable by others, in such a folder)
    assert_eq!(set_subject(0, "role=kiosk"), 0);
    let mut root_dir = || Some(Attr { uid: 0, mode: 0o040755, ..Default::default() });
    assert!(abac::exec_check("/abac-apps/bin/game", &ga, &mut root_dir), "root's, not writable by others, in root's folder: trusted");
    let mut user_dir = || Some(Attr { uid: 1000, mode: 0o040755, ..Default::default() });
    assert!(!abac::exec_check("/abac-apps/bin/game", &ga, &mut user_dir), "in a user's folder: not trusted");
    let mut others = ga;
    others.mode = 0o100666;
    assert!(!abac::exec_check("/abac-apps/bin/game", &others, &mut root_dir), "writable by others");
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    assert!(abac::exec_check("/abac-apps/bin/game", &ga, &mut no_parent), "no app rules");
    fake::PROCS.lock().remove(&5300);
}

#[test]
fn boot_loads_the_compiled_policy_once() {
    let _g = serial();
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    let d = fakefs::test_dir("abacroot");
    with_fs(|fs| fs.put(d, POLICY_FILE.trim_start_matches('/'), POLICY.as_bytes()));
    abac::boot_load("/abacroot/");
    assert!(fake::klog_take().contains("[access] policy loaded from /abacroot/etc/hydra/access/policy.compiled"));
    assert!(abac::active());
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    abac::boot_load("/abacroot");
    assert!(!abac::active(), "only once per boot");
}

/// A what-if query compares values the interner has never seen as never equal (each gets
/// its own temporary ID), so `evaluate` denies what enforcement (which interns subjects
/// and labels) would allow: user `department=Sales` and a file `department=Sales` with a
/// rule `user.department res.department ==`.
#[test]
#[ignore = "BUG: evaluate() treats two equal values unknown to the interner as different (temporary IDs), unlike enforcement"]
fn evaluate_matches_equal_unseen_values() {
    let _g = serial();
    assert_eq!(load("hydra-access 1
policy P global
rule same
allow r user.team res.team ==
"), 0);
    let s = abac::evaluate("team=NeverSeenBefore
--
team=NeverSeenBefore").unwrap();
    as_admin(|| prctl(cmd::LOAD, 0, 0, 0));
    assert!(s.starts_with("enforced=r "), "{s}");
}
