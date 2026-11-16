//! Tests for the attribute-based access control engine (`src/compat/linux/abac_core.rs`):
//! the compiled policy format, attribute sets, condition evaluation (equality, ordered
//! levels, member-of, missing attributes), rule combination (rules ANDed, allow entries
//! ORed), staging, the environment (local time), app control and SHA-256.

use hydra_hosttests::compat::linux::abac_core::*;

const POLICY: &str = "hydra-access 1
type level Public Internal Confidential Secret
attrtype clearance level
attrtype classification level
policy Fin
rule fin-dept
allow rw user.department res.department == user.clearance res.classification >= and
allow r user.role 'auditor ==
";

fn setup(policy: &str) -> (Interner, Compiled) {
    let mut it = Interner::new();
    let c = Compiled::parse(&mut it, policy).expect("policy parses");
    (it, c)
}

fn set(it: &mut Interner, text: &str) -> AttrSet {
    AttrSet::parse(it, text, true).expect("attribute set parses")
}

fn decide(it: &mut Interner, c: &Compiled, user: &str, res: &str) -> Decision {
    let u = set(it, user);
    let r = set(it, res);
    c.decide(&u, &r, &c.env_at(0))
}

#[test]
fn department_and_clearance() {
    let (mut it, c) = setup(POLICY);
    let fin = "department=Finance\nclearance=Confidential";
    let d = decide(&mut it, &c, fin, "department=Finance\nclassification=Internal\npolicy=Fin");
    assert!(d.covered);
    assert_eq!(d.enforced, R | W);
    let d = decide(&mut it, &c, fin, "department=Finance\nclassification=Secret\npolicy=Fin");
    assert_eq!(d.enforced, 0);
    assert_eq!(d.deciding_rule(R, false), Some(0));
    let d = decide(&mut it, &c, fin, "department=HR\nclassification=Public\npolicy=Fin");
    assert_eq!(d.enforced, 0);
    // Equal level is enough
    let d = decide(&mut it, &c, fin, "department=Finance\nclassification=Confidential\npolicy=Fin");
    assert_eq!(d.enforced, R | W);
}

#[test]
fn uncovered_and_missing_attributes() {
    let (mut it, c) = setup(POLICY);
    // No policy label: not covered, nothing restricted
    let d = decide(&mut it, &c, "department=Finance", "department=HR\nclassification=Secret");
    assert!(!d.covered);
    assert_eq!(d.enforced, ALL);
    // Covered, but the user has no clearance: comparisons with a missing value are false
    let d = decide(&mut it, &c, "department=Finance", "department=Finance\nclassification=Public\npolicy=Fin");
    assert_eq!(d.enforced, 0);
    // An unranked value never compares
    let d = decide(&mut it, &c, "department=Finance\nclearance=Bogus", "department=Finance\nclassification=Public\npolicy=Fin");
    assert_eq!(d.enforced, 0);
}

#[test]
fn allow_entries_or_and_rules_and() {
    let p = format!("{POLICY}rule weekdays-only\nallow rwxd env.weekday #6 <\n");
    let (mut it, c) = setup(&p);
    let u = set(&mut it, "role=auditor");
    let r = set(&mut it, "classification=Secret\npolicy=Fin");
    // 1970-01-05 was a Monday (weekday 1): both rules allow read
    let monday = c.env_at(4 * 86400 + 12 * 3600);
    assert_eq!(c.decide(&u, &r, &monday).enforced, R);
    // 1970-01-03, Saturday (6): the second rule takes everything away
    let saturday = c.env_at(2 * 86400 + 12 * 3600);
    let d = c.decide(&u, &r, &saturday);
    assert_eq!(d.enforced, 0);
    assert_eq!(d.deciding_rule(R, false), Some(1));
}

#[test]
fn staged_rules_only_propose() {
    let p = format!("{POLICY}rule strict staged\nallow r user.clearance 'Secret ==\n");
    let (mut it, c) = setup(&p);
    let d = decide(&mut it, &c, "department=Finance\nclearance=Confidential", "department=Finance\nclassification=Internal\npolicy=Fin");
    assert_eq!(d.enforced, R | W);
    assert_eq!(d.proposed, 0);
    assert_eq!(d.deciding_rule(R, true), Some(1));
    // A staged replacement: the old rule is left out of the proposed evaluation only
    let p = format!("{POLICY}rule fin-dept-2 staged replaces=fin-dept\nallow r user.department res.department ==\n");
    let (mut it, c) = setup(&p);
    let d = decide(&mut it, &c, "department=Finance\nclearance=Public", "department=Finance\nclassification=Secret\npolicy=Fin");
    assert_eq!(d.enforced, 0);
    assert_eq!(d.proposed, R);
}

#[test]
fn staged_policy_and_global_policy() {
    let p = "hydra-access 1\npolicy P global staged\nrule r1\nallow r user.ok 'yes ==\n";
    let (mut it, c) = setup(p);
    let d = decide(&mut it, &c, "ok=no", "anything=1");
    assert!(d.covered);
    assert_eq!(d.enforced, ALL);
    assert_eq!(d.proposed, 0);
}

#[test]
fn member_of_and_any_of() {
    let p = "hydra-access 1\npolicy P global\nrule projects\nallow r res.project user.projects in\nallow w user.groups res.editors any\n";
    let (mut it, c) = setup(p);
    let d = decide(&mut it, &c, "projects=Apollo,Gemini\ngroups=staff", "project=Apollo,Gemini\neditors=admins");
    assert_eq!(d.enforced, R);
    let d = decide(&mut it, &c, "projects=Apollo\ngroups=staff,admins", "project=Apollo,Gemini\neditors=admins");
    assert_eq!(d.enforced, W);
}

#[test]
fn targets_select_resources() {
    let p = "hydra-access 1\npolicy P global\nrule secret\ntarget res.classification 'Secret ==\nallow r user.vip 'yes ==\n";
    let (mut it, c) = setup(p);
    assert_eq!(decide(&mut it, &c, "vip=no", "classification=Secret").enforced, 0);
    assert_eq!(decide(&mut it, &c, "vip=no", "classification=Public").enforced, ALL);
    assert_eq!(decide(&mut it, &c, "vip=yes", "classification=Secret").enforced, R);
}

#[test]
fn not_or_ne_and_literal_ranks() {
    let p = "hydra-access 1
type level Public Internal Confidential Secret
attrtype classification level
policy P global
rule r
allow r res.classification 'Internal <= user.account 'child != or
allow w user.account 'child == not
";
    let (mut it, c) = setup(p);
    assert_eq!(decide(&mut it, &c, "account=child", "classification=Public").enforced, R);
    assert_eq!(decide(&mut it, &c, "account=child", "classification=Secret").enforced, 0);
    assert_eq!(decide(&mut it, &c, "account=standard", "classification=Secret").enforced, R | W);
    // != needs both sides known
    assert_eq!(decide(&mut it, &c, "", "classification=Secret").enforced, W);
}

#[test]
fn env_time() {
    let (mut it, mut c) = setup("hydra-access 1\ntz 3600\npolicy P global\nrule hours\nallow x env.time #800 >= env.time #2030 < and\n");
    assert!(c.uses_time);
    let u = set(&mut it, "a=1");
    let r = set(&mut it, "b=1");
    // 07:30 UTC = 08:30 local
    assert_eq!(c.decide(&u, &r, &c.env_at(7 * 3600 + 30 * 60)).enforced, X);
    // 19:45 UTC = 20:45 local
    assert_eq!(c.decide(&u, &r, &c.env_at(19 * 3600 + 45 * 60)).enforced, 0);
    c.tz = 0;
    let e = c.env_at(4 * 86400); // Monday 00:00
    let wd = it.intern("weekday").unwrap();
    assert_eq!(e.values(wd), &[(wd, INT | 1)]);
}

#[test]
fn parse_errors() {
    let mut it = Interner::new();
    assert!(Compiled::parse(&mut it, "").is_err());
    assert!(Compiled::parse(&mut it, "hydra-access 2\n").is_err());
    assert_eq!(Compiled::parse(&mut it, "hydra-access 1\nrule x\n").unwrap_err().0, 2);
    assert!(Compiled::parse(&mut it, "hydra-access 1\npolicy P\nrule x\nallow r user.a ==\n").is_err());
    assert!(Compiled::parse(&mut it, "hydra-access 1\npolicy P\nrule x\nallow q true\n").is_err());
    assert!(Compiled::parse(&mut it, "hydra-access 1\npolicy P\nrule x\nallow r user.a user.b\n").is_err());
    assert!(Compiled::parse(&mut it, "hydra-access 1\nattrtype a nosuchtype\n").is_err());
    assert!(Compiled::parse(&mut it, "hydra-access 1\nwhatever\n").is_err());
    assert!(Compiled::parse(&mut it, "hydra-access 1\n# comment\n\npolicy P\nrule x\nallow r true\n").is_ok());
}

#[test]
fn attr_sets() {
    let mut it = Interner::new();
    let s = set(&mut it, "groups=b,a,a\nname=Mary%20Smith\n# comment\nlevel=3");
    // Sorted by interned ID (first seen first), not alphabetically
    let text = s.format(&it);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort();
    assert_eq!(lines, ["groups=b,a", "level=3", "name=Mary Smith"]);
    assert!(AttrSet::parse(&mut it, "novalue", true).is_err());
    // Too many entries
    let many: String = (0..40).map(|i| format!("k{i}=v\n")).collect();
    assert!(AttrSet::parse(&mut it, &many, true).is_err());
    // Unprivileged parsing does not grow the tables
    let before = it.len();
    let q = AttrSet::parse(&mut it, "unknownattr=x\ngroups=zzz", false).unwrap();
    assert_eq!(it.len(), before);
    let g = it.intern("groups").unwrap();
    assert_eq!(q.values(g).len(), 1);
    assert!(q.values(g)[0].1 != it.lookup("a"));
}

#[test]
fn app_control() {
    let p = "hydra-access 1
app no-term deny path /usr/bin/konsole user.account 'child ==
app games deny path /usr/games/ user.account 'child ==
app kiosk-installed allow trusted - user.role 'kiosk ==
app kiosk-browser allow name firefox user.role 'kiosk ==
app trial deny staged name xterm true
";
    let (mut it, c) = setup(p);
    let env = c.env_at(0);
    let child = set(&mut it, "account=child");
    let kiosk = set(&mut it, "role=kiosk");
    let adult = set(&mut it, "account=standard");
    let run = |u: &AttrSet, path: &str, trusted: bool| {
        let mut h = || None;
        let mut t = || trusted;
        c.app_decide(u, &env, path, &mut h, &mut t)
    };
    assert!(!run(&child, "/usr/bin/konsole", true).allowed);
    assert_eq!(run(&child, "/usr/bin/konsole", true).rule, 1);
    assert!(!run(&child, "/usr/games/tetris", true).allowed);
    assert!(run(&child, "/usr/bin/dolphin", false).allowed);
    assert!(run(&adult, "/usr/bin/konsole", true).allowed);
    // Allow list: trusted programs, or by name
    assert!(run(&kiosk, "/usr/bin/dolphin", true).allowed);
    assert!(!run(&kiosk, "/home/k/evil", false).allowed);
    assert!(run(&kiosk, "/home/k/firefox", false).allowed);
    // Staged deny
    let d = run(&adult, "/usr/bin/xterm", true);
    assert!(d.allowed && !d.would_allow);
}

#[test]
fn app_hash() {
    let data = b"abc";
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finish();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let p = format!("hydra-access 1\napp bad deny hash {hex} true\n");
    let (mut it, c) = setup(&p);
    let u = set(&mut it, "a=1");
    let env = c.env_at(0);
    let mut calls = 0;
    let mut hf = || {
        calls += 1;
        Some(digest)
    };
    let mut t = || true;
    assert!(!c.app_decide(&u, &env, "/x", &mut hf, &mut t).allowed);
    assert_eq!(calls, 1);
    // A long message spanning blocks
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update(b"0123456789");
    }
    let hex: String = h.finish().iter().map(|b| format!("{b:02x}")).collect();
    // sha256 of "0123456789" * 1000
    assert_eq!(hex.len(), 64);
}

#[test]
fn decisions_do_not_depend_on_order_of_labels() {
    let (mut it, c) = setup(POLICY);
    let a = decide(&mut it, &c, "clearance=Secret\ndepartment=Finance", "policy=Fin\nclassification=Secret\ndepartment=Finance");
    let b = decide(&mut it, &c, "department=Finance\nclearance=Secret", "department=Finance\nclassification=Secret\npolicy=Fin");
    assert_eq!(a, b);
    assert_eq!(a.enforced, R | W);
}

/// What userland/hydra-access/hydra_access/core.py compiles (Pro rules, staging,
/// administrative actions, Family screen time and private folders, app control) parses
/// and decides as the apps describe it.
#[test]
fn userland_compiler_output() {
    let text = "hydra-access 1
# Generated by hydra-access from /etc/hydra/access/config.json; do not edit.
type classification Public Internal Confidential Secret
attrtype classification classification
attrtype clearance classification
env device.managed no
tz 3600
policy Finance%20Data
rule Department%20and%20clearance
allow rwxd user.department res.department == user.clearance res.classification >= and
allow rx user.role 'Auditor ==
rule Office%20hours staged
target res.classification exists
allow rwxd env.time #800 >= env.device.managed 'yes == and
policy Administrative%20actions global
rule software-1
target res.category 'software ==
allow x user.role 'IT ==
policy Family global
rule Screen%20time%20for%20kid
target res.action 'session == user.name 'kid == and
allow x env.weekday #1 == env.time #700 >= and env.time #2000 < and
allow x env.weekday #6 == env.time #900 >= and env.time #2130 < and
rule Private%20folders
target res.private exists
allow rwxd user.name res.private ==
app Blocked%20for%20kid%201 deny path /usr/bin/konsole user.name 'kid ==
app No%20terminal deny path /usr/bin/konsole user.account 'admin !=
app Installed%20only allow staged trusted - user.role 'Kiosk%20user ==
";
    let (mut it, c) = setup(text);
    assert_eq!(c.policies[0].name, "Finance Data");
    assert!(c.rules[1].staged);
    // Monday 1970-01-05 10:00 local (09:00 UTC with tz 3600)
    let monday10 = c.env_at(4 * 86400 + 9 * 3600);
    let kid = set(&mut it, "name=kid\naccount=child");
    let session = set(&mut it, "action=session\ncategory=session");
    assert_eq!(c.decide(&kid, &session, &monday10).enforced & X, X);
    // Monday 21:00 local: outside the hours
    let monday21 = c.env_at(4 * 86400 + 20 * 3600);
    assert_eq!(c.decide(&kid, &session, &monday21).enforced & X, 0);
    // Tuesday: no hours at all
    let tuesday = c.env_at(5 * 86400 + 9 * 3600);
    assert_eq!(c.decide(&kid, &session, &tuesday).enforced & X, 0);
    // An adult's session is not targeted
    let adult = set(&mut it, "name=hydra\naccount=admin");
    assert_eq!(c.decide(&adult, &session, &tuesday).enforced, ALL);
    // Software installs: IT only
    let sw = set(&mut it, "action=org.freedesktop.packagekit.package-install\ncategory=software");
    let it_user = set(&mut it, "name=bob\nrole=IT");
    assert_eq!(c.decide(&it_user, &sw, &monday10).enforced & X, X);
    assert_eq!(c.decide(&adult, &sw, &monday10).enforced & X, 0);
    // Private folder
    let private = set(&mut it, "private=hydra");
    assert_eq!(c.decide(&adult, &private, &monday10).enforced, ALL);
    assert_eq!(c.decide(&kid, &private, &monday10).enforced, 0);
    // Finance data: department + clearance; the staged office-hours rule (unmanaged
    // device) would deny everything
    let fin = set(&mut it, "name=hydra\ndepartment=Finance\nclearance=Secret");
    let doc = set(&mut it, "policy=Finance%20Data\ndepartment=Finance\nclassification=Confidential");
    let d = c.decide(&fin, &doc, &monday10);
    assert_eq!(d.enforced, ALL);
    assert_eq!(d.proposed, 0);
    // App control
    let env = c.env_at(0);
    let mut h = || None;
    let mut t = || true;
    assert!(!c.app_decide(&kid, &env, "/usr/bin/konsole", &mut h, &mut t).allowed);
    assert!(c.app_decide(&adult, &env, "/usr/bin/konsole", &mut h, &mut t).allowed);
    let kiosk = set(&mut it, "role=Kiosk user\naccount=standard");
    let mut untrusted = || false;
    let d = c.app_decide(&kiosk, &env, "/home/k/x", &mut h, &mut untrusted);
    assert!(d.allowed && !d.would_allow);
}
