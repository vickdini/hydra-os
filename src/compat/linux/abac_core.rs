//! Attribute-based access control: the pure engine (no kernel dependencies, so the host
//! tests compile this very file).
//!
//! Everything here works on small integer IDs: attribute names and values are interned
//! ([`Interner`]) when a policy, a subject or a label set is loaded, so a decision compares
//! `u32`s and never allocates.
//!
//! - **Attribute sets** ([`AttrSet`]): a subject's attributes (`department=Finance`,
//!   `clearance=Secret`, `groups=sudo,finance`, ...) or a file's labels
//!   (`classification=Confidential`, `policy=Finance`). Fixed capacity, sorted by
//!   attribute; a multi-valued attribute has one entry per value.
//! - **Policy** ([`Compiled`]): ordered value types (`Public < Internal < Confidential <
//!   Secret`), policies made of rules. A rule has a *target* condition on the resource
//!   (which files it covers) and *allow* entries, each a condition and the actions it grants
//!   (`r` read, `w` write, `x` execute, `d` delete). Conditions are in postfix form (the
//!   userland compiler produces them), evaluated on a fixed stack.
//! - **Decision** ([`Compiled::decide`]): the policies that cover a file are the global
//!   ones and those its `policy` label names. Every covering rule whose target matches
//!   restricts the allowed actions to what its allow entries grant (rules are ANDed, allow
//!   entries ORed, as in Windows central access rules). Nothing covering = no restriction.
//!   Staged (proposed) rules and policies are evaluated separately: they never restrict,
//!   but the caller logs where they would have decided differently.
//! - **App control** ([`Compiled::app_decide`]): deny rules, and allow rules that turn on
//!   an allow list for the subjects they apply to.
//!
//! The compiled text format (written by `hydra-access` in userland, one directive per
//! line, tokens separated by spaces, `%XX` escapes inside tokens):
//!
//! ```text
//! hydra-access 1
//! type level Public Internal Confidential Secret
//! attrtype clearance level
//! env device.managed yes
//! tz 3600
//! policy Finance [global] [staged]
//! rule Finance-read [staged] [replaces=Old-rule]
//! target res.department exists
//! allow rw user.department res.department == user.clearance res.classification >= and
//! app Block-konsole deny [staged] path /usr/bin/konsole user.account 'child ==
//! ```
//!
//! Condition tokens: `user.X`, `res.X`, `env.X` (attribute values), `'text` (a literal;
//! ranked if it is a value of an ordered type), `#N` (an integer), `true`, `false`,
//! `==` (some value in common), `!=` (both known, none in common), `>=` `<=` `>` `<`
//! (ranks of the first ranked values), `in` (every left value is among the right ones:
//! member-of), `any` (some value in common), `exists` (has a value), `and`, `or`, `not`.
//! A missing attribute makes comparisons false, so a rule never grants on unknown data.
#![allow(missing_docs)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Read.
pub const R: u8 = 4;
/// Write (also: create in a folder).
pub const W: u8 = 2;
/// Execute (also: enter a folder; for admin actions: perform it).
pub const X: u8 = 1;
/// Delete (unlink, rmdir, move away).
pub const D: u8 = 8;
/// Every action.
pub const ALL: u8 = R | W | X | D;

/// Value IDs with this bit are integers (the low 31 bits), not interned strings.
pub const INT: u32 = 1 << 31;
/// Value IDs from here on are temporary (strings an unprivileged query used that no
/// policy, subject or label knows: they match only themselves).
const TEMP_BASE: u32 = 1 << 30;

/// Most entries in an attribute set.
pub const MAX_ATTRS: usize = 32;
/// Deepest condition stack.
const STACK: usize = 16;

/// Interns attribute names and values.
#[derive(Default)]
pub struct Interner {
    names: Vec<String>,
    ids: BTreeMap<String, u32>,
    temp: u32,
}

impl Interner {
    /// An empty interner (ID 0 is the empty string).
    pub fn new() -> Self {
        let mut i = Interner { names: Vec::new(), ids: BTreeMap::new(), temp: 0 };
        i.intern("");
        i
    }
    /// The ID of `s`, added if new (`None` when the table is full).
    pub fn intern(&mut self, s: &str) -> Option<u32> {
        if let Some(&id) = self.ids.get(s) {
            return Some(id);
        }
        if self.names.len() >= (TEMP_BASE as usize) - 1 || self.names.len() >= 1 << 20 {
            return None;
        }
        let id = self.names.len() as u32;
        self.names.push(String::from(s));
        self.ids.insert(String::from(s), id);
        Some(id)
    }
    /// The ID of `s` if known, else a temporary ID that equals nothing else.
    pub fn lookup(&mut self, s: &str) -> u32 {
        match self.ids.get(s) {
            Some(&id) => id,
            None => {
                self.temp = self.temp.wrapping_add(1) & (TEMP_BASE - 1);
                TEMP_BASE | self.temp
            }
        }
    }
    /// The text of ID `id`.
    pub fn name(&self, id: u32) -> &str {
        self.names.get(id as usize).map_or("?", |s| s.as_str())
    }
    /// How many strings are interned.
    pub fn len(&self) -> usize {
        self.names.len()
    }
}

/// Decodes `%XX` escapes.
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = |c: u8| (c as char).to_digit(16);
            if let (Some(x), Some(y)) = (h(b[i + 1]), h(b[i + 2])) {
                out.push((x * 16 + y) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// A value's ID: digits are integers, other text is interned (`intern`) or looked up.
fn value_id(it: &mut Interner, text: &str, intern: bool) -> Option<u32> {
    if !text.is_empty() && text.len() <= 9 && text.bytes().all(|c| c.is_ascii_digit()) {
        return text.parse::<u32>().ok().map(|n| INT | n);
    }
    if intern { it.intern(text) } else { Some(it.lookup(text)) }
}

/// A set of attributes: `(attribute, value)` pairs sorted by attribute (then value).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttrSet {
    n: u8,
    e: [(u32, u32); MAX_ATTRS],
}

impl Default for AttrSet {
    fn default() -> Self {
        AttrSet { n: 0, e: [(0, 0); MAX_ATTRS] }
    }
}

impl core::fmt::Debug for AttrSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.entries()).finish()
    }
}

impl AttrSet {
    /// The entries.
    pub fn entries(&self) -> &[(u32, u32)] {
        &self.e[..self.n as usize]
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    /// Adds an entry (kept sorted, duplicates dropped); `false` when full.
    pub fn push(&mut self, attr: u32, val: u32) -> bool {
        let n = self.n as usize;
        let pos = self.e[..n].partition_point(|&x| x < (attr, val));
        if pos < n && self.e[pos] == (attr, val) {
            return true;
        }
        if n >= MAX_ATTRS {
            return false;
        }
        self.e.copy_within(pos..n, pos + 1);
        self.e[pos] = (attr, val);
        self.n += 1;
        true
    }
    /// Removes every value of `attr`.
    pub fn remove(&mut self, attr: u32) {
        let mut k = 0;
        for i in 0..self.n as usize {
            if self.e[i].0 != attr {
                self.e[k] = self.e[i];
                k += 1;
            }
        }
        self.n = k as u8;
    }
    /// The values of `attr`.
    pub fn values(&self, attr: u32) -> &[(u32, u32)] {
        let all = self.entries();
        let lo = all.partition_point(|&(a, _)| a < attr);
        let hi = all.partition_point(|&(a, _)| a <= attr);
        &all[lo..hi]
    }
    /// Parses `key=v1,v2` lines (`#` comments, `%XX` escapes). With `intern` false, unknown
    /// attribute names are skipped and unknown values get temporary IDs (unprivileged
    /// queries must not grow the tables). `Err(line)` on a malformed or overlong set.
    pub fn parse(it: &mut Interner, text: &str, intern: bool) -> Result<AttrSet, usize> {
        let mut s = AttrSet::default();
        for (no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or(no + 1)?;
            let k = unescape(k.trim());
            if k.is_empty() {
                return Err(no + 1);
            }
            let attr = if intern {
                it.intern(&k).ok_or(no + 1)?
            } else {
                match it.ids.get(k.as_str()) {
                    Some(&a) => a,
                    None => continue,
                }
            };
            for v in v.split(',') {
                let v = unescape(v.trim());
                if v.is_empty() {
                    continue;
                }
                let val = value_id(it, &v, intern).ok_or(no + 1)?;
                if !s.push(attr, val) {
                    return Err(no + 1);
                }
            }
        }
        Ok(s)
    }
    /// The set as `key=v1,v2` lines.
    pub fn format(&self, it: &Interner) -> String {
        let mut out = String::new();
        let mut last = u32::MAX;
        for &(a, v) in self.entries() {
            if a != last {
                if last != u32::MAX {
                    out.push('\n');
                }
                out.push_str(it.name(a));
                out.push('=');
                last = a;
            } else {
                out.push(',');
            }
            if v & INT != 0 {
                out.push_str(&alloc::format!("{}", v & !INT));
            } else if v & TEMP_BASE != 0 {
                out.push('?');
            } else {
                out.push_str(it.name(v));
            }
        }
        if last != u32::MAX {
            out.push('\n');
        }
        out
    }
}

/// Which attribute set an operand reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    /// The subject (the user's session).
    User,
    /// The resource (the file's labels, or an admin action's description).
    Res,
    /// The environment (time, device).
    Env,
}

/// Comparison operators.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CmpOp {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
    In,
    Any,
}

/// A condition step (postfix).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Attr(Side, u32),
    Lit(u32),
    Bool(bool),
    Cmp(CmpOp),
    Exists,
    And,
    Or,
    Not,
}

/// A condition in postfix form.
#[derive(Clone, Default, Debug)]
pub struct Cond {
    pub ops: Vec<Op>,
}

/// One rule of a policy.
#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub policy: usize,
    pub staged: bool,
    /// Replaced (in the proposed evaluation) by a staged rule.
    pub replaced: bool,
    pub target: Cond,
    pub allows: Vec<(u8, Cond)>,
}

/// A policy: rules applied together.
#[derive(Clone, Debug)]
pub struct Policy {
    pub name: String,
    pub name_id: u32,
    pub global: bool,
    pub staged: bool,
}

/// What an app rule matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppMatch {
    /// The program's path exactly.
    Path(String),
    /// Programs under a directory (ends with `/`).
    Prefix(String),
    /// The program's file name.
    Name(String),
    /// The SHA-256 of the program.
    Hash([u8; 32]),
    /// A program installed by the administrator: root's, not writable by others, in a
    /// folder that is root's and not writable by others (like Windows' "Program Files").
    Trusted,
}

/// An app-control rule.
#[derive(Clone, Debug)]
pub struct AppRule {
    pub name: String,
    pub deny: bool,
    pub staged: bool,
    pub what: AppMatch,
    /// Whom it applies to (subject and environment).
    pub cond: Cond,
}

/// A loaded policy set.
#[derive(Clone, Default, Debug)]
pub struct Compiled {
    /// Ordered types: their values, lowest first.
    pub types: Vec<Vec<u32>>,
    /// The type of each ordered attribute.
    pub attr_type: BTreeMap<u32, usize>,
    /// Static environment attributes (`env device.managed yes`).
    pub env: AttrSet,
    /// Local time offset from UTC, seconds.
    pub tz: i32,
    pub policies: Vec<Policy>,
    pub rules: Vec<Rule>,
    pub apps: Vec<AppRule>,
    /// A condition reads `env.time`, `env.hour`, `env.minute` or `env.weekday`.
    pub uses_time: bool,
    /// IDs of the names the evaluator reads.
    pub ids: Ids,
}

/// Interned names the evaluator needs.
#[derive(Clone, Copy, Default, Debug)]
pub struct Ids {
    pub policy: u32,
    pub hour: u32,
    pub minute: u32,
    pub time: u32,
    pub weekday: u32,
}

/// A decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decision {
    /// Allowed actions (enforced rules).
    pub enforced: u8,
    /// Allowed actions were the staged rules enforced.
    pub proposed: u8,
    /// Some policy covers the resource.
    pub covered: bool,
    /// For each action bit (index 0 `x`, 1 `w`, 2 `r`, 3 `d`): the rule (index + 1) that
    /// first refused it, enforced then proposed; 0 none.
    pub refused_by: [u16; 4],
    pub would_refuse_by: [u16; 4],
}

impl Decision {
    /// No restriction.
    pub const OPEN: Decision = Decision { enforced: ALL, proposed: ALL, covered: false, refused_by: [0; 4], would_refuse_by: [0; 4] };
    /// The rule (index) that refused the first of `want`'s actions not allowed.
    pub fn deciding_rule(&self, want: u8, proposed: bool) -> Option<usize> {
        let (mask, by) = if proposed { (self.proposed, &self.would_refuse_by) } else { (self.enforced, &self.refused_by) };
        (0..4).find(|&b| want & (1 << b) != 0 && mask & (1 << b) == 0).and_then(|b| by[b].checked_sub(1)).map(|r| r as usize)
    }
}

/// The result of an app-control check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AppDecision {
    pub allowed: bool,
    pub would_allow: bool,
    /// The deciding rule (index + 1; 0: the allow list matched nothing, or no rule).
    pub rule: u16,
    pub would_rule: u16,
}

/// Parses an action string (`rwxd` letters).
pub fn parse_actions(s: &str) -> Option<u8> {
    let mut m = 0;
    for c in s.chars() {
        m |= match c {
            'r' => R,
            'w' => W,
            'x' => X,
            'd' => D,
            '-' => 0,
            _ => return None,
        };
    }
    Some(m)
}

/// Formats an action mask (`rwxd`, `-` for none).
pub fn format_actions(m: u8) -> String {
    let mut s = String::new();
    for (bit, c) in [(R, 'r'), (W, 'w'), (X, 'x'), (D, 'd')] {
        if m & bit != 0 {
            s.push(c);
        }
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// Parses a hex SHA-256.
fn parse_hash(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(h)
}

impl Compiled {
    /// Parses the compiled text. `Err((line, reason))`.
    pub fn parse(it: &mut Interner, text: &str) -> Result<Compiled, (usize, &'static str)> {
        let mut c = Compiled::default();
        let mut header = false;
        let mut type_names: Vec<String> = Vec::new();
        let ids = |it: &mut Interner, s: &str| it.intern(s).ok_or((0, "intern table full"));
        c.ids = Ids {
            policy: ids(it, "policy")?,
            hour: ids(it, "hour")?,
            minute: ids(it, "minute")?,
            time: ids(it, "time")?,
            weekday: ids(it, "weekday")?,
        };
        for (no, line) in text.lines().enumerate() {
            let no = no + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut tok = line.split_ascii_whitespace();
            let kw = tok.next().unwrap_or("");
            if !header {
                if kw != "hydra-access" || tok.next() != Some("1") {
                    return Err((no, "expected 'hydra-access 1'"));
                }
                header = true;
                continue;
            }
            let rest: Vec<&str> = tok.collect();
            match kw {
                "type" => {
                    let name = rest.first().ok_or((no, "type needs a name"))?;
                    let mut vals = Vec::new();
                    for v in &rest[1..] {
                        vals.push(value_id(it, &unescape(v), true).ok_or((no, "intern table full"))?);
                    }
                    type_names.push(unescape(name));
                    c.types.push(vals);
                }
                "attrtype" => {
                    if rest.len() != 2 {
                        return Err((no, "attrtype <attribute> <type>"));
                    }
                    let a = it.intern(&unescape(rest[0])).ok_or((no, "intern table full"))?;
                    let t = type_names.iter().position(|n| *n == unescape(rest[1])).ok_or((no, "unknown type"))?;
                    c.attr_type.insert(a, t);
                }
                "env" => {
                    if rest.len() != 2 {
                        return Err((no, "env <attribute> <value>"));
                    }
                    let a = it.intern(&unescape(rest[0])).ok_or((no, "intern table full"))?;
                    let v = value_id(it, &unescape(rest[1]), true).ok_or((no, "intern table full"))?;
                    c.env.push(a, v);
                }
                "tz" => {
                    c.tz = rest.first().and_then(|s| s.parse().ok()).ok_or((no, "tz <seconds>"))?;
                }
                "policy" => {
                    let name = unescape(rest.first().ok_or((no, "policy needs a name"))?);
                    let name_id = it.intern(&name).ok_or((no, "intern table full"))?;
                    let flags = &rest[1..];
                    if flags.iter().any(|f| *f != "global" && *f != "staged") {
                        return Err((no, "unknown policy flag"));
                    }
                    c.policies.push(Policy { name, name_id, global: flags.contains(&"global"), staged: flags.contains(&"staged") });
                }
                "rule" => {
                    if c.policies.is_empty() {
                        return Err((no, "rule outside a policy"));
                    }
                    let name = unescape(rest.first().ok_or((no, "rule needs a name"))?);
                    let mut staged = false;
                    for f in &rest[1..] {
                        if *f == "staged" {
                            staged = true;
                        } else if let Some(r) = f.strip_prefix("replaces=") {
                            let r = unescape(r);
                            let p = c.policies.len() - 1;
                            let old = c.rules.iter_mut().find(|x| x.name == r && x.policy == p).ok_or((no, "replaces an unknown rule"))?;
                            old.replaced = true;
                        } else {
                            return Err((no, "unknown rule flag"));
                        }
                    }
                    c.rules.push(Rule { name, policy: c.policies.len() - 1, staged, replaced: false, target: Cond::default(), allows: Vec::new() });
                }
                "target" | "allow" => {
                    let rule = c.rules.last_mut().ok_or((no, "target/allow outside a rule"))?;
                    let (mask, toks) = if kw == "allow" {
                        (parse_actions(rest.first().ok_or((no, "allow <actions> <condition>"))?).ok_or((no, "bad actions"))?, &rest[1..])
                    } else {
                        (0, &rest[..])
                    };
                    let (cond, time) = parse_cond(it, toks, &c.ids).map_err(|e| (no, e))?;
                    c.uses_time |= time;
                    if kw == "allow" {
                        rule.allows.push((mask, cond));
                    } else {
                        rule.target = cond;
                    }
                }
                "app" => {
                    // app <name> <allow|deny> [staged] <kind> <pattern> <condition...>
                    if rest.len() < 4 {
                        return Err((no, "app <name> <allow|deny> [staged] <kind> <pattern> <condition>"));
                    }
                    let name = unescape(rest[0]);
                    let deny = match rest[1] {
                        "allow" => false,
                        "deny" => true,
                        _ => return Err((no, "app rules allow or deny")),
                    };
                    let mut i = 2;
                    let staged = rest[i] == "staged";
                    if staged {
                        i += 1;
                    }
                    if rest.len() < i + 2 {
                        return Err((no, "app rule too short"));
                    }
                    let pat = unescape(rest[i + 1]);
                    let what = match rest[i] {
                        "path" if pat.ends_with('/') => AppMatch::Prefix(pat),
                        "path" => AppMatch::Path(pat),
                        "name" => AppMatch::Name(pat),
                        "hash" => AppMatch::Hash(parse_hash(&pat.to_ascii_lowercase()).ok_or((no, "bad hash"))?),
                        "trusted" => AppMatch::Trusted,
                        _ => return Err((no, "unknown app match")),
                    };
                    let (cond, time) = parse_cond(it, &rest[i + 2..], &c.ids).map_err(|e| (no, e))?;
                    c.uses_time |= time;
                    c.apps.push(AppRule { name, deny, staged, what, cond });
                }
                _ => return Err((no, "unknown directive")),
            }
        }
        if !header {
            return Err((0, "empty policy"));
        }
        if c.rules.len() > u16::MAX as usize - 1 || c.apps.len() > u16::MAX as usize - 1 {
            return Err((0, "too many rules"));
        }
        Ok(c)
    }

    /// The rank of a value of attribute `attr` (`None`: unordered).
    fn rank(&self, attr: Option<u32>, val: u32) -> Option<i64> {
        if val & INT != 0 {
            return Some((val & !INT) as i64);
        }
        match attr.and_then(|a| self.attr_type.get(&a)) {
            Some(&t) => self.types[t].iter().position(|&v| v == val).map(|p| p as i64),
            // A literal: its rank in whichever ordered type has it
            None => self.types.iter().find_map(|t| t.iter().position(|&v| v == val)).map(|p| p as i64),
        }
    }

    /// Evaluates a condition (an empty one is true).
    pub fn eval(&self, cond: &Cond, user: &AttrSet, res: &AttrSet, env: &AttrSet) -> bool {
        #[derive(Clone, Copy)]
        enum Item {
            Set(Side, u32),
            Lit(u32),
            Bool(bool),
        }
        if cond.ops.is_empty() {
            return true;
        }
        let set = |s: Side| match s {
            Side::User => user,
            Side::Res => res,
            Side::Env => env,
        };
        let truth = |i: &Item| match *i {
            Item::Bool(b) => b,
            Item::Set(s, a) => !set(s).values(a).is_empty(),
            Item::Lit(_) => true,
        };
        let mut st = [Item::Bool(false); STACK];
        let mut sp = 0usize;
        for op in &cond.ops {
            match *op {
                Op::Attr(s, a) => {
                    if sp == STACK {
                        return false;
                    }
                    st[sp] = Item::Set(s, a);
                    sp += 1;
                }
                Op::Lit(v) => {
                    if sp == STACK {
                        return false;
                    }
                    st[sp] = Item::Lit(v);
                    sp += 1;
                }
                Op::Bool(b) => {
                    if sp == STACK {
                        return false;
                    }
                    st[sp] = Item::Bool(b);
                    sp += 1;
                }
                Op::Not | Op::Exists => {
                    if sp < 1 {
                        return false;
                    }
                    let t = truth(&st[sp - 1]);
                    st[sp - 1] = Item::Bool(if *op == Op::Not { !t } else { t });
                }
                Op::And | Op::Or => {
                    if sp < 2 {
                        return false;
                    }
                    let (a, b) = (truth(&st[sp - 2]), truth(&st[sp - 1]));
                    sp -= 1;
                    st[sp - 1] = Item::Bool(if *op == Op::And { a && b } else { a || b });
                }
                Op::Cmp(c) => {
                    if sp < 2 {
                        return false;
                    }
                    let (lb, rb): ([(u32, u32); 1], [(u32, u32); 1]);
                    let (la, l): (Option<u32>, &[(u32, u32)]) = match st[sp - 2] {
                        Item::Set(s, a) => (Some(a), set(s).values(a)),
                        Item::Lit(v) => {
                            lb = [(0, v)];
                            (None, &lb)
                        }
                        Item::Bool(_) => (None, &[]),
                    };
                    let (ra, r): (Option<u32>, &[(u32, u32)]) = match st[sp - 1] {
                        Item::Set(s, a) => (Some(a), set(s).values(a)),
                        Item::Lit(v) => {
                            rb = [(0, v)];
                            (None, &rb)
                        }
                        Item::Bool(_) => (None, &[]),
                    };
                    let common = l.iter().any(|x| r.iter().any(|y| x.1 == y.1));
                    let first_rank = |attr: Option<u32>, s: &[(u32, u32)]| s.iter().find_map(|x| self.rank(attr, x.1));
                    let res = match c {
                        CmpOp::Eq | CmpOp::Any => common,
                        CmpOp::Ne => !l.is_empty() && !r.is_empty() && !common,
                        CmpOp::In => !l.is_empty() && l.iter().all(|x| r.iter().any(|y| x.1 == y.1)),
                        _ => match (first_rank(la, l), first_rank(ra, r)) {
                            (Some(x), Some(y)) => match c {
                                CmpOp::Ge => x >= y,
                                CmpOp::Le => x <= y,
                                CmpOp::Gt => x > y,
                                _ => x < y,
                            },
                            _ => false,
                        },
                    };
                    sp -= 1;
                    st[sp - 1] = Item::Bool(res);
                }
            }
        }
        sp == 1 && truth(&st[0])
    }

    /// The decision for subject `user` on a resource labelled `res` at `env`.
    pub fn decide(&self, user: &AttrSet, res: &AttrSet, env: &AttrSet) -> Decision {
        let named = res.values(self.ids.policy);
        let mut d = Decision::OPEN;
        for (ri, rule) in self.rules.iter().enumerate() {
            let p = &self.policies[rule.policy];
            if !p.global && !named.iter().any(|&(_, v)| v == p.name_id) {
                continue;
            }
            d.covered = true;
            if !self.eval(&rule.target, user, res, env) {
                continue;
            }
            let mut mask = 0u8;
            for (m, cond) in &rule.allows {
                if mask & m != *m && self.eval(cond, user, res, env) {
                    mask |= m;
                }
            }
            let tag = (ri + 1) as u16;
            let staged = rule.staged || p.staged;
            if !staged {
                for b in 0..4 {
                    if d.enforced & (1 << b) != 0 && mask & (1 << b) == 0 {
                        d.refused_by[b] = tag;
                    }
                }
                d.enforced &= mask;
            }
            if staged || !rule.replaced {
                for b in 0..4 {
                    if d.proposed & (1 << b) != 0 && mask & (1 << b) == 0 {
                        d.would_refuse_by[b] = tag;
                    }
                }
                d.proposed &= mask;
            }
        }
        d
    }

    /// The app-control decision for running `path` (`hash` and `trusted` are computed on
    /// demand: they cost a file read and a directory lookup).
    pub fn app_decide(
        &self,
        user: &AttrSet,
        env: &AttrSet,
        path: &str,
        hash: &mut dyn FnMut() -> Option<[u8; 32]>,
        trusted: &mut dyn FnMut() -> bool,
    ) -> AppDecision {
        let empty = AttrSet::default();
        let name = path.rsplit('/').next().unwrap_or(path);
        let mut hash_v: Option<Option<[u8; 32]>> = None;
        let mut trusted_v: Option<bool> = None;
        let mut matches = |w: &AppMatch| -> bool {
            match w {
                AppMatch::Path(p) => p == path,
                AppMatch::Prefix(p) => path.starts_with(p.as_str()),
                AppMatch::Name(n) => n == name,
                AppMatch::Hash(h) => hash_v.get_or_insert_with(&mut *hash).as_ref() == Some(h),
                AppMatch::Trusted => *trusted_v.get_or_insert_with(&mut *trusted),
            }
        };
        // Per evaluation (enforced, proposed): allow-list on, allowed by a rule, denied by
        let mut out = [(false, 0u16, 0u16); 2];
        for (i, r) in self.apps.iter().enumerate() {
            if !self.eval(&r.cond, user, &empty, env) {
                continue;
            }
            let tag = (i + 1) as u16;
            let views: &[usize] = if r.staged { &[1] } else { &[0, 1] };
            let mut m: Option<bool> = None;
            for &v in views {
                let o = &mut out[v];
                if r.deny {
                    if o.2 == 0 && *m.get_or_insert_with(|| matches(&r.what)) {
                        o.2 = tag;
                    }
                } else {
                    o.0 = true;
                    if o.1 == 0 && *m.get_or_insert_with(|| matches(&r.what)) {
                        o.1 = tag;
                    }
                }
            }
        }
        let verdict = |(list, allowed_by, denied_by): (bool, u16, u16)| -> (bool, u16) {
            if denied_by != 0 {
                (false, denied_by)
            } else if list && allowed_by == 0 {
                (false, 0)
            } else {
                (true, allowed_by)
            }
        };
        let (allowed, rule) = verdict(out[0]);
        let (would_allow, would_rule) = verdict(out[1]);
        AppDecision { allowed, would_allow, rule, would_rule }
    }

    /// Whether any app rule exists.
    pub fn has_apps(&self) -> bool {
        !self.apps.is_empty()
    }

    /// The environment attributes at `unix_secs` (UTC): `hour`, `minute`, `time` (HHMM),
    /// `weekday` (1 Monday .. 7 Sunday), plus the static ones.
    pub fn env_at(&self, unix_secs: i64) -> AttrSet {
        let mut e = self.env;
        let local = unix_secs + self.tz as i64;
        let day_secs = local.rem_euclid(86400);
        let days = local.div_euclid(86400);
        let (h, m) = ((day_secs / 3600) as u32, ((day_secs % 3600) / 60) as u32);
        // 1970-01-01 was a Thursday (4)
        let wd = ((days + 3).rem_euclid(7) + 1) as u32;
        e.push(self.ids.hour, INT | h);
        e.push(self.ids.minute, INT | m);
        e.push(self.ids.time, INT | (h * 100 + m));
        e.push(self.ids.weekday, INT | wd);
        e
    }
}

/// Parses postfix condition tokens. Returns the condition and whether it reads the time.
fn parse_cond(it: &mut Interner, toks: &[&str], ids: &Ids) -> Result<(Cond, bool), &'static str> {
    let mut ops = Vec::new();
    let mut depth: i32 = 0;
    let mut time = false;
    for t in toks {
        let op = match *t {
            "==" => Op::Cmp(CmpOp::Eq),
            "!=" => Op::Cmp(CmpOp::Ne),
            ">=" => Op::Cmp(CmpOp::Ge),
            "<=" => Op::Cmp(CmpOp::Le),
            ">" => Op::Cmp(CmpOp::Gt),
            "<" => Op::Cmp(CmpOp::Lt),
            "in" => Op::Cmp(CmpOp::In),
            "any" => Op::Cmp(CmpOp::Any),
            "and" => Op::And,
            "or" => Op::Or,
            "not" => Op::Not,
            "exists" => Op::Exists,
            "true" => Op::Bool(true),
            "false" => Op::Bool(false),
            t => {
                if let Some(l) = t.strip_prefix('\'') {
                    Op::Lit(value_id(it, &unescape(l), true).ok_or("intern table full")?)
                } else if let Some(n) = t.strip_prefix('#') {
                    Op::Lit(INT | n.parse::<u32>().map_err(|_| "bad number")? & !INT)
                } else {
                    let (side, name) = if let Some(n) = t.strip_prefix("user.") {
                        (Side::User, n)
                    } else if let Some(n) = t.strip_prefix("res.") {
                        (Side::Res, n)
                    } else if let Some(n) = t.strip_prefix("env.") {
                        (Side::Env, n)
                    } else {
                        return Err("unknown token");
                    };
                    let a = it.intern(&unescape(name)).ok_or("intern table full")?;
                    if side == Side::Env && [ids.hour, ids.minute, ids.time, ids.weekday].contains(&a) {
                        time = true;
                    }
                    Op::Attr(side, a)
                }
            }
        };
        depth += match op {
            Op::Attr(..) | Op::Lit(_) | Op::Bool(_) => 1,
            Op::Not | Op::Exists => 0,
            _ => -1,
        };
        if depth < 1 || depth > STACK as i32 {
            return Err("unbalanced condition");
        }
        ops.push(op);
    }
    if !ops.is_empty() && depth != 1 {
        return Err("unbalanced condition");
    }
    Ok((Cond { ops }, time))
}

/// SHA-256 (FIPS 180-4), for app-control hash rules.
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    n: usize,
    len: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buf: [0; 64],
            n: 0,
            len: 0,
        }
    }
    fn block(&mut self, b: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = self.h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            self.h[i] = self.h[i].wrapping_add(v[i]);
        }
    }
    pub fn update(&mut self, mut d: &[u8]) {
        self.len += d.len() as u64;
        while !d.is_empty() {
            let k = (64 - self.n).min(d.len());
            self.buf[self.n..self.n + k].copy_from_slice(&d[..k]);
            self.n += k;
            d = &d[k..];
            if self.n == 64 {
                let b = self.buf;
                self.block(&b);
                self.n = 0;
            }
        }
    }
    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len * 8;
        self.update(&[0x80]);
        while self.n != 56 {
            self.update(&[0]);
        }
        let mut b = self.buf;
        b[56..].copy_from_slice(&bits.to_be_bytes());
        self.block(&b);
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}
