//! # The name, attribute and link caches
//!
//! What vfs-server remembers of zfs-server's answers, so that a walk over warm paths asks it
//! nothing (`docs/vfs-design.md` section 3.3: the kernel's 8,192-name cache, emptied when
//! full, hit 13 % in `ls -lR`):
//!
//! - **names:** `(directory, name) -> object`, or "no such name" (a negative entry);
//! - **attributes:** `object -> Attr`;
//! - **links:** `object -> target` of a symbolic link;
//! - **ACLs:** `object -> its access ACL or none` (asked only for directories the mode bits
//!   cannot decide for).
//!
//! **Size:** each map holds about `cap` entries; when it grows past `cap + cap/8`, the
//! entries not used in the last `7/8 cap` uses of that map go (an approximate LRU without a
//! list), so the cache never empties all at once.
//!
//! **Coherence:** every change forgets what it touches ([`Cache::forget_name`],
//! [`Cache::forget_dir`], [`Cache::forget_attr`], ...), and bumps a generation. A fill is
//! made with the generation read *before* its zfs-server request ([`Cache::begin`]): if a
//! change came in between, the answer may be stale and is not kept. Forgetting a whole
//! directory's names is O(1): name entries carry their directory's generation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::ctx::Node;
use crate::fs::fsproto::Attr;
use crate::lock::YLock;

/// The default size of each map.
pub const DEFAULT_CAP: usize = 65536;

/// A name's hash (FNV-1a): the name map's key is `(directory, hash)`, the name itself is
/// kept in the entry and compared (two names with one hash share the slot: the later wins).
pub fn name_hash(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct NameEnt {
    name: Vec<u8>,
    target: Option<Node>,
    dirgen: u64,
    used: u64,
}

/// One map with its use clock.
struct Map<K: Ord, V> {
    m: BTreeMap<K, (V, u64)>,
    clock: u64,
}

impl<K: Ord, V> Map<K, V> {
    const fn new() -> Self {
        Self { m: BTreeMap::new(), clock: 0 }
    }

    fn get(&mut self, k: &K) -> Option<&V> {
        // (only hits move the clock: a burst of misses ages nothing)
        let c = self.clock + 1;
        let e = self.m.get_mut(k)?;
        self.clock = c;
        e.1 = c;
        Some(&e.0)
    }

    fn put(&mut self, k: K, v: V, cap: usize) {
        self.clock += 1;
        self.m.insert(k, (v, self.clock));
        if self.m.len() > cap.saturating_add(cap / 8) {
            let keep = (cap - cap / 8) as u64;
            let now = self.clock;
            self.m.retain(|_, e| now.saturating_sub(e.1) <= keep);
        }
    }
}

struct Inner {
    names: BTreeMap<(Node, u64), NameEnt>,
    name_clock: u64,
    dirgen: BTreeMap<Node, u64>,
    attrs: Map<Node, Attr>,
    links: Map<Node, Vec<u8>>,
    acls: Map<Node, Option<Vec<u8>>>,
}

/// Hits and misses since the start (or [`Cache::reset_stats`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Name lookups answered / not answered.
    pub name_hits: u64,
    /// See [`Stats::name_hits`].
    pub name_misses: u64,
    /// Attribute lookups answered / not answered.
    pub attr_hits: u64,
    /// See [`Stats::attr_hits`].
    pub attr_misses: u64,
    /// Link lookups answered / not answered.
    pub link_hits: u64,
    /// See [`Stats::link_hits`].
    pub link_misses: u64,
    /// Fills dropped because a change came during their request.
    pub stale_fills: u64,
    /// Times everything was forgotten.
    pub flushes: u64,
}

/// The caches.
pub struct Cache {
    inner: YLock<Inner>,
    gen: AtomicU64,
    cap: AtomicUsize,
    stats: [AtomicU64; 8],
}

const NAME_HIT: usize = 0;
const NAME_MISS: usize = 1;
const ATTR_HIT: usize = 2;
const ATTR_MISS: usize = 3;
const LINK_HIT: usize = 4;
const LINK_MISS: usize = 5;
const STALE: usize = 6;
const FLUSH: usize = 7;

/// A generation read before a zfs-server request (see [`Cache::begin`]).
#[derive(Clone, Copy, Debug)]
pub struct Ticket(u64);

impl Cache {
    /// Empty caches of about `cap` entries each.
    pub const fn new(cap: usize) -> Self {
        let cap = if cap < 16 { 16 } else { cap };
        Self {
            inner: YLock::new(Inner { names: BTreeMap::new(), name_clock: 0, dirgen: BTreeMap::new(), attrs: Map::new(), links: Map::new(), acls: Map::new() }),
            gen: AtomicU64::new(1),
            cap: AtomicUsize::new(cap),
            stats: [const { AtomicU64::new(0) }; 8],
        }
    }

    /// Sets the size of each map (`cache=N`); at least 16.
    pub fn set_cap(&self, cap: usize) {
        self.cap.store(cap.max(16), Ordering::Release);
    }

    /// The size of each map.
    pub fn cap(&self) -> usize {
        self.cap.load(Ordering::Acquire)
    }

    fn count(&self, i: usize) {
        self.stats[i].fetch_add(1, Ordering::Relaxed);
    }

    /// The counters.
    pub fn stats(&self) -> Stats {
        let s = |i: usize| self.stats[i].load(Ordering::Relaxed);
        Stats {
            name_hits: s(NAME_HIT),
            name_misses: s(NAME_MISS),
            attr_hits: s(ATTR_HIT),
            attr_misses: s(ATTR_MISS),
            link_hits: s(LINK_HIT),
            link_misses: s(LINK_MISS),
            stale_fills: s(STALE),
            flushes: s(FLUSH),
        }
    }

    /// Clears the counters.
    pub fn reset_stats(&self) {
        for s in &self.stats {
            s.store(0, Ordering::Relaxed);
        }
    }

    /// Entries held: `(names, attributes, links)`.
    pub fn len(&self) -> (usize, usize, usize) {
        let g = self.inner.lock();
        (g.names.len(), g.attrs.m.len(), g.links.m.len())
    }

    /// The generation to fill with after the zfs-server request about to be made.
    pub fn begin(&self) -> Ticket {
        Ticket(self.gen.load(Ordering::Acquire))
    }

    fn fresh(&self, t: Ticket) -> bool {
        let ok = self.gen.load(Ordering::Acquire) == t.0;
        if !ok {
            self.count(STALE);
        }
        ok
    }

    fn changed(&self) {
        self.gen.fetch_add(1, Ordering::AcqRel);
    }

    // ------------------------------------------------------------------
    // Lookups and fills
    // ------------------------------------------------------------------

    /// What `name` in `dir` is: `Some(Some(object))`, `Some(None)` (known not to exist), or
    /// `None` (not known).
    pub fn name(&self, dir: Node, name: &[u8]) -> Option<Option<Node>> {
        let mut g = self.inner.lock();
        let dg = g.dirgen.get(&dir).copied().unwrap_or(0);
        let c = g.name_clock + 1;
        let r = match g.names.get_mut(&(dir, name_hash(name))) {
            Some(e) if e.name == name && e.dirgen == dg => {
                e.used = c;
                Some(e.target)
            }
            _ => None,
        };
        if r.is_some() {
            g.name_clock = c;
        }
        drop(g);
        self.count(if r.is_some() { NAME_HIT } else { NAME_MISS });
        r
    }

    /// Remembers that `name` in `dir` is `target` (`None`: does not exist).
    pub fn put_name(&self, t: Ticket, dir: Node, name: &[u8], target: Option<Node>) {
        let cap = self.cap();
        let mut g = self.inner.lock();
        if !self.fresh(t) {
            return;
        }
        let dirgen = g.dirgen.get(&dir).copied().unwrap_or(0);
        g.name_clock += 1;
        let used = g.name_clock;
        g.names.insert((dir, name_hash(name)), NameEnt { name: name.to_vec(), target, dirgen, used });
        if g.names.len() > cap.saturating_add(cap / 8) {
            let keep = (cap - cap / 8) as u64;
            g.names.retain(|_, e| used.saturating_sub(e.used) <= keep);
        }
    }

    /// The attributes of `n`, if known.
    pub fn attr(&self, n: Node) -> Option<Attr> {
        let r = self.inner.lock().attrs.get(&n).copied();
        self.count(if r.is_some() { ATTR_HIT } else { ATTR_MISS });
        r
    }

    /// Remembers the attributes of `n`.
    pub fn put_attr(&self, t: Ticket, n: Node, a: Attr) {
        let cap = self.cap();
        let mut g = self.inner.lock();
        if self.fresh(t) {
            g.attrs.put(n, a, cap);
        }
    }

    /// The target of symbolic link `n`, if known.
    pub fn link(&self, n: Node) -> Option<Vec<u8>> {
        let r = self.inner.lock().links.get(&n).cloned();
        self.count(if r.is_some() { LINK_HIT } else { LINK_MISS });
        r
    }

    /// Remembers the target of symbolic link `n`.
    pub fn put_link(&self, t: Ticket, n: Node, target: &[u8]) {
        let cap = self.cap();
        let mut g = self.inner.lock();
        if self.fresh(t) {
            g.links.put(n, target.to_vec(), cap);
        }
    }

    /// The access ACL of `n`: `Some(None)` known to have none, `None` not known.
    pub fn acl(&self, n: Node) -> Option<Option<Vec<u8>>> {
        self.inner.lock().acls.get(&n).cloned()
    }

    /// Remembers the access ACL of `n`.
    pub fn put_acl(&self, t: Ticket, n: Node, acl: Option<&[u8]>) {
        let cap = self.cap() / 16;
        let mut g = self.inner.lock();
        if self.fresh(t) {
            g.acls.put(n, acl.map(|a| a.to_vec()), cap.max(16));
        }
    }

    // ------------------------------------------------------------------
    // Invalidation
    // ------------------------------------------------------------------

    /// Forgets what `name` in `dir` is.
    pub fn forget_name(&self, dir: Node, name: &[u8]) {
        let mut g = self.inner.lock();
        self.changed();
        g.names.remove(&(dir, name_hash(name)));
    }

    /// Forgets every name in `dir`.
    pub fn forget_dir(&self, dir: Node) {
        let cap = self.cap();
        let mut g = self.inner.lock();
        self.changed();
        Self::bump_dir(&mut g, dir, cap);
    }

    /// Moves `dir`'s generation on (its names become stale). The generations are kept only
    /// while there are fewer than `cap` of them: beyond that every name goes at once.
    fn bump_dir(g: &mut Inner, dir: Node, cap: usize) {
        if g.dirgen.len() >= cap && !g.dirgen.contains_key(&dir) {
            g.names.clear();
            g.dirgen.clear();
            return;
        }
        *g.dirgen.entry(dir).or_insert(0) += 1;
    }

    /// Forgets the attributes (and the ACL) of `n`.
    pub fn forget_attr(&self, n: Node) {
        let mut g = self.inner.lock();
        self.changed();
        g.attrs.m.remove(&n);
        g.acls.m.remove(&n);
    }

    /// Forgets the link target of `n`.
    pub fn forget_link(&self, n: Node) {
        let mut g = self.inner.lock();
        self.changed();
        g.links.m.remove(&n);
    }

    /// Forgets everything about object `ino` in every mount (a change the kernel made: it
    /// names objects by number only): attributes, ACL, link target, and the names in it.
    pub fn forget_object(&self, ino: u64) {
        let mut g = self.inner.lock();
        let g = &mut *g;
        self.changed();
        let nodes: Vec<Node> = g.attrs.m.keys().chain(g.links.m.keys()).filter(|n| n.ino == ino).copied().collect();
        for n in nodes {
            g.attrs.m.remove(&n);
            g.links.m.remove(&n);
            g.acls.m.remove(&n);
        }
        g.acls.m.retain(|n, _| n.ino != ino);
        // Names that lead to it (it may be gone or replaced)
        g.names.retain(|_, e| !e.target.is_some_and(|t| t.ino == ino));
        // Names in it (in whichever mount): their directory generation moves on
        let dirs: alloc::collections::BTreeSet<Node> = g.names.keys().filter(|k| k.0.ino == ino).map(|k| k.0).collect();
        let cap = self.cap();
        for d in dirs {
            Self::bump_dir(g, d, cap);
        }
    }

    /// Forgets every name (negative entries too), keeping attributes and links.
    pub fn forget_names(&self) {
        let mut g = self.inner.lock();
        self.changed();
        g.names.clear();
        g.dirgen.clear();
    }

    /// Forgets everything.
    pub fn forget_all(&self) {
        let mut g = self.inner.lock();
        self.changed();
        g.names.clear();
        g.dirgen.clear();
        g.attrs.m.clear();
        g.links.m.clear();
        g.acls.m.clear();
        drop(g);
        self.count(FLUSH);
    }
}

/// vfs-server's caches.
pub static CACHE: Cache = Cache::new(DEFAULT_CAP);

/// [`Cache::forget_name`] on [`CACHE`].
pub fn forget_name(dir: Node, name: &[u8]) {
    CACHE.forget_name(dir, name)
}

/// [`Cache::forget_dir`] on [`CACHE`].
pub fn forget_dir(dir: Node) {
    CACHE.forget_dir(dir)
}

/// [`Cache::forget_attr`] on [`CACHE`].
pub fn forget_attr(n: Node) {
    CACHE.forget_attr(n)
}

/// [`Cache::forget_link`] on [`CACHE`].
pub fn forget_link(n: Node) {
    CACHE.forget_link(n)
}

/// [`Cache::forget_all`] on [`CACHE`].
pub fn forget_all() {
    CACHE.forget_all()
}
