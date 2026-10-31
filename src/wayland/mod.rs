//! # Hydra Wayland Compositor
//!
//! An in-kernel Wayland display server for unmodified Linux clients (Qt 6, GTK, SDL):
//! a kernel task that listens on `$XDG_RUNTIME_DIR/wayland-0` inside a Linux root,
//! speaks the Wayland wire protocol over the `AF_UNIX` layer, and composites client
//! buffers onto the framebuffer.
//!
//! Supported: `wl_compositor` / `wl_surface` / `wl_region` / `wl_callback`, `wl_shm`
//! pools and buffers over memfds, `wl_subcompositor`, `xdg_wm_base` with toplevels
//! (title, interactive move) and popups (positioner placement), `wl_output`, `wl_seat`
//! with `wl_pointer` (PS/2 mouse) and `wl_keyboard` (PS/2 keyboard as evdev key codes,
//! an XKB keymap the client resolves from its own `xkb-data`, modifiers, repeat
//! information), and an empty `wl_data_device_manager` (no clipboard yet).
//!
//! Display ownership works like virtual terminals: the compositor takes the screen when
//! a window maps; Ctrl+Alt+F1 returns to the text console (which kept drawing into a
//! shadow buffer) and Ctrl+Alt+F2 back to the compositor. While the compositor shows,
//! the keyboard is delivered raw to it.
//!
//! Clients draw client-side decorations (no `xdg-decoration`); the compositor draws only
//! the background and the pointer. Buffers are copied on commit and released at once.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::compat::linux::memfd::MemFd;
use crate::compat::linux::unix::UnixSocket;
use crate::fs::FileDescriptor;
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

/// Woken by keyboard input destined for the compositor and display-switch requests.
pub static INPUT_WQ: WaitQueue = WaitQueue::new();
/// The compositor owns the keyboard (raw scancodes go to it, not to the console).
pub static RAW_KEYBOARD: AtomicBool = AtomicBool::new(false);
/// Ctrl+Alt+F2 pressed on the console: give the screen back to the compositor.
pub static SWITCH_TO_COMPOSITOR: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Raw keyboard scancodes for the compositor (filled by the keyboard interrupt).
static SCANCODES: Mutex<VecDeque<u8>> = Mutex::new(VecDeque::new());

/// Called from the keyboard interrupt in raw mode. Never allocates beyond the queue's
/// capacity (reserved when the compositor starts).
pub fn push_scancode(code: u8) {
    if let Some(mut q) = SCANCODES.try_lock() {
        if q.len() < q.capacity() {
            q.push_back(code);
        }
    }
    INPUT_WQ.wake_all();
}

/// Server parameters chosen by `wayland start`.
struct Config {
    root_ino: u64,
    path: String,
    uid: u32,
    gid: u32,
}

static CONFIG: Mutex<Option<Config>> = Mutex::new(None);

/// Starts the compositor for the Linux root `root_ino` (socket at `path` inside it).
pub fn start(root_ino: u64, path: &str, uid: u32, gid: u32) -> Result<(), &'static str> {
    if RUNNING.swap(true, Ordering::AcqRel) {
        return Err("the compositor is already running");
    }
    SCANCODES.lock().reserve(512);
    *CONFIG.lock() = Some(Config { root_ino, path: String::from(path), uid, gid });
    crate::task::spawn("waylandd", compositor_main, crate::task::TaskPriority::High);
    Ok(())
}

/// Returns true if the Wayland compositor service daemon is currently running.
pub fn is_running() -> bool {
    RUNNING.load(Ordering::Acquire)
}

// ----------------------------------------------------------------------
// Wire format
// ----------------------------------------------------------------------

/// Reads request arguments.
struct Args<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Args<'a> {
    fn u32(&mut self) -> u32 {
        if self.off + 4 > self.b.len() {
            self.off = self.b.len();
            return 0;
        }
        let v = u32::from_le_bytes(self.b[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        v
    }

    fn i32(&mut self) -> i32 {
        self.u32() as i32
    }

    fn string(&mut self) -> String {
        let len = self.u32() as usize;
        let start = self.off;
        let padded = (len + 3) & !3;
        self.off = (self.off + padded).min(self.b.len());
        if len == 0 || start + len > self.b.len() {
            return String::new();
        }
        String::from_utf8_lossy(&self.b[start..start + len - 1]).into_owned()
    }
}

/// An event argument.
enum A<'a> {
    U(u32),
    I(i32),
    /// 24.8 fixed point from a whole number of pixels.
    F(i32),
    S(&'a str),
    Arr(&'a [u8]),
    O(u32),
    Fd(FileDescriptor),
}

// ----------------------------------------------------------------------
// Objects
// ----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    None,
    Toplevel,
    Popup,
    Sub,
}

struct Surface {
    pending_buffer: Option<Option<u32>>,
    pending_frames: Vec<u32>,
    frames: Vec<u32>,
    pixels: Vec<u32>,
    w: usize,
    h: usize,
    /// ARGB (blended) rather than XRGB (opaque).
    alpha: bool,
    role: Role,
    xdg: Option<u32>,
    /// Subsurfaces drawn above this surface, in order.
    children: Vec<u32>,
    sub_pos: (i32, i32),
    sub_pending_pos: Option<(i32, i32)>,
    sub_parent: Option<u32>,
    /// A buffer has been committed (the surface has content).
    mapped: bool,
}

impl Surface {
    fn new() -> Self {
        Self {
            pending_buffer: None,
            pending_frames: Vec::new(),
            frames: Vec::new(),
            pixels: Vec::new(),
            w: 0,
            h: 0,
            alpha: false,
            role: Role::None,
            xdg: None,
            children: Vec::new(),
            sub_pos: (0, 0),
            sub_pending_pos: None,
            sub_parent: None,
            mapped: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Positioner {
    size: (i32, i32),
    anchor_rect: (i32, i32, i32, i32),
    anchor: u32,
    gravity: u32,
    offset: (i32, i32),
}

enum Obj {
    Display,
    Registry,
    Callback,
    Compositor,
    Surface(Surface),
    Region,
    Shm,
    Pool { mem: Arc<Mutex<MemFd>> },
    Buffer { mem: Arc<Mutex<MemFd>>, offset: usize, w: usize, h: usize, stride: usize, format: u32 },
    Output,
    Seat,
    Pointer,
    Keyboard,
    WmBase,
    Positioner(Positioner),
    XdgSurface { surface: u32, geometry: Option<(i32, i32, i32, i32)> },
    Toplevel { xdg: u32 },
    Popup { xdg: u32 },
    Subcompositor,
    Subsurface { surface: u32 },
    DataDeviceManager,
    Other,
}

/// The interface of an object (dispatch key).
#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    Display,
    Registry,
    Callback,
    Compositor,
    Surface,
    Region,
    Shm,
    Pool,
    Buffer,
    Output,
    Seat,
    Pointer,
    Keyboard,
    WmBase,
    Positioner,
    XdgSurface,
    Toplevel,
    Popup,
    Subcompositor,
    Subsurface,
    DataDeviceManager,
    Other,
}

fn kind(o: &Obj) -> K {
    match o {
        Obj::Display => K::Display,
        Obj::Registry => K::Registry,
        Obj::Callback => K::Callback,
        Obj::Compositor => K::Compositor,
        Obj::Surface(_) => K::Surface,
        Obj::Region => K::Region,
        Obj::Shm => K::Shm,
        Obj::Pool { .. } => K::Pool,
        Obj::Buffer { .. } => K::Buffer,
        Obj::Output => K::Output,
        Obj::Seat => K::Seat,
        Obj::Pointer => K::Pointer,
        Obj::Keyboard => K::Keyboard,
        Obj::WmBase => K::WmBase,
        Obj::Positioner(_) => K::Positioner,
        Obj::XdgSurface { .. } => K::XdgSurface,
        Obj::Toplevel { .. } => K::Toplevel,
        Obj::Popup { .. } => K::Popup,
        Obj::Subcompositor => K::Subcompositor,
        Obj::Subsurface { .. } => K::Subsurface,
        Obj::DataDeviceManager => K::DataDeviceManager,
        Obj::Other => K::Other,
    }
}

struct Client {
    id: u64,
    sock: Arc<UnixSocket>,
    inbuf: Vec<u8>,
    infds: VecDeque<FileDescriptor>,
    out: Vec<u8>,
    outfds: Vec<FileDescriptor>,
    objects: BTreeMap<u32, (Obj, u32)>,
    dead: bool,
}

impl Client {
    fn event(&mut self, obj: u32, opcode: u16, args: &[A]) {
        let start = self.out.len();
        self.out.extend_from_slice(&obj.to_le_bytes());
        self.out.extend_from_slice(&0u32.to_le_bytes());
        for a in args {
            match a {
                A::U(v) | A::O(v) => self.out.extend_from_slice(&v.to_le_bytes()),
                A::I(v) => self.out.extend_from_slice(&v.to_le_bytes()),
                A::F(v) => self.out.extend_from_slice(&(v.wrapping_mul(256)).to_le_bytes()),
                A::S(s) => {
                    let len = s.len() + 1;
                    self.out.extend_from_slice(&(len as u32).to_le_bytes());
                    self.out.extend_from_slice(s.as_bytes());
                    self.out.push(0);
                    while self.out.len() % 4 != 0 {
                        self.out.push(0);
                    }
                }
                A::Arr(b) => {
                    self.out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    self.out.extend_from_slice(b);
                    while self.out.len() % 4 != 0 {
                        self.out.push(0);
                    }
                }
                A::Fd(fd) => self.outfds.push(fd.clone()),
            }
        }
        let size = (self.out.len() - start) as u32;
        let word = (size << 16) | opcode as u32;
        self.out[start + 4..start + 8].copy_from_slice(&word.to_le_bytes());
    }

    fn version(&self, obj: u32) -> u32 {
        self.objects.get(&obj).map_or(1, |o| o.1)
    }

    /// Destroys a client object (`wl_display.delete_id` lets the client reuse the id).
    fn destroy(&mut self, obj: u32) {
        if self.objects.remove(&obj).is_some() {
            self.event(1, 1, &[A::U(obj)]);
        }
    }

    fn objects_of(&self, pred: impl Fn(&Obj) -> bool) -> Vec<u32> {
        self.objects.iter().filter(|(_, (o, _))| pred(o)).map(|(id, _)| *id).collect()
    }

    fn surface(&mut self, id: u32) -> Option<&mut Surface> {
        match self.objects.get_mut(&id) {
            Some((Obj::Surface(s), _)) => Some(s),
            _ => None,
        }
    }
}

/// A mapped toplevel or popup on screen.
struct Window {
    client: u64,
    surface: u32,
    /// Screen position of the window geometry's origin.
    x: i32,
    y: i32,
    popup: bool,
}

#[derive(Default, Clone, Copy)]
struct Mods {
    shift: bool,
    ctrl: bool,
    alt: bool,
    logo: bool,
    caps: bool,
}

impl Mods {
    /// (depressed, locked) XKB modifier masks: Shift, Lock, Control, Mod1 (Alt), Mod4.
    fn masks(&self) -> (u32, u32) {
        let mut d = 0;
        if self.shift {
            d |= 1;
        }
        if self.ctrl {
            d |= 4;
        }
        if self.alt {
            d |= 8;
        }
        if self.logo {
            d |= 64;
        }
        (d, if self.caps { 2 } else { 0 })
    }
}

const GLOBALS: &[(u32, &str, u32)] = &[
    (1, "wl_compositor", 5),
    (2, "wl_shm", 1),
    (3, "wl_output", 4),
    (4, "wl_seat", 7),
    (5, "xdg_wm_base", 3),
    (6, "wl_subcompositor", 1),
    (7, "wl_data_device_manager", 3),
];

const KEYMAP: &str = "xkb_keymap {\n\
    xkb_keycodes  { include \"evdev+aliases(qwerty)\" };\n\
    xkb_types     { include \"complete\" };\n\
    xkb_compat    { include \"complete\" };\n\
    xkb_symbols   { include \"pc+us+inet(evdev)\" };\n\
    xkb_geometry  { include \"pc(pc105)\" };\n\
};\n";

const BACKGROUND: u32 = 0xFF1D_2733;

struct Screen {
    fb: *mut u8,
    w: usize,
    h: usize,
    stride: usize,
    bgr: bool,
}

struct Compositor {
    listener: Arc<UnixSocket>,
    clients: Vec<Client>,
    windows: Vec<Window>,
    next_client: u64,
    serial: u32,
    screen: Screen,
    back: Vec<u32>,
    owns_display: bool,
    dirty: bool,
    ptr: (i32, i32),
    buttons: (bool, bool, bool),
    ptr_focus: Option<(u64, u32)>,
    kbd_focus: Option<(u64, u32)>,
    mods: Mods,
    /// Interactive move: (window surface owner, surface, grab offset).
    moving: Option<(u64, u32, i32, i32)>,
    keymap: Arc<Mutex<MemFd>>,
    keymap_size: u32,
    e0: bool,
    cascade: i32,
}

/// Protocol tracing follows `linux trace on`.
fn tracing() -> bool {
    crate::compat::linux::TRACE_SYSCALLS.load(Ordering::Relaxed)
}

fn now_ms() -> u32 {
    (crate::arch::pit::ticks() * 10) as u32
}

fn compositor_main() {
    let cfg = CONFIG.lock().take().expect("compositor configuration");
    let listener = match crate::compat::linux::unix::kernel_listen(cfg.root_ino, &cfg.path, cfg.uid, cfg.gid) {
        Ok(l) => l,
        Err(e) => {
            crate::kprintln!("[wayland] cannot listen on {}: errno {}", cfg.path, e);
            RUNNING.store(false, Ordering::Release);
            crate::task::exit();
        }
    };
    let (w, h, stride, bgr) = match crate::video::get_video_info() {
        Some(i) => (i.width, i.height, i.stride, i.is_bgr),
        None => (1024, 768, 1024, true),
    };
    let keymap = MemFd::new("hydra-xkb-keymap");
    keymap.lock().write_at(0, KEYMAP.as_bytes());
    keymap.lock().write_at(KEYMAP.len(), &[0]);
    let mut comp = Compositor {
        listener,
        clients: Vec::new(),
        windows: Vec::new(),
        next_client: 1,
        serial: 1,
        screen: Screen { fb: core::ptr::null_mut(), w, h, stride, bgr },
        back: alloc::vec![BACKGROUND; w * h],
        owns_display: false,
        dirty: true,
        ptr: ((w / 2) as i32, (h / 2) as i32),
        buttons: (false, false, false),
        ptr_focus: None,
        kbd_focus: None,
        mods: Mods::default(),
        moving: None,
        keymap,
        keymap_size: KEYMAP.len() as u32 + 1,
        e0: false,
        cascade: 0,
    };
    crate::arch::mouse::set_position(comp.ptr.0 as usize, comp.ptr.1 as usize);
    crate::kprintln!("[wayland] compositor listening on {} ({}x{})", cfg.path, w, h);
    loop {
        let mut waits = WaitSet::new();
        comp.listener.add_wait_queues(&mut waits);
        waits.add(QueueRef::Static(&INPUT_WQ));
        for c in &comp.clients {
            c.sock.add_wait_queues(&mut waits);
        }
        waits.register();
        if comp.step() {
            // New clients are not in this wait set yet: register them before sleeping
            continue;
        }
        // Poll the mouse every tick while windows exist
        let deadline = if comp.windows.is_empty() { None } else { Some(crate::arch::pit::ticks() + 1) };
        waits.wait(deadline);
    }
}

impl Compositor {
    /// One pass over connections, requests, input and output. Returns true if it accepted
    /// new clients.
    fn step(&mut self) -> bool {
        let mut accepted = false;
        while let Some(sock) = self.listener.kernel_accept() {
            accepted = true;
            if tracing() {
                crate::kprintln!("[wayland] client {} connected", self.next_client);
            }
            let id = self.next_client;
            self.next_client += 1;
            let mut objects = BTreeMap::new();
            objects.insert(1, (Obj::Display, 1));
            self.clients.push(Client {
                id,
                sock,
                inbuf: Vec::new(),
                infds: VecDeque::new(),
                out: Vec::new(),
                outfds: Vec::new(),
                objects,
                dead: false,
            });
        }
        for ci in 0..self.clients.len() {
            self.read_client(ci);
        }
        self.handle_display_switch();
        self.handle_keyboard();
        self.handle_pointer();
        if self.dirty && self.owns_display {
            self.render();
        }
        self.dirty = false;
        self.send_frame_done();
        for c in self.clients.iter_mut() {
            flush(c);
        }
        self.reap();
        accepted
    }

    fn reap(&mut self) {
        let dead: Vec<u64> = self.clients.iter().filter(|c| c.dead).map(|c| c.id).collect();
        if dead.is_empty() {
            return;
        }
        self.windows.retain(|w| !dead.contains(&w.client));
        self.clients.retain(|c| !c.dead);
        if self.ptr_focus.map_or(false, |f| dead.contains(&f.0)) {
            self.ptr_focus = None;
        }
        if self.kbd_focus.map_or(false, |f| dead.contains(&f.0)) {
            self.kbd_focus = None;
            self.focus_top();
        }
        self.dirty = true;
    }

    fn client_index(&self, id: u64) -> Option<usize> {
        self.clients.iter().position(|c| c.id == id)
    }

    fn next_serial(&mut self) -> u32 {
        self.serial = self.serial.wrapping_add(1);
        self.serial
    }

    // ------------------------------------------------------------------
    // Requests
    // ------------------------------------------------------------------

    fn read_client(&mut self, ci: usize) {
        let mut buf = alloc::vec![0u8; 65536];
        loop {
            match self.clients[ci].sock.kernel_recv(&mut buf) {
                Ok(Some((0, _))) | Err(_) => {
                    self.clients[ci].dead = true;
                    return;
                }
                Ok(Some((n, fds))) => {
                    let c = &mut self.clients[ci];
                    c.inbuf.extend_from_slice(&buf[..n]);
                    c.infds.extend(fds);
                }
                Ok(None) => break,
            }
        }
        loop {
            let c = &self.clients[ci];
            if c.inbuf.len() < 8 {
                break;
            }
            let obj = u32::from_le_bytes(c.inbuf[0..4].try_into().unwrap());
            let word = u32::from_le_bytes(c.inbuf[4..8].try_into().unwrap());
            let size = (word >> 16) as usize;
            let opcode = (word & 0xFFFF) as u16;
            if size < 8 {
                self.clients[ci].dead = true;
                return;
            }
            if c.inbuf.len() < size {
                break;
            }
            let msg: Vec<u8> = self.clients[ci].inbuf.drain(..size).collect();
            self.request(ci, obj, opcode, &msg[8..]);
            if self.clients[ci].dead {
                return;
            }
        }
    }

    fn request(&mut self, ci: usize, obj: u32, op: u16, payload: &[u8]) {
        if tracing() {
            crate::kprintln!("[wayland] client {} -> object {} op {} ({} bytes)", self.clients[ci].id, obj, op, payload.len());
        }
        let mut a = Args { b: payload, off: 0 };
        let k = match self.clients[ci].objects.get(&obj) {
            Some((o, _)) => kind(o),
            None => return, // requests to destroyed objects are ignored
        };
        let is = |x: K| x == k;
        let c = &mut self.clients[ci];
        if is(K::Display) {
            match op {
                0 => {
                    // sync(callback): reply at once
                    let cb = a.u32();
                    c.event(cb, 0, &[A::U(now_ms())]);
                    c.event(1, 1, &[A::U(cb)]);
                }
                1 => {
                    let reg = a.u32();
                    c.objects.insert(reg, (Obj::Registry, 1));
                    for (name, iface, ver) in GLOBALS {
                        c.event(reg, 0, &[A::U(*name), A::S(iface), A::U(*ver)]);
                    }
                }
                _ => {}
            }
        } else if is(K::Registry) {
            if op == 0 {
                let name = a.u32();
                let _iface = a.string();
                let version = a.u32();
                let id = a.u32();
                self.bind(ci, name, version, id);
            }
        } else if is(K::Compositor) {
            match op {
                0 => {
                    let id = a.u32();
                    c.objects.insert(id, (Obj::Surface(Surface::new()), 5));
                }
                1 => {
                    let id = a.u32();
                    c.objects.insert(id, (Obj::Region, 1));
                }
                _ => {}
            }
        } else if is(K::Region) {
            if op == 0 {
                c.destroy(obj);
            }
        } else if is(K::Callback) {
        } else if is(K::Surface) {
            self.surface_request(ci, obj, op, &mut a);
        } else if is(K::Shm) {
            if op == 0 {
                let id = a.u32();
                let fd = c.infds.pop_front();
                let _size = a.i32();
                match fd {
                    Some(FileDescriptor::MemFd(m)) => {
                        c.objects.insert(id, (Obj::Pool { mem: m }, 1));
                    }
                    _ => {
                        crate::kprintln!("[wayland] wl_shm pool is not a memfd; ignored");
                        c.objects.insert(id, (Obj::Other, 1));
                    }
                }
            }
        } else if let Some((Obj::Pool { mem }, _)) = c.objects.get(&obj) {
            let mem = mem.clone();
            match op {
                0 => {
                    let id = a.u32();
                    let offset = a.i32().max(0) as usize;
                    let w = a.i32().max(0) as usize;
                    let h = a.i32().max(0) as usize;
                    let stride = a.i32().max(0) as usize;
                    let format = a.u32();
                    c.objects.insert(id, (Obj::Buffer { mem, offset, w, h, stride, format }, 1));
                }
                1 => c.destroy(obj),
                _ => {} // resize: the memfd grows by itself
            }
        } else if is(K::Buffer) {
            if op == 0 {
                c.destroy(obj);
            }
        } else if is(K::Seat) {
            match op {
                0 => {
                    let id = a.u32();
                    let v = c.version(obj);
                    c.objects.insert(id, (Obj::Pointer, v));
                }
                1 => {
                    let id = a.u32();
                    let v = c.version(obj);
                    c.objects.insert(id, (Obj::Keyboard, v));
                    let fd = FileDescriptor::MemFd(self.keymap.clone());
                    let size = self.keymap_size;
                    let c = &mut self.clients[ci];
                    c.event(id, 0, &[A::U(1), A::Fd(fd), A::U(size)]);
                    if v >= 4 {
                        c.event(id, 5, &[A::I(25), A::I(600)]);
                    }
                    // A keyboard bound while its client has focus gets the focus at once
                    if let Some((fc, fs)) = self.kbd_focus {
                        if fc == self.clients[ci].id {
                            let serial = self.next_serial();
                            let (d, l) = self.mods.masks();
                            let c = &mut self.clients[ci];
                            c.event(id, 1, &[A::U(serial), A::O(fs), A::Arr(&[])]);
                            c.event(id, 4, &[A::U(serial), A::U(d), A::U(0), A::U(l), A::U(0)]);
                        }
                    }
                }
                2 => {
                    let id = a.u32();
                    c.objects.insert(id, (Obj::Other, 1)); // touch: never sends events
                }
                3 => c.destroy(obj),
                _ => {}
            }
        } else if is(K::Pointer) || is(K::Keyboard) {
            // set_cursor (pointer 0) is ignored: the compositor draws its own pointer
            if (is(K::Pointer) && op == 1) || (is(K::Keyboard) && op == 0) {
                c.destroy(obj);
            }
        } else if is(K::Output) {
            if op == 0 {
                c.destroy(obj);
            }
        } else if is(K::WmBase) {
            match op {
                0 => c.destroy(obj),
                1 => {
                    let id = a.u32();
                    c.objects.insert(id, (Obj::Positioner(Positioner::default()), 1));
                }
                2 => {
                    let id = a.u32();
                    let surface = a.u32();
                    c.objects.insert(id, (Obj::XdgSurface { surface, geometry: None }, c.version(obj)));
                    if let Some(s) = c.surface(surface) {
                        s.xdg = Some(id);
                    }
                }
                _ => {} // pong
            }
        } else if let Some((Obj::Positioner(p), _)) = c.objects.get_mut(&obj) {
            match op {
                0 => c.destroy(obj),
                1 => p.size = (a.i32(), a.i32()),
                2 => p.anchor_rect = (a.i32(), a.i32(), a.i32(), a.i32()),
                3 => p.anchor = a.u32(),
                4 => p.gravity = a.u32(),
                6 => p.offset = (a.i32(), a.i32()),
                _ => {}
            }
        } else if let Some((Obj::XdgSurface { surface, .. }, _)) = c.objects.get(&obj) {
            let surface = *surface;
            match op {
                0 => c.destroy(obj),
                1 => {
                    let id = a.u32();
                    let v = c.version(obj);
                    c.objects.insert(id, (Obj::Toplevel { xdg: obj }, v));
                    if let Some(s) = c.surface(surface) {
                        s.role = Role::Toplevel;
                    }
                }
                2 => {
                    let id = a.u32();
                    let parent_xdg = a.u32();
                    let pos_id = a.u32();
                    self.create_popup(ci, obj, surface, id, parent_xdg, pos_id);
                }
                3 => {
                    let g = (a.i32(), a.i32(), a.i32(), a.i32());
                    if let Some((Obj::XdgSurface { geometry, .. }, _)) = self.clients[ci].objects.get_mut(&obj) {
                        *geometry = Some(g);
                    }
                }
                _ => {} // ack_configure
            }
        } else if let Some((Obj::Toplevel { xdg }, _)) = c.objects.get(&obj) {
            let xdg = *xdg;
            match op {
                0 => {
                    let surf = self.xdg_surface_of(ci, xdg);
                    self.unmap(ci, surf);
                    self.clients[ci].destroy(obj);
                }
                5 => {
                    // move(seat, serial): follow the pointer until the button is released
                    if let Some(surf) = self.xdg_surface_of(ci, xdg) {
                        let cid = self.clients[ci].id;
                        if let Some(w) = self.windows.iter().find(|w| w.client == cid && w.surface == surf) {
                            self.moving = Some((cid, surf, self.ptr.0 - w.x, self.ptr.1 - w.y));
                        }
                    }
                }
                _ => {} // title, app id, sizes, states: the window keeps its own size
            }
        } else if let Some((Obj::Popup { xdg }, _)) = c.objects.get(&obj) {
            let xdg = *xdg;
            if op == 0 {
                let surf = self.xdg_surface_of(ci, xdg);
                self.unmap(ci, surf);
                self.clients[ci].destroy(obj);
            }
        } else if is(K::Subcompositor) {
            match op {
                0 => c.destroy(obj),
                1 => {
                    let id = a.u32();
                    let surface = a.u32();
                    let parent = a.u32();
                    c.objects.insert(id, (Obj::Subsurface { surface }, 1));
                    if let Some(s) = c.surface(surface) {
                        s.role = Role::Sub;
                        s.sub_parent = Some(parent);
                    }
                    if let Some(p) = c.surface(parent) {
                        p.children.push(surface);
                    }
                }
                _ => {}
            }
        } else if let Some((Obj::Subsurface { surface }, _)) = c.objects.get(&obj) {
            let surface = *surface;
            match op {
                0 => {
                    let parent = c.surface(surface).and_then(|s| s.sub_parent.take());
                    if let Some(p) = parent.and_then(|p| c.surface(p)) {
                        p.children.retain(|&s| s != surface);
                    }
                    c.destroy(obj);
                    self.dirty = true;
                }
                1 => {
                    let pos = (a.i32(), a.i32());
                    if let Some(s) = c.surface(surface) {
                        s.sub_pending_pos = Some(pos);
                    }
                }
                _ => {} // stacking and sync modes: drawn in creation order, applied at once
            }
        } else if is(K::DataDeviceManager) {
            match op {
                0 | 1 => {
                    let id = a.u32();
                    c.objects.insert(id, (Obj::Other, 1));
                }
                _ => {}
            }
        } else if is(K::Other) {
            // data sources/devices and the like: their destructors are opcode 0 or 1
        }
    }

    fn bind(&mut self, ci: usize, name: u32, version: u32, id: u32) {
        let max = GLOBALS.iter().find(|g| g.0 == name).map_or(1, |g| g.2);
        let v = version.min(max).max(1);
        let (w, h) = (self.screen.w as i32, self.screen.h as i32);
        let c = &mut self.clients[ci];
        let obj = match name {
            1 => Obj::Compositor,
            2 => Obj::Shm,
            3 => Obj::Output,
            4 => Obj::Seat,
            5 => Obj::WmBase,
            6 => Obj::Subcompositor,
            7 => Obj::DataDeviceManager,
            _ => Obj::Other,
        };
        c.objects.insert(id, (obj, v));
        match name {
            2 => {
                c.event(id, 0, &[A::U(0)]); // ARGB8888
                c.event(id, 0, &[A::U(1)]); // XRGB8888
            }
            3 => {
                c.event(id, 0, &[A::I(0), A::I(0), A::I(w * 254 / 960), A::I(h * 254 / 960), A::I(0), A::S("Hydra"), A::S("Framebuffer"), A::I(0)]);
                c.event(id, 1, &[A::U(3), A::I(w), A::I(h), A::I(60_000)]);
                if v >= 2 {
                    c.event(id, 3, &[A::I(1)]);
                }
                if v >= 4 {
                    c.event(id, 4, &[A::S("HYDRA-1")]);
                    c.event(id, 5, &[A::S("Hydra boot framebuffer")]);
                }
                if v >= 2 {
                    c.event(id, 2, &[]);
                }
            }
            4 => {
                c.event(id, 0, &[A::U(3)]); // pointer | keyboard
                if v >= 2 {
                    c.event(id, 1, &[A::S("seat0")]);
                }
            }
            _ => {}
        }
    }

    fn surface_request(&mut self, ci: usize, obj: u32, op: u16, a: &mut Args) {
        let c = &mut self.clients[ci];
        match op {
            0 => {
                // destroy
                self.unmap(ci, Some(obj));
                self.clients[ci].destroy(obj);
            }
            1 => {
                let buffer = a.u32();
                if let Some(s) = c.surface(obj) {
                    s.pending_buffer = Some(if buffer == 0 { None } else { Some(buffer) });
                }
            }
            3 => {
                let cb = a.u32();
                c.objects.insert(cb, (Obj::Callback, 1));
                if let Some(s) = c.surface(obj) {
                    s.pending_frames.push(cb);
                }
            }
            6 => self.commit(ci, obj),
            _ => {} // damage, regions, transform, scale, offset
        }
    }

    fn commit(&mut self, ci: usize, obj: u32) {
        let c = &mut self.clients[ci];
        let (pending, frames, role, xdg, sub_pos) = match c.surface(obj) {
            Some(s) => (s.pending_buffer.take(), core::mem::take(&mut s.pending_frames), s.role, s.xdg, s.sub_pending_pos.take()),
            None => return,
        };
        if let Some(s) = c.surface(obj) {
            s.frames.extend(frames);
            if let Some(p) = sub_pos {
                s.sub_pos = p;
            }
        }
        match pending {
            Some(Some(buf)) => {
                let info = match c.objects.get(&buf) {
                    Some((Obj::Buffer { mem, offset, w, h, stride, format }, _)) => Some((mem.clone(), *offset, *w, *h, *stride, *format)),
                    _ => None,
                };
                if let Some((mem, offset, w, h, stride, format)) = info {
                    let mut pixels = alloc::vec![0u32; w * h];
                    {
                        let mut m = mem.lock();
                        let mut row = alloc::vec![0u8; w * 4];
                        for y in 0..h {
                            m.read_at(offset + y * stride, &mut row);
                            for (x, px) in row.chunks_exact(4).enumerate() {
                                pixels[y * w + x] = u32::from_le_bytes([px[0], px[1], px[2], px[3]]);
                            }
                        }
                    }
                    if let Some(s) = c.surface(obj) {
                        s.pixels = pixels;
                        s.w = w;
                        s.h = h;
                        s.alpha = format == 0;
                        s.mapped = true;
                    }
                    c.event(buf, 0, &[]); // wl_buffer.release: the pixels were copied
                }
            }
            Some(None) => {
                if let Some(s) = c.surface(obj) {
                    s.mapped = false;
                    s.pixels.clear();
                }
                self.unmap(ci, Some(obj));
            }
            None => {}
        }
        self.dirty = true;

        // xdg roles: the first commit gets a configure; the first buffer maps the window
        if let Some(xdg) = xdg {
            let cid = self.clients[ci].id;
            let mapped = self.clients[ci].surface(obj).map_or(false, |s| s.mapped);
            let known = self.windows.iter().any(|w| w.client == cid && w.surface == obj);
            if role == Role::Toplevel && !known {
                if !mapped {
                    self.configure_toplevel(ci, xdg);
                } else {
                    let (x, y) = (60 + self.cascade, 50 + self.cascade);
                    self.cascade = (self.cascade + 32) % 192;
                    self.windows.push(Window { client: cid, surface: obj, x, y, popup: false });
                    self.take_display();
                    self.set_keyboard_focus(Some((cid, obj)));
                }
            }
        }
    }

    fn configure_toplevel(&mut self, ci: usize, xdg: u32) {
        let serial = self.next_serial();
        let c = &mut self.clients[ci];
        let top = c.objects.iter().find(|(_, (o, _))| matches!(o, Obj::Toplevel { xdg: x } if *x == xdg)).map(|(id, (_, v))| (*id, *v));
        if let Some((top, v)) = top {
            // Activated (state 4): the client may choose its size
            c.event(top, 0, &[A::I(0), A::I(0), A::Arr(&4u32.to_le_bytes())]);
            if v >= 5 {
                c.event(top, 3, &[A::Arr(&[])]); // wm_capabilities: none
            }
        }
        c.event(xdg, 0, &[A::U(serial)]);
    }

    fn create_popup(&mut self, ci: usize, xdg: u32, surface: u32, id: u32, parent_xdg: u32, pos_id: u32) {
        let cid = self.clients[ci].id;
        let pos = match self.clients[ci].objects.get(&pos_id) {
            Some((Obj::Positioner(p), _)) => *p,
            _ => Positioner::default(),
        };
        let v = self.clients[ci].version(xdg);
        self.clients[ci].objects.insert(id, (Obj::Popup { xdg }, v));
        if let Some(s) = self.clients[ci].surface(surface) {
            s.role = Role::Popup;
        }
        // Position relative to the parent's window geometry
        let (rx, ry, rw, rh) = pos.anchor_rect;
        let ax = match pos.anchor {
            3 | 5 | 6 => rx,
            4 | 7 | 8 => rx + rw,
            _ => rx + rw / 2,
        };
        let ay = match pos.anchor {
            1 | 5 | 7 => ry,
            2 | 6 | 8 => ry + rh,
            _ => ry + rh / 2,
        };
        let (w, h) = pos.size;
        let px = match pos.gravity {
            3 | 5 | 6 => ax - w,
            4 | 7 | 8 => ax,
            _ => ax - w / 2,
        } + pos.offset.0;
        let py = match pos.gravity {
            1 | 5 | 7 => ay - h,
            2 | 6 | 8 => ay,
            _ => ay - h / 2,
        } + pos.offset.1;
        let parent_surface = self.xdg_surface_of(ci, parent_xdg);
        let (bx, by) = parent_surface
            .and_then(|ps| self.windows.iter().find(|w| w.client == cid && w.surface == ps))
            .map_or((0, 0), |w| (w.x, w.y));
        // Keep the popup on screen
        let sx = (bx + px).clamp(0, (self.screen.w as i32 - w).max(0));
        let sy = (by + py).clamp(0, (self.screen.h as i32 - h).max(0));
        self.windows.push(Window { client: cid, surface, x: sx, y: sy, popup: true });
        let serial = self.next_serial();
        let c = &mut self.clients[ci];
        c.event(id, 0, &[A::I(sx - bx), A::I(sy - by), A::I(w), A::I(h)]);
        c.event(xdg, 0, &[A::U(serial)]);
        self.dirty = true;
    }

    fn xdg_surface_of(&self, ci: usize, xdg: u32) -> Option<u32> {
        match self.clients[ci].objects.get(&xdg) {
            Some((Obj::XdgSurface { surface, .. }, _)) => Some(*surface),
            _ => None,
        }
    }

    fn unmap(&mut self, ci: usize, surface: Option<u32>) {
        let surface = match surface {
            Some(s) => s,
            None => return,
        };
        let cid = self.clients[ci].id;
        let before = self.windows.len();
        self.windows.retain(|w| !(w.client == cid && w.surface == surface));
        if self.windows.len() != before {
            self.dirty = true;
            if self.kbd_focus == Some((cid, surface)) {
                self.kbd_focus = None;
                self.focus_top();
            }
            if self.ptr_focus == Some((cid, surface)) {
                self.ptr_focus = None;
            }
        }
    }

    // ------------------------------------------------------------------
    // Display ownership
    // ------------------------------------------------------------------

    fn take_display(&mut self) {
        if self.owns_display {
            return;
        }
        if let Some((fb, w, h, stride, bgr)) = crate::video::console::release_display() {
            self.screen = Screen { fb, w, h, stride, bgr };
            if self.back.len() != w * h {
                self.back = alloc::vec![BACKGROUND; w * h];
            }
            self.owns_display = true;
            self.dirty = true;
            RAW_KEYBOARD.store(true, Ordering::Release);
        }
    }

    fn give_display(&mut self) {
        if !self.owns_display {
            return;
        }
        RAW_KEYBOARD.store(false, Ordering::Release);
        self.owns_display = false;
        crate::video::console::reclaim_display();
    }

    fn handle_display_switch(&mut self) {
        if SWITCH_TO_COMPOSITOR.swap(false, Ordering::AcqRel) && !self.windows.is_empty() {
            self.take_display();
        }
    }

    // ------------------------------------------------------------------
    // Input
    // ------------------------------------------------------------------

    fn set_keyboard_focus(&mut self, focus: Option<(u64, u32)>) {
        if self.kbd_focus == focus {
            return;
        }
        if let Some((cid, surf)) = self.kbd_focus {
            let serial = self.next_serial();
            if let Some(ci) = self.client_index(cid) {
                let c = &mut self.clients[ci];
                for k in c.objects_of(|o| matches!(o, Obj::Keyboard)) {
                    c.event(k, 2, &[A::U(serial), A::O(surf)]);
                }
            }
        }
        self.kbd_focus = focus;
        if let Some((cid, surf)) = focus {
            let serial = self.next_serial();
            let (d, l) = self.mods.masks();
            if let Some(ci) = self.client_index(cid) {
                let c = &mut self.clients[ci];
                for k in c.objects_of(|o| matches!(o, Obj::Keyboard)) {
                    c.event(k, 1, &[A::U(serial), A::O(surf), A::Arr(&[])]);
                    c.event(k, 4, &[A::U(serial), A::U(d), A::U(0), A::U(l), A::U(0)]);
                }
            }
        }
    }

    /// Focuses the topmost toplevel (after the focused one went away).
    fn focus_top(&mut self) {
        let top = self.windows.iter().rev().find(|w| !w.popup).map(|w| (w.client, w.surface));
        self.set_keyboard_focus(top);
    }

    fn handle_keyboard(&mut self) {
        // The keyboard interrupt also takes this lock: hold it with interrupts off
        let codes: Vec<u8> = x86_64::instructions::interrupts::without_interrupts(|| SCANCODES.lock().drain(..).collect());
        for sc in codes {
            if sc == 0xE0 {
                self.e0 = true;
                continue;
            }
            let release = sc & 0x80 != 0;
            let make = sc & 0x7F;
            let key = if self.e0 { e0_keycode(make) } else { make as u32 };
            self.e0 = false;
            if key == 0 {
                continue;
            }
            let pressed = !release;
            let before = self.mods;
            match key {
                42 | 54 => self.mods.shift = pressed,
                29 | 97 => self.mods.ctrl = pressed,
                56 | 100 => self.mods.alt = pressed,
                125 | 126 => self.mods.logo = pressed,
                58 if pressed => self.mods.caps = !self.mods.caps,
                _ => {}
            }
            // Ctrl+Alt+F1: back to the text console
            if pressed && key == 59 && self.mods.ctrl && self.mods.alt {
                self.give_display();
                continue;
            }
            let (cid, surf) = match self.kbd_focus {
                Some(f) => f,
                None => continue,
            };
            let serial = self.next_serial();
            let time = now_ms();
            let changed = before.masks() != self.mods.masks();
            let (d, l) = self.mods.masks();
            if let Some(ci) = self.client_index(cid) {
                let c = &mut self.clients[ci];
                for k in c.objects_of(|o| matches!(o, Obj::Keyboard)) {
                    c.event(k, 3, &[A::U(serial), A::U(time), A::U(key), A::U(pressed as u32)]);
                    if changed {
                        c.event(k, 4, &[A::U(serial), A::U(d), A::U(0), A::U(l), A::U(0)]);
                    }
                }
                let _ = surf;
            }
        }
    }

    /// The window and surface under screen point (x, y), topmost first; returns
    /// (window index, surface, surface-local x, y).
    fn surface_at(&self, x: i32, y: i32) -> Option<(usize, u64, u32, i32, i32)> {
        for (wi, w) in self.windows.iter().enumerate().rev() {
            let ci = match self.client_index(w.client) {
                Some(ci) => ci,
                None => continue,
            };
            let c = &self.clients[ci];
            let (ox, oy) = self.window_origin(c, w);
            if let Some(hit) = hit_test(c, w.surface, x - ox, y - oy) {
                return Some((wi, w.client, hit.0, hit.1, hit.2));
            }
        }
        None
    }

    /// Screen position of a window's main surface (its geometry origin is at w.x, w.y).
    fn window_origin(&self, c: &Client, w: &Window) -> (i32, i32) {
        let geo = match c.objects.get(&w.surface) {
            Some((Obj::Surface(s), _)) => s.xdg.and_then(|x| match c.objects.get(&x) {
                Some((Obj::XdgSurface { geometry, .. }, _)) => *geometry,
                _ => None,
            }),
            _ => None,
        };
        match geo {
            Some((gx, gy, _, _)) => (w.x - gx, w.y - gy),
            None => (w.x, w.y),
        }
    }

    fn handle_pointer(&mut self) {
        if !self.owns_display {
            return;
        }
        let ev = crate::arch::mouse::poll_mouse(self.screen.w, self.screen.h);
        let st = crate::arch::mouse::current_state();
        let pos = (st.x as i32, st.y as i32);
        let buttons = (st.left_button, st.right_button, st.middle_button);
        if ev.is_none() && pos == self.ptr && buttons == self.buttons {
            return;
        }
        let moved = pos != self.ptr;
        self.ptr = pos;
        self.dirty = true; // the pointer is drawn by the compositor

        if let Some((cid, surf, gx, gy)) = self.moving {
            if let Some(w) = self.windows.iter_mut().find(|w| w.client == cid && w.surface == surf) {
                w.x = pos.0 - gx;
                w.y = pos.1 - gy;
            }
            if !buttons.0 {
                self.moving = None;
            }
        }

        let hit = self.surface_at(pos.0, pos.1);
        let target = hit.map(|h| (h.1, h.2));
        let time = now_ms();
        if target != self.ptr_focus {
            if let Some((cid, surf)) = self.ptr_focus {
                let serial = self.next_serial();
                if let Some(ci) = self.client_index(cid) {
                    let c = &mut self.clients[ci];
                    for p in c.objects_of(|o| matches!(o, Obj::Pointer)) {
                        c.event(p, 1, &[A::U(serial), A::O(surf)]);
                        if c.version(p) >= 5 {
                            c.event(p, 5, &[]);
                        }
                    }
                }
            }
            if let Some((_, cid, surf, lx, ly)) = hit {
                let serial = self.next_serial();
                if let Some(ci) = self.client_index(cid) {
                    let c = &mut self.clients[ci];
                    for p in c.objects_of(|o| matches!(o, Obj::Pointer)) {
                        c.event(p, 0, &[A::U(serial), A::O(surf), A::F(lx), A::F(ly)]);
                        if c.version(p) >= 5 {
                            c.event(p, 5, &[]);
                        }
                    }
                }
            }
            self.ptr_focus = target;
        } else if moved {
            if let Some((_, cid, _, lx, ly)) = hit {
                if let Some(ci) = self.client_index(cid) {
                    let c = &mut self.clients[ci];
                    for p in c.objects_of(|o| matches!(o, Obj::Pointer)) {
                        c.event(p, 2, &[A::U(time), A::F(lx), A::F(ly)]);
                        if c.version(p) >= 5 {
                            c.event(p, 5, &[]);
                        }
                    }
                }
            }
        }

        let changes = [(buttons.0, self.buttons.0, 0x110u32), (buttons.1, self.buttons.1, 0x111), (buttons.2, self.buttons.2, 0x112)];
        self.buttons = buttons;
        for (now, before, code) in changes {
            if now == before {
                continue;
            }
            if now {
                self.on_press(hit.map(|h| h.0));
            }
            if let Some((cid, _)) = self.ptr_focus {
                let serial = self.next_serial();
                if let Some(ci) = self.client_index(cid) {
                    let c = &mut self.clients[ci];
                    for p in c.objects_of(|o| matches!(o, Obj::Pointer)) {
                        c.event(p, 3, &[A::U(serial), A::U(time), A::U(code), A::U(now as u32)]);
                        if c.version(p) >= 5 {
                            c.event(p, 5, &[]);
                        }
                    }
                }
            }
        }
    }

    /// A button press: closes popups clicked outside of, raises and focuses the window.
    fn on_press(&mut self, window: Option<usize>) {
        let on_popup = window.map_or(false, |wi| self.windows[wi].popup);
        if !on_popup {
            // Clicking outside open popups dismisses them (popup_done)
            let popups: Vec<(u64, u32)> = self.windows.iter().filter(|w| w.popup).map(|w| (w.client, w.surface)).collect();
            for (cid, surf) in popups {
                if let Some(ci) = self.client_index(cid) {
                    let c = &mut self.clients[ci];
                    let xdg = c.surface(surf).and_then(|s| s.xdg);
                    let popup = xdg.and_then(|x| c.objects.iter().find(|(_, (o, _))| matches!(o, Obj::Popup { xdg: px } if *px == x)).map(|(id, _)| *id));
                    if let Some(p) = popup {
                        c.event(p, 1, &[]);
                    }
                }
            }
        }
        if let Some(wi) = window {
            if !self.windows[wi].popup {
                let w = self.windows.remove(wi);
                let focus = (w.client, w.surface);
                self.windows.push(w);
                self.set_keyboard_focus(Some(focus));
                self.dirty = true;
            }
        }
    }

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    fn render(&mut self) {
        let (sw, sh) = (self.screen.w, self.screen.h);
        for px in self.back.iter_mut() {
            *px = BACKGROUND;
        }
        for wi in 0..self.windows.len() {
            let w = &self.windows[wi];
            let ci = match self.client_index(w.client) {
                Some(ci) => ci,
                None => continue,
            };
            let (ox, oy) = self.window_origin(&self.clients[ci], w);
            draw_tree(&self.clients[ci], w.surface, ox, oy, &mut self.back, sw, sh);
        }
        draw_pointer(&mut self.back, sw, sh, self.ptr);
        // Present
        let fb = self.screen.fb as *mut u32;
        for y in 0..sh {
            let row = &self.back[y * sw..(y + 1) * sw];
            unsafe {
                if self.screen.bgr {
                    core::ptr::copy_nonoverlapping(row.as_ptr(), fb.add(y * self.screen.stride), sw);
                } else {
                    for (x, px) in row.iter().enumerate() {
                        let (r, g, b) = ((px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF);
                        *fb.add(y * self.screen.stride + x) = r | (g << 8) | (b << 16);
                    }
                }
            }
        }
    }

    fn send_frame_done(&mut self) {
        let time = now_ms();
        for c in self.clients.iter_mut() {
            let mut done = Vec::new();
            for (_, (o, _)) in c.objects.iter_mut() {
                if let Obj::Surface(s) = o {
                    done.append(&mut s.frames);
                }
            }
            for cb in done {
                c.event(cb, 0, &[A::U(time)]);
                c.destroy(cb);
            }
        }
    }
}

/// Finds the surface (main or subsurface) of `surface`'s tree under local point (x, y).
fn hit_test(c: &Client, surface: u32, x: i32, y: i32) -> Option<(u32, i32, i32)> {
    let s = match c.objects.get(&surface) {
        Some((Obj::Surface(s), _)) => s,
        _ => return None,
    };
    for &child in s.children.iter().rev() {
        if let Some((Obj::Surface(cs), _)) = c.objects.get(&child) {
            if let Some(hit) = hit_test(c, child, x - cs.sub_pos.0, y - cs.sub_pos.1) {
                return Some(hit);
            }
        }
    }
    if s.mapped && x >= 0 && y >= 0 && (x as usize) < s.w && (y as usize) < s.h {
        Some((surface, x, y))
    } else {
        None
    }
}

/// Draws a surface and its subsurfaces with its top-left at screen (x, y).
fn draw_tree(c: &Client, surface: u32, x: i32, y: i32, back: &mut [u32], sw: usize, sh: usize) {
    let s = match c.objects.get(&surface) {
        Some((Obj::Surface(s), _)) => s,
        _ => return,
    };
    if s.mapped {
        blit(&s.pixels, s.w, s.h, s.alpha, x, y, back, sw, sh);
    }
    for &child in &s.children {
        if let Some((Obj::Surface(cs), _)) = c.objects.get(&child) {
            draw_tree(c, child, x + cs.sub_pos.0, y + cs.sub_pos.1, back, sw, sh);
        }
    }
}

/// Copies (or, for ARGB, blends: Wayland pixels are premultiplied) `src` onto `back`.
fn blit(src: &[u32], w: usize, h: usize, alpha: bool, x: i32, y: i32, back: &mut [u32], sw: usize, sh: usize) {
    let x0 = x.max(0) as usize;
    let y0 = y.max(0) as usize;
    let x1 = ((x + w as i32).min(sw as i32)).max(0) as usize;
    let y1 = ((y + h as i32).min(sh as i32)).max(0) as usize;
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    for dy in y0..y1 {
        let sy = (dy as i32 - y) as usize;
        let srow = &src[sy * w..(sy + 1) * w];
        let drow = &mut back[dy * sw..(dy + 1) * sw];
        for dx in x0..x1 {
            let p = srow[(dx as i32 - x) as usize];
            if !alpha {
                drow[dx] = p | 0xFF00_0000;
                continue;
            }
            let a = p >> 24;
            if a == 0xFF {
                drow[dx] = p;
            } else if a != 0 {
                let d = drow[dx];
                let inv = 255 - a;
                let ch = |sh: u32| -> u32 {
                    let s = (p >> sh) & 0xFF;
                    let dd = (d >> sh) & 0xFF;
                    (s + dd * inv / 255).min(255) << sh
                };
                drow[dx] = 0xFF00_0000 | ch(16) | ch(8) | ch(0);
            }
        }
    }
}

/// An arrow pointer (1 = outline, 2 = fill).
const POINTER: [&[u8]; 16] = [
    b"1", b"11", b"121", b"1221", b"12221", b"122221", b"1222221", b"12222221", b"122222221", b"1222222221",
    b"12222211111", b"1221221", b"121 1221", b"11  1221", b"1    1221", b"      11",
];

fn draw_pointer(back: &mut [u32], sw: usize, sh: usize, (px, py): (i32, i32)) {
    for (dy, row) in POINTER.iter().enumerate() {
        for (dx, &c) in row.iter().enumerate() {
            let (x, y) = (px + dx as i32, py + dy as i32);
            if x < 0 || y < 0 || x as usize >= sw || y as usize >= sh {
                continue;
            }
            let color = match c {
                b'1' => 0xFF00_0000,
                b'2' => 0xFFFF_FFFF,
                _ => continue,
            };
            back[y as usize * sw + x as usize] = color;
        }
    }
}

/// Sends queued events (and their descriptors).
fn flush(c: &mut Client) {
    if c.out.is_empty() || c.dead {
        return;
    }
    let fds = core::mem::take(&mut c.outfds);
    let n = c.sock.kernel_send(&c.out, fds);
    if tracing() {
        crate::kprintln!("[wayland] client {} <- {} bytes: sent {}", c.id, c.out.len(), n);
    }
    if n > 0 {
        c.out.drain(..n as usize);
    } else if n != -11 {
        c.dead = true; // EPIPE and the like: the client went away
    }
}

/// Linux key code for a set-1 scancode after an `0xE0` prefix (0 = ignored).
fn e0_keycode(make: u8) -> u32 {
    match make {
        0x1C => 96,  // KP Enter
        0x1D => 97,  // Right Ctrl
        0x35 => 98,  // KP /
        0x38 => 100, // Right Alt
        0x47 => 102, // Home
        0x48 => 103, // Up
        0x49 => 104, // Page Up
        0x4B => 105, // Left
        0x4D => 106, // Right
        0x4F => 107, // End
        0x50 => 108, // Down
        0x51 => 109, // Page Down
        0x52 => 110, // Insert
        0x53 => 111, // Delete
        0x5B => 125, // Left Meta
        0x5C => 126, // Right Meta
        0x5D => 127, // Menu
        _ => 0,
    }
}
