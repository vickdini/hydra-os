//! # Linux ABI Wayland Compositor Bridge
//!
//! Implements an in-kernel Wayland display server bridge listening on `/run/user/1000/wayland-0`.
//! Translates client Wayland protocol wire messages (wl_display, wl_registry, wl_compositor,
//! wl_shm, wl_shm_pool, wl_buffer, wl_surface, xdg_wm_base, xdg_surface, xdg_toplevel),
//! receives shared memory pixel buffers passed via `SCM_RIGHTS` ancillary file descriptors,
//! and composites/blits them directly into the UEFI GOP linear framebuffer and desktop compositor.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

use crate::compat::linux::memfd::MemFd;
use crate::compat::linux::socket::{ensure_wayland_socket, UnixSocket, UnixSocketRole};
use crate::video::with_framebuffer;

// Wayland Core Protocol Object IDs & Opcodes
pub const WL_DISPLAY_ID: u32 = 1;

pub const WL_DISPLAY_SYNC: u16 = 0;
pub const WL_DISPLAY_GET_REGISTRY: u16 = 1;

pub const WL_REGISTRY_BIND: u16 = 0;

pub const WL_COMPOSITOR_CREATE_SURFACE: u16 = 0;
pub const WL_COMPOSITOR_CREATE_REGION: u16 = 1;

pub const WL_SHM_CREATE_POOL: u16 = 0;

pub const WL_SHM_POOL_CREATE_BUFFER: u16 = 0;
pub const WL_SHM_POOL_DESTROY: u16 = 1;
pub const WL_SHM_POOL_RESIZE: u16 = 2;

pub const XDG_WM_BASE_DESTROY: u16 = 0;
pub const XDG_WM_BASE_CREATE_POSITIONER: u16 = 1;
pub const XDG_WM_BASE_GET_XDG_SURFACE: u16 = 2;
pub const XDG_WM_BASE_PONG: u16 = 3;

pub const XDG_SURFACE_DESTROY: u16 = 0;
pub const XDG_SURFACE_GET_TOPLEVEL: u16 = 1;
pub const XDG_SURFACE_GET_POPUP: u16 = 2;
pub const XDG_SURFACE_SET_WINDOW_GEOMETRY: u16 = 3;
pub const XDG_SURFACE_ACK_CONFIGURE: u16 = 4;

pub const XDG_TOPLEVEL_DESTROY: u16 = 0;
pub const XDG_TOPLEVEL_SET_PARENT: u16 = 1;
pub const XDG_TOPLEVEL_SET_TITLE: u16 = 2;
pub const XDG_TOPLEVEL_SET_APP_ID: u16 = 3;

pub const WL_SURFACE_DESTROY: u16 = 0;
pub const WL_SURFACE_ATTACH: u16 = 1;
pub const WL_SURFACE_DAMAGE: u16 = 2;
pub const WL_SURFACE_FRAME: u16 = 3;
pub const WL_SURFACE_SET_OPAQUE_REGION: u16 = 4;
pub const WL_SURFACE_SET_INPUT_REGION: u16 = 5;
pub const WL_SURFACE_COMMIT: u16 = 6;

// wl_seat Opcodes & Capabilities
pub const WL_SEAT_GET_POINTER: u16 = 0;
pub const WL_SEAT_GET_KEYBOARD: u16 = 1;
pub const WL_SEAT_GET_TOUCH: u16 = 2;
pub const WL_SEAT_RELEASE: u16 = 3;

pub const WL_SEAT_CAPABILITY_POINTER: u32 = 1;
pub const WL_SEAT_CAPABILITY_KEYBOARD: u32 = 2;
pub const WL_SEAT_CAPABILITY_TOUCH: u32 = 4;

// wl_pointer Opcodes & Events
pub const WL_POINTER_SET_CURSOR: u16 = 0;
pub const WL_POINTER_RELEASE: u16 = 1;

pub const WL_POINTER_EVENT_ENTER: u16 = 0;
pub const WL_POINTER_EVENT_LEAVE: u16 = 1;
pub const WL_POINTER_EVENT_MOTION: u16 = 2;
pub const WL_POINTER_EVENT_BUTTON: u16 = 3;
pub const WL_POINTER_EVENT_AXIS: u16 = 4;
pub const WL_POINTER_EVENT_FRAME: u16 = 5;

pub const BTN_LEFT: u32 = 0x110;
pub const BTN_RIGHT: u32 = 0x111;
pub const BTN_MIDDLE: u32 = 0x112;

// wl_keyboard Opcodes & Events
pub const WL_KEYBOARD_RELEASE: u16 = 0;

pub const WL_KEYBOARD_EVENT_KEYMAP: u16 = 0;
pub const WL_KEYBOARD_EVENT_ENTER: u16 = 1;
pub const WL_KEYBOARD_EVENT_LEAVE: u16 = 2;
pub const WL_KEYBOARD_EVENT_KEY: u16 = 3;
pub const WL_KEYBOARD_EVENT_MODIFIERS: u16 = 4;
pub const WL_KEYBOARD_EVENT_REPEAT_INFO: u16 = 5;

// Supported Pixel Formats
pub const WL_SHM_FORMAT_ARGB8888: u32 = 0;
pub const WL_SHM_FORMAT_XRGB8888: u32 = 1;

/// Represents a shared memory pool created by a Wayland client via `wl_shm.create_pool`.
pub struct WaylandShmPool {
    pub id: u32,
    pub memfd: Arc<Mutex<MemFd>>,
    pub size: usize,
}

/// Represents an individual pixel buffer created by `wl_shm_pool.create_buffer`.
#[derive(Debug, Clone, Copy)]
pub struct WaylandBuffer {
    pub id: u32,
    pub pool_id: u32,
    pub offset: usize,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub format: u32,
}

/// Internal state of a client application surface.
pub struct WaylandSurfaceState {
    pub id: u32,
    pub attached_buffer_id: Option<u32>,
    pub title: String,
    pub app_id: String,
    pub frame_callbacks: Vec<u32>,
    pub configured: bool,
    pub commit_count: u64,
}

impl WaylandSurfaceState {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            attached_buffer_id: None,
            title: String::from("KDE Plasma App — Wayland Client"),
            app_id: String::new(),
            frame_callbacks: Vec::new(),
            configured: false,
            commit_count: 0,
        }
    }
}

/// Active connection session with an individual Wayland client process.
pub struct WaylandClientSession {
    pub socket: Arc<Mutex<UnixSocket>>,
    pub in_buffer: Vec<u8>,
    pub registry_id: Option<u32>,
    pub compositor_id: Option<u32>,
    pub shm_id: Option<u32>,
    pub wm_base_id: Option<u32>,
    pub pools: BTreeMap<u32, WaylandShmPool>,
    pub buffers: BTreeMap<u32, WaylandBuffer>,
    pub surfaces: BTreeMap<u32, WaylandSurfaceState>,
    pub xdg_surfaces: BTreeMap<u32, u32>, // xdg_surface_id -> surface_id
    pub toplevels: BTreeMap<u32, u32>,    // toplevel_id -> xdg_surface_id
    pub seat_id: Option<u32>,
    pub pointer_id: Option<u32>,
    pub keyboard_id: Option<u32>,
    pub pointer_inside: bool,
    pub last_mouse_x: usize,
    pub last_mouse_y: usize,
    pub last_mouse_pressed: bool,
}

impl WaylandClientSession {
    pub fn new(socket: Arc<Mutex<UnixSocket>>) -> Self {
        Self {
            socket,
            in_buffer: Vec::new(),
            registry_id: None,
            compositor_id: None,
            shm_id: None,
            wm_base_id: None,
            pools: BTreeMap::new(),
            buffers: BTreeMap::new(),
            surfaces: BTreeMap::new(),
            xdg_surfaces: BTreeMap::new(),
            toplevels: BTreeMap::new(),
            seat_id: None,
            pointer_id: None,
            keyboard_id: None,
            pointer_inside: false,
            last_mouse_x: 0,
            last_mouse_y: 0,
            last_mouse_pressed: false,
        }
    }
}

/// Global In-Kernel Wayland Compositor Bridge.
pub struct WaylandBridge {
    pub sessions: Vec<WaylandClientSession>,
    pub next_serial: u32,
}

impl WaylandBridge {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_serial: 1,
        }
    }
}

pub static WAYLAND_BRIDGE: Mutex<Option<WaylandBridge>> = Mutex::new(None);
pub static SIMULATED_CLICKS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

/// Injects a simulated mouse click event for interactive testing and automation.
pub fn inject_simulated_click(x: usize, y: usize) {
    SIMULATED_CLICKS.lock().push((x, y));
}

/// Ensures that the in-kernel Wayland display server bridge and socket are active.
pub fn ensure_wayland_bridge() {
    let _ = ensure_wayland_socket();
    let mut bridge = WAYLAND_BRIDGE.lock();
    if bridge.is_none() {
        *bridge = Some(WaylandBridge::new());
    }
}

/// Dispatches all pending Wayland client requests, extracts shared memory buffers,
/// performs display blitting on commit, and writes responses to the socket.
pub fn dispatch_wayland_events() {
    ensure_wayland_bridge();

    let server_sock = ensure_wayland_socket();
    let mut bridge_guard = WAYLAND_BRIDGE.lock();
    let bridge = match bridge_guard.as_mut() {
        Some(b) => b,
        None => return,
    };

    // 1. Accept any newly pending client connections
    loop {
        match server_sock.lock().accept(true) {
            Ok(client) => {
                bridge.sessions.push(WaylandClientSession::new(client));
            }
            Err(_) => break,
        }
    }

    // 2. Process each active client session
    let mut i = 0;
    while i < bridge.sessions.len() {
        {
            let session = &mut bridge.sessions[i];
            let is_closed = matches!(&session.socket.lock().role, UnixSocketRole::Closed);
            if is_closed {
                bridge.sessions.remove(i);
                continue;
            }

            let rx_pipe = match &session.socket.lock().role {
                UnixSocketRole::Connected { rx, .. } => rx.clone(),
                _ => {
                    i += 1;
                    continue;
                }
            };

            let mut out_events = Vec::new();

            let avail = rx_pipe.lock().available_read();
            if avail > 0 {
                let mut chunk = vec![0u8; avail];
                let n = rx_pipe.lock().read(&mut chunk);
                session.in_buffer.extend_from_slice(&chunk[..n]);
            }

            // Parse complete Wayland messages from staging buffer
            while session.in_buffer.len() >= 8 {
                let obj_id = u32::from_ne_bytes(session.in_buffer[0..4].try_into().unwrap());
                let op_len = u32::from_ne_bytes(session.in_buffer[4..8].try_into().unwrap());
                let opcode = (op_len & 0xFFFF) as u16;
                let msg_len = ((op_len >> 16) & 0xFFFF) as usize;

                if msg_len < 8 {
                    // Invalid packet header: drop 4 bytes to recover alignment
                    session.in_buffer.drain(0..4);
                    continue;
                }

                if session.in_buffer.len() < msg_len {
                    // Incomplete packet: await more bytes
                    break;
                }

                let payload = session.in_buffer[8..msg_len].to_vec();
                session.in_buffer.drain(0..msg_len);

                handle_client_message(
                    session,
                    obj_id,
                    opcode,
                    &payload,
                    &mut out_events,
                    &mut bridge.next_serial,
                );
            }

            // 2b. Dispatch Interactive Pointer / Mouse Events if wl_pointer is bound
            if let Some(ptr_id) = session.pointer_id {
                let surf_opt = session.surfaces.iter().find_map(|(&s_id, s)| {
                    let b_id = s.attached_buffer_id?;
                    let buf = session.buffers.get(&b_id)?;
                    Some((s_id, *buf))
                });

                if let Some((surf_id, buf)) = surf_opt {
                    let screen_dims = with_framebuffer(|fb| (fb.width(), fb.height()));
                    let (screen_w, screen_h) = screen_dims.unwrap_or((1280, 800));
                    let win_w = buf.width;
                    let win_h = buf.height;
                    let (win_x, win_y) = if win_w >= screen_w && win_h >= screen_h {
                        (0, 0)
                    } else {
                        (
                            (screen_w.saturating_sub(win_w)) / 2,
                            (screen_h.saturating_sub(win_h + 28)) / 2 + 28,
                        )
                    };

                    // Check for simulated test click or real hardware PS/2 mouse
                    let (mx, my, left_btn) = if let Some((sx, sy)) = SIMULATED_CLICKS.lock().pop() {
                        (sx, sy, true)
                    } else {
                        let m = crate::arch::mouse::current_state();
                        (m.x, m.y, m.left_button)
                    };

                    let is_inside = mx >= win_x && mx < win_x + win_w && my >= win_y && my < win_y + win_h;
                    let timestamp = (crate::arch::pit::ticks() * 10) as u32;

                    if is_inside {
                        let rel_x = (mx - win_x) as i32;
                        let rel_y = (my - win_y) as i32;
                        let fixed_x = rel_x << 8;
                        let fixed_y = rel_y << 8;

                        if !session.pointer_inside {
                            bridge.next_serial = bridge.next_serial.wrapping_add(1);
                            write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_ENTER, 16);
                            write_u32(&mut out_events, bridge.next_serial);
                            write_u32(&mut out_events, surf_id);
                            write_i32(&mut out_events, fixed_x);
                            write_i32(&mut out_events, fixed_y);
                            write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_FRAME, 0);
                            session.pointer_inside = true;
                        }

                        if mx != session.last_mouse_x || my != session.last_mouse_y {
                            write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_MOTION, 12);
                            write_u32(&mut out_events, timestamp);
                            write_i32(&mut out_events, fixed_x);
                            write_i32(&mut out_events, fixed_y);
                            write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_FRAME, 0);
                            session.last_mouse_x = mx;
                            session.last_mouse_y = my;
                        }

                        if left_btn != session.last_mouse_pressed {
                            bridge.next_serial = bridge.next_serial.wrapping_add(1);
                            write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_BUTTON, 16);
                            write_u32(&mut out_events, bridge.next_serial);
                            write_u32(&mut out_events, timestamp);
                            write_u32(&mut out_events, BTN_LEFT);
                            write_u32(&mut out_events, if left_btn { 1 } else { 0 });
                            write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_FRAME, 0);
                            session.last_mouse_pressed = left_btn;
                        }
                    } else if session.pointer_inside {
                        bridge.next_serial = bridge.next_serial.wrapping_add(1);
                        write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_LEAVE, 8);
                        write_u32(&mut out_events, bridge.next_serial);
                        write_u32(&mut out_events, surf_id);
                        write_msg_header(&mut out_events, ptr_id, WL_POINTER_EVENT_FRAME, 0);
                        session.pointer_inside = false;
                    }
                }
            }

            // 2c. Dispatch Interactive Keyboard Events if wl_keyboard is bound
            if let Some(kbd_id) = session.keyboard_id {
                if session.pointer_inside {
                    if let Some(key) = crate::console::read_key() {
                        let scancode = match key {
                            uefi::proto::console::text::Key::Printable(ch) => {
                                let c = (u16::from(ch) as u8).to_ascii_lowercase();
                                match c {
                                    b'a'..=b'z' => (30 + (c - b'a')) as u32,
                                    b'1'..=b'9' => (2 + (c - b'1')) as u32,
                                    b'0' => 11,
                                    b' ' => 57,
                                    b'\r' | b'\n' => 28,
                                    _ => 30,
                                }
                            }
                            _ => 28,
                        };
                        let timestamp = (crate::arch::pit::ticks() * 10) as u32;
                        // Key Press
                        bridge.next_serial = bridge.next_serial.wrapping_add(1);
                        write_msg_header(&mut out_events, kbd_id, WL_KEYBOARD_EVENT_KEY, 16);
                        write_u32(&mut out_events, bridge.next_serial);
                        write_u32(&mut out_events, timestamp);
                        write_u32(&mut out_events, scancode);
                        write_u32(&mut out_events, 1);
                        // Key Release
                        bridge.next_serial = bridge.next_serial.wrapping_add(1);
                        write_msg_header(&mut out_events, kbd_id, WL_KEYBOARD_EVENT_KEY, 16);
                        write_u32(&mut out_events, bridge.next_serial);
                        write_u32(&mut out_events, timestamp + 5);
                        write_u32(&mut out_events, scancode);
                        write_u32(&mut out_events, 0);
                    }
                }
            }

            // Write generated Wayland event replies to client's receive pipe
            if !out_events.is_empty() {
                let tx_pipe = match &session.socket.lock().role {
                    UnixSocketRole::Connected { tx, .. } => tx.clone(),
                    _ => continue,
                };
                let mut tx = tx_pipe.lock();
                let mut written = 0;
                while written < out_events.len() {
                    match tx.write(&out_events[written..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => written += n,
                    }
                }
            }
        }

        i += 1;
    }
}

// -----------------------------------------------------------------------------
// Message Serialization & Parsing Helpers
// -----------------------------------------------------------------------------

fn write_msg_header(buf: &mut Vec<u8>, object_id: u32, opcode: u16, payload_len: usize) {
    let total_len = (8 + payload_len) as u32;
    let op_len = ((total_len as u32) << 16) | (opcode as u32);
    buf.extend_from_slice(&object_id.to_ne_bytes());
    buf.extend_from_slice(&op_len.to_ne_bytes());
}

fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_ne_bytes());
}

fn write_i32(buf: &mut Vec<u8>, val: i32) {
    buf.extend_from_slice(&val.to_ne_bytes());
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len() + 1; // null-terminated
    write_u32(buf, len as u32);
    buf.extend_from_slice(bytes);
    buf.push(0);
    let pad = (4 - (len % 4)) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

fn read_u32(payload: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 4 <= payload.len() {
        let val = u32::from_ne_bytes(payload[*offset..*offset + 4].try_into().ok()?);
        *offset += 4;
        Some(val)
    } else {
        None
    }
}

fn read_i32(payload: &[u8], offset: &mut usize) -> Option<i32> {
    if *offset + 4 <= payload.len() {
        let val = i32::from_ne_bytes(payload[*offset..*offset + 4].try_into().ok()?);
        *offset += 4;
        Some(val)
    } else {
        None
    }
}

fn read_string(payload: &[u8], offset: &mut usize) -> Option<String> {
    let len = read_u32(payload, offset)? as usize;
    if *offset + len <= payload.len() {
        let str_bytes = &payload[*offset..*offset + len.saturating_sub(1)];
        let s = core::str::from_utf8(str_bytes).ok().map(String::from)?;
        let padded = (len + 3) & !3;
        *offset += padded;
        Some(s)
    } else {
        None
    }
}

fn send_global(out: &mut Vec<u8>, reg_id: u32, name: u32, iface: &str, ver: u32) {
    let mut payload = Vec::new();
    write_u32(&mut payload, name);
    write_string(&mut payload, iface);
    write_u32(&mut payload, ver);
    write_msg_header(out, reg_id, 0, payload.len());
    out.extend_from_slice(&payload);
}

// -----------------------------------------------------------------------------
// Wayland Protocol Request Dispatcher
// -----------------------------------------------------------------------------

fn handle_client_message(
    session: &mut WaylandClientSession,
    object_id: u32,
    opcode: u16,
    payload: &[u8],
    out_events: &mut Vec<u8>,
    serial_counter: &mut u32,
) {
    let mut offset = 0;

    // 1. `wl_display` (object_id = 1)
    if object_id == WL_DISPLAY_ID {
        match opcode {
            WL_DISPLAY_SYNC => {
                if let Some(callback_id) = read_u32(payload, &mut offset) {
                    *serial_counter = serial_counter.wrapping_add(1);
                    // Event: wl_callback.done(serial)
                    write_msg_header(out_events, callback_id, 0, 4);
                    write_u32(out_events, *serial_counter);
                }
            }
            WL_DISPLAY_GET_REGISTRY => {
                if let Some(registry_id) = read_u32(payload, &mut offset) {
                    session.registry_id = Some(registry_id);
                    // Advertise core desktop globals
                    send_global(out_events, registry_id, 1, "wl_compositor", 4);
                    send_global(out_events, registry_id, 2, "wl_shm", 1);
                    send_global(out_events, registry_id, 3, "xdg_wm_base", 1);
                    send_global(out_events, registry_id, 4, "wl_seat", 5);
                }
            }
            _ => {}
        }
        return;
    }

    // 2. `wl_registry`
    if Some(object_id) == session.registry_id {
        if opcode == WL_REGISTRY_BIND {
            if let Some(_name) = read_u32(payload, &mut offset) {
                if let Some(iface) = read_string(payload, &mut offset) {
                    let _version = read_u32(payload, &mut offset);
                    if let Some(new_id) = read_u32(payload, &mut offset) {
                        match iface.as_str() {
                            "wl_compositor" => session.compositor_id = Some(new_id),
                            "wl_shm" => {
                                session.shm_id = Some(new_id);
                                // Broadcast supported pixel formats
                                write_msg_header(out_events, new_id, 0, 4);
                                write_u32(out_events, WL_SHM_FORMAT_ARGB8888);
                                write_msg_header(out_events, new_id, 0, 4);
                                write_u32(out_events, WL_SHM_FORMAT_XRGB8888);
                            }
                            "xdg_wm_base" => session.wm_base_id = Some(new_id),
                            "wl_seat" => {
                                session.seat_id = Some(new_id);
                                write_msg_header(out_events, new_id, 0, 4);
                                write_u32(out_events, WL_SEAT_CAPABILITY_POINTER | WL_SEAT_CAPABILITY_KEYBOARD);
                                let mut p = Vec::new();
                                write_string(&mut p, "seat0");
                                write_msg_header(out_events, new_id, 1, p.len());
                                out_events.extend_from_slice(&p);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        return;
    }

    // 3. `wl_compositor`
    if Some(object_id) == session.compositor_id {
        match opcode {
            WL_COMPOSITOR_CREATE_SURFACE => {
                if let Some(surface_id) = read_u32(payload, &mut offset) {
                    session
                        .surfaces
                        .insert(surface_id, WaylandSurfaceState::new(surface_id));
                }
            }
            WL_COMPOSITOR_CREATE_REGION => {
                // Regions are optional optimizations
            }
            _ => {}
        }
        return;
    }

    // 4. `wl_shm`
    if Some(object_id) == session.shm_id {
        if opcode == WL_SHM_CREATE_POOL {
            if let Some(pool_id) = read_u32(payload, &mut offset) {
                if let Some(size) = read_i32(payload, &mut offset) {
                    // Extract passed MemFd file descriptor from SCM_RIGHTS queue!
                    if let Some(crate::fs::FileDescriptor::MemFd(mfd)) =
                        session.socket.lock().pop_ancillary_fd()
                    {
                        session.pools.insert(
                            pool_id,
                            WaylandShmPool {
                                id: pool_id,
                                memfd: mfd,
                                size: size as usize,
                            },
                        );
                    }
                }
            }
        }
        return;
    }

    // 5. `wl_shm_pool`
    if session.pools.contains_key(&object_id) {
        match opcode {
            WL_SHM_POOL_CREATE_BUFFER => {
                if let Some(buffer_id) = read_u32(payload, &mut offset) {
                    if let Some(buf_offset) = read_i32(payload, &mut offset) {
                        if let Some(width) = read_i32(payload, &mut offset) {
                            if let Some(height) = read_i32(payload, &mut offset) {
                                if let Some(stride) = read_i32(payload, &mut offset) {
                                    if let Some(format) = read_u32(payload, &mut offset) {
                                        session.buffers.insert(
                                            buffer_id,
                                            WaylandBuffer {
                                                id: buffer_id,
                                                pool_id: object_id,
                                                offset: buf_offset as usize,
                                                width: width as usize,
                                                height: height as usize,
                                                stride: stride as usize,
                                                format,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            WL_SHM_POOL_DESTROY => {
                session.pools.remove(&object_id);
            }
            WL_SHM_POOL_RESIZE => {
                if let Some(new_size) = read_i32(payload, &mut offset) {
                    if let Some(pool) = session.pools.get_mut(&object_id) {
                        pool.size = new_size as usize;
                    }
                }
            }
            _ => {}
        }
        return;
    }

    // 6. `xdg_wm_base`
    if Some(object_id) == session.wm_base_id {
        match opcode {
            XDG_WM_BASE_GET_XDG_SURFACE => {
                if let Some(xdg_surface_id) = read_u32(payload, &mut offset) {
                    if let Some(surface_id) = read_u32(payload, &mut offset) {
                        session.xdg_surfaces.insert(xdg_surface_id, surface_id);
                        // Emit initial xdg_surface.configure(serial)
                        *serial_counter = serial_counter.wrapping_add(1);
                        write_msg_header(out_events, xdg_surface_id, 0, 4);
                        write_u32(out_events, *serial_counter);
                    }
                }
            }
            XDG_WM_BASE_PONG => {
                // Client acknowledged ping
            }
            _ => {}
        }
        return;
    }

    // 7. `xdg_surface`
    if session.xdg_surfaces.contains_key(&object_id) {
        match opcode {
            XDG_SURFACE_GET_TOPLEVEL => {
                if let Some(toplevel_id) = read_u32(payload, &mut offset) {
                    session.toplevels.insert(toplevel_id, object_id);
                    // Send xdg_toplevel.configure: suggested width=0, height=0, states=[]
                    let mut conf_p = Vec::new();
                    write_i32(&mut conf_p, 0);
                    write_i32(&mut conf_p, 0);
                    write_u32(&mut conf_p, 0); // 0 state items
                    write_msg_header(out_events, toplevel_id, 0, conf_p.len());
                    out_events.extend_from_slice(&conf_p);

                    // Send xdg_surface.configure(serial)
                    *serial_counter = serial_counter.wrapping_add(1);
                    write_msg_header(out_events, object_id, 0, 4);
                    write_u32(out_events, *serial_counter);
                }
            }
            XDG_SURFACE_ACK_CONFIGURE => {
                // Client acknowledged configure
            }
            _ => {}
        }
        return;
    }

    // 8. `xdg_toplevel`
    if session.toplevels.contains_key(&object_id) {
        match opcode {
            XDG_TOPLEVEL_SET_TITLE => {
                if let Some(title) = read_string(payload, &mut offset) {
                    if let Some(&xdg_surf_id) = session.toplevels.get(&object_id) {
                        if let Some(&surf_id) = session.xdg_surfaces.get(&xdg_surf_id) {
                            if let Some(surf) = session.surfaces.get_mut(&surf_id) {
                                surf.title = title;
                            }
                        }
                    }
                }
            }
            XDG_TOPLEVEL_SET_APP_ID => {
                if let Some(app_id) = read_string(payload, &mut offset) {
                    if let Some(&xdg_surf_id) = session.toplevels.get(&object_id) {
                        if let Some(&surf_id) = session.xdg_surfaces.get(&xdg_surf_id) {
                            if let Some(surf) = session.surfaces.get_mut(&surf_id) {
                                surf.app_id = app_id;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        return;
    }

    // 9. `wl_surface`
    if session.surfaces.contains_key(&object_id) {
        match opcode {
            WL_SURFACE_ATTACH => {
                if let Some(buf_id) = read_u32(payload, &mut offset) {
                    if let Some(surf) = session.surfaces.get_mut(&object_id) {
                        surf.attached_buffer_id = if buf_id == 0 { None } else { Some(buf_id) };
                    }
                }
            }
            WL_SURFACE_DAMAGE => {
                // Damage region recorded
            }
            WL_SURFACE_FRAME => {
                if let Some(callback_id) = read_u32(payload, &mut offset) {
                    if let Some(surf) = session.surfaces.get_mut(&object_id) {
                        surf.frame_callbacks.push(callback_id);
                    }
                }
            }
            WL_SURFACE_COMMIT => {
                let mut callbacks_to_send = Vec::new();
                if let Some(surf) = session.surfaces.get_mut(&object_id) {
                    surf.commit_count += 1;
                    if let Some(buf_id) = surf.attached_buffer_id {
                        if let Some(buf) = session.buffers.get(&buf_id) {
                            if let Some(pool) = session.pools.get(&buf.pool_id) {
                                blit_wayland_surface(surf, buf, pool);
                            }
                        }
                    }
                    callbacks_to_send = core::mem::take(&mut surf.frame_callbacks);
                }

                // Send frame done event for all requested callbacks
                for cb in callbacks_to_send {
                    *serial_counter = serial_counter.wrapping_add(1);
                    write_msg_header(out_events, cb, 0, 4);
                    write_u32(out_events, *serial_counter);
                }
            }
            _ => {}
        }
        return;
    }

    // 10. `wl_seat`
    if Some(object_id) == session.seat_id {
        match opcode {
            WL_SEAT_GET_POINTER => {
                if let Some(ptr_id) = read_u32(payload, &mut offset) {
                    session.pointer_id = Some(ptr_id);
                }
            }
            WL_SEAT_GET_KEYBOARD => {
                if let Some(kbd_id) = read_u32(payload, &mut offset) {
                    session.keyboard_id = Some(kbd_id);
                    // Send keymap event: format 0 (raw scancodes), size 0
                    write_msg_header(out_events, kbd_id, WL_KEYBOARD_EVENT_KEYMAP, 8);
                    write_u32(out_events, 0);
                    write_u32(out_events, 0);

                    // Send repeat_info event: rate = 25 chars/sec, delay = 400ms
                    write_msg_header(out_events, kbd_id, WL_KEYBOARD_EVENT_REPEAT_INFO, 8);
                    write_i32(out_events, 25);
                    write_i32(out_events, 400);
                }
            }
            WL_SEAT_RELEASE => {
                session.seat_id = None;
            }
            _ => {}
        }
        return;
    }

    // 11. `wl_pointer`
    if Some(object_id) == session.pointer_id {
        match opcode {
            WL_POINTER_RELEASE => {
                session.pointer_id = None;
            }
            _ => {}
        }
        return;
    }

    // 12. `wl_keyboard`
    if Some(object_id) == session.keyboard_id {
        match opcode {
            WL_KEYBOARD_RELEASE => {
                session.keyboard_id = None;
            }
            _ => {}
        }
        return;
    }
}

// -----------------------------------------------------------------------------
// Direct UEFI GOP Linear Framebuffer Blitter
// -----------------------------------------------------------------------------

/// Renders a Wayland client surface directly onto the active UEFI GOP linear framebuffer,
/// complete with a dark KDE Plasma Breeze window frame, Plasma Blue accent header, and control buttons.
pub fn blit_wayland_surface(
    surface: &WaylandSurfaceState,
    buffer: &WaylandBuffer,
    pool: &WaylandShmPool,
) {
    with_framebuffer(|fb| {
        let screen_w = fb.width();
        let screen_h = fb.height();
        if screen_w == 0 || screen_h == 0 || buffer.width == 0 || buffer.height == 0 {
            return;
        }

        const TITLEBAR_HEIGHT: usize = 28;
        const CONTROL_BTN_WIDTH: usize = 28;

        let is_fullscreen = buffer.width >= screen_w && buffer.height >= screen_h;
        let win_w = if is_fullscreen { screen_w } else { buffer.width.min(screen_w.saturating_sub(20)) };
        let win_h = if is_fullscreen { screen_h } else { buffer.height + TITLEBAR_HEIGHT };
        let win_x = (screen_w.saturating_sub(win_w)) / 2;
        let win_y = (screen_h.saturating_sub(win_h)) / 2;

        // Breeze Dark Palette
        let color_border = (61u8, 174u8, 233u8);     // #3daee9 (Plasma Blue)
        let color_titlebar = (49u8, 54u8, 59u8);    // #31363b
        let color_titlebar_line = (35u8, 38u8, 41u8);// #232629
        let color_close_red = (218u8, 68u8, 83u8);   // #da4453
        let color_text_light = (239u8, 240u8, 241u8);// #eff0f1
        let color_text_muted = (189u8, 195u8, 199u8);// #bdc3c7

        // 1. Draw Breeze Window Outer Border Outline (1px)
        let bx_start = win_x.saturating_sub(1);
        let by_start = win_y.saturating_sub(1);
        let bw = win_w + 2;
        let bh = win_h + 2;

        fb.fill_rect(bx_start, by_start, bw, 1, color_border.0, color_border.1, color_border.2);
        fb.fill_rect(bx_start, by_start + bh - 1, bw, 1, color_border.0, color_border.1, color_border.2);
        fb.fill_rect(bx_start, by_start, 1, bh, color_border.0, color_border.1, color_border.2);
        fb.fill_rect(bx_start + bw - 1, by_start, 1, bh, color_border.0, color_border.1, color_border.2);

        // 2. Draw Breeze Titlebar Header (height 28px)
        fb.fill_rect(win_x, win_y, win_w, TITLEBAR_HEIGHT, color_titlebar.0, color_titlebar.1, color_titlebar.2);
        fb.fill_rect(win_x, win_y + TITLEBAR_HEIGHT - 1, win_w, 1, color_titlebar_line.0, color_titlebar_line.1, color_titlebar_line.2);

        // Window icon emblem (Plasma Blue square)
        fb.fill_rect(win_x + 8, win_y + 8, 12, 12, 61, 174, 233);

        // Window title text
        let title_to_draw = if surface.title.is_empty() {
            "Plasma 6.8 — Linux Wayland Client"
        } else {
            surface.title.as_str()
        };
        fb.draw_string(win_x + 28, win_y + 6, title_to_draw, color_text_light, color_titlebar);

        // Control Buttons on Top-Right: [ - ] [ # ] [ X ]
        let right_edge = win_x + win_w;

        // Close button ('X')
        let close_x = right_edge.saturating_sub(CONTROL_BTN_WIDTH);
        fb.fill_rect(close_x, win_y, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT, color_close_red.0, color_close_red.1, color_close_red.2);
        fb.draw_char(close_x + 10, win_y + 6, 'X', color_text_light, color_close_red);

        // Maximize button ('#')
        let max_x = right_edge.saturating_sub(CONTROL_BTN_WIDTH * 2);
        fb.fill_rect(max_x, win_y, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT, color_titlebar.0, color_titlebar.1, color_titlebar.2);
        fb.draw_char(max_x + 10, win_y + 6, '#', color_text_muted, color_titlebar);

        // Minimize button ('-')
        let min_x = right_edge.saturating_sub(CONTROL_BTN_WIDTH * 3);
        fb.fill_rect(min_x, win_y, CONTROL_BTN_WIDTH, TITLEBAR_HEIGHT, color_titlebar.0, color_titlebar.1, color_titlebar.2);
        fb.draw_char(min_x + 10, win_y + 6, '-', color_text_muted, color_titlebar);

        // 3. Direct Pixel Blit from MemFd into Framebuffer
        let client_y = if is_fullscreen { 0 } else { win_y + TITLEBAR_HEIGHT };
        let mut memfd = pool.memfd.lock();
        let mut row = alloc::vec![0u8; buffer.width * 4];
        let offset = buffer.offset;
        let stride = buffer.stride;
        let is_bgr = fb.is_bgr();
        let fb_stride = fb.stride();
        let base_ptr = fb.base_ptr();
        let fb_size = fb.size();

        for sy in 0..buffer.height {
            let py = client_y + sy;
            if py >= screen_h {
                break;
            }

            let row_offset = offset + sy * stride;
            let fb_row_offset = (py * fb_stride + win_x) * 4;
            let row_len = memfd.read_at(row_offset, &mut row);

            for sx in 0..buffer.width {
                let px = win_x + sx;
                if px >= screen_w {
                    break;
                }

                let pixel_src = sx * 4;
                let dst_offset = fb_row_offset + sx * 4;

                if pixel_src + 3 < row_len && dst_offset + 3 < fb_size {
                    let b = row[pixel_src];
                    let g = row[pixel_src + 1];
                    let r = row[pixel_src + 2];
                    let a = row[pixel_src + 3];

                    unsafe {
                        let dst_ptr = base_ptr.add(dst_offset);
                        if is_bgr {
                            *dst_ptr = b;
                            *dst_ptr.add(1) = g;
                            *dst_ptr.add(2) = r;
                            *dst_ptr.add(3) = a;
                        } else {
                            *dst_ptr = r;
                            *dst_ptr.add(1) = g;
                            *dst_ptr.add(2) = b;
                            *dst_ptr.add(3) = a;
                        }
                    }
                }
            }
        }
    });
}
