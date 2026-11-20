//! Helpers shared by the test binaries.

#![allow(dead_code)]

pub use hydra_hosttests_t34 as k;
pub use hydra_hosttests_t34::{fake, uefi_fake};

use k::admin::proto::*;

/// Puts the global console back in its boot state: firmware text console, no
/// framebuffer console, no splash, empty scrollback, scroll lock off.
pub fn console_reset() {
    k::video::splash::compositor_took();
    k::video::splash::poll();
    // Give the screen back (framebuffers in tests are leaked, so stale pointers stay valid)
    k::video::console::reclaim_display();
    *k::video::console::VIDEO_CONSOLE.lock() = None;
    k::console::enable_standalone_video(false);
    k::console::set_hardware_mode(false);
    k::console::set_scroll_lock(false);
    k::console::clear_scrollback();
    k::console::CONSOLE.lock().current_attr = 0x0F;
    k::task::clear_tasks();
    if let Some(id) = k::admin::console_task() {
        k::admin::revoke_console(id);
    }
    uefi_fake::reset();
}

/// A fresh fake machine with the console reset. Hold the guard for the whole test.
pub fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = fake::reset();
    console_reset();
    g
}

/// A leaked framebuffer of `w`x`h` pixels (stride `w`), made the video console (RGB).
pub fn video(w: usize, h: usize) -> &'static mut [u8] {
    let mem: &'static mut [u8] = Box::leak(vec![0u8; w * h * 4].into_boxed_slice());
    let info = k::video::gop::mode_info_for(mem.as_mut_ptr(), mem.len(), w, h, w, uefi::proto::console::gop::PixelFormat::Rgb);
    k::video::gop::install(info);
    mem
}

/// The pixel `(x, y)` of a framebuffer of stride `stride`: `[b0, b1, b2, b3]`.
pub fn px(fb: &[u8], stride: usize, x: usize, y: usize) -> [u8; 4] {
    let o = (y * stride + x) * 4;
    [fb[o], fb[o + 1], fb[o + 2], fb[o + 3]]
}

/// The lines of the console's scrollback (committed and the current one).
pub fn scrollback() -> Vec<String> {
    let c = k::console::CONSOLE.lock();
    let mut out = Vec::new();
    let mut line = [0u8; 128];
    let mut attr = [0u8; 128];
    for i in 0..c.scrollback.total_lines() {
        let n = c.scrollback.get_line_with_attrs(i, &mut line, &mut attr).unwrap();
        out.push(String::from_utf8_lossy(&line[..n]).to_string());
    }
    out
}

/// Starts `hydra-shell` (the stub loader) as the admin console and makes it the running
/// task, so its admin calls are authorized.
pub fn authorize() -> k::task::TaskId {
    let id = k::admin::launch_shell(&["hydra-shell"], 1000, 1000).expect("launch");
    fake::with(|s| {
        s.current_tid = id.0;
        s.personality = Some(k::task::TaskPersonality::Hydra);
    });
    id
}

/// The answer of an admin call.
pub struct Answer {
    /// The system call's result.
    pub rc: i64,
    /// The bytes written to the answer buffer (the answer, or the error message).
    pub out: Vec<u8>,
    /// The error message (`err_len` bytes), if any.
    pub msg: String,
}

impl Answer {
    /// Record `T` at `off`.
    pub fn rec<T: Copy + Default>(&self, off: usize) -> T {
        read_record::<T>(&self.out, off).expect("record")
    }
    /// The `u64` at `off`.
    pub fn u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.out[off..off + 8].try_into().unwrap())
    }
}

/// Makes admin call `op` with `args` and `input`, answer buffer of `cap` bytes.
pub fn admin_cap(op: u32, args: [u64; 4], input: &[u8], cap: usize) -> Answer {
    let mut out = vec![0xEEu8; cap.max(1)];
    let call = Box::new(AdminCall {
        op,
        flags: 0,
        args,
        in_ptr: if input.is_empty() { 0 } else { input.as_ptr() as u64 },
        in_len: input.len() as u64,
        out_ptr: if cap == 0 { 0 } else { out.as_mut_ptr() as u64 },
        out_cap: cap as u64,
        err_len: 0,
    });
    let p = Box::into_raw(call);
    let rc = k::admin::syscall(p as u64);
    let call = unsafe { Box::from_raw(p) };
    let err_len = call.err_len as usize;
    let n = if rc >= 0 { (rc as usize).min(cap) } else { err_len };
    out.truncate(n.min(out.len()));
    let msg = if rc < 0 { String::from_utf8_lossy(&out[..err_len.min(out.len())]).to_string() } else { String::new() };
    Answer { rc, out, msg }
}

/// Makes admin call `op` (64 KiB answer buffer).
pub fn admin(op: u32, args: [u64; 4], input: &[u8]) -> Answer {
    admin_cap(op, args, input, 1 << 16)
}

/// Accounts of an installed system with password checks: `root`, `alice` (uid 1000, in
/// `sudo`), `bob` (uid 1001, not an admin), `carol` (uid 1002, primary group 27 = `sudo`),
/// and a broken line.
pub fn accounts() {
    fake::file("/ubuntu/usr/sbin/unix_chkpwd", b"\x7fELF");
    fake::file(
        "/ubuntu/etc/passwd",
        b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\ncarol:x:1002:27::/home/carol:/bin/sh\nbroken:x:abc:1\n",
    );
    fake::file("/ubuntu/etc/group", b"root:x:0:\nsudo:x:27:alice\nbob:x:1001:\n");
}

/// Makes the password checker (`unix_chkpwd`) accept exactly the `(name, password)` pairs
/// of `map`: the checker task's standard input is read when the kernel waits for it.
pub fn passwords(map: &'static [(&'static str, &'static str)]) {
    fake::with(|s| {
        s.on_sleep = Some(Box::new(move |st: &mut fake::State| {
            // The last chroot spawn is the checker: spawn_chroot /ubuntu /usr/sbin/unix_chkpwd ["...", "name", "nonull"] 0 0
            let Some(line) = st.log.iter().rev().find(|l| l.starts_with("spawn_chroot /ubuntu /usr/sbin/unix_chkpwd")) else { return };
            let name = line.split('"').nth(3).unwrap_or("").to_string();
            let tid = st.next_tid - 1;
            let input = k::task::with_task(tid, |t| {
                let fds = t.fds.lock();
                match fds.fds.get(&0) {
                    Some(k::fs::FileDescriptor::PipeRead(p)) => p.lock().data.clone(),
                    _ => Vec::new(),
                }
            });
            let ok = map.iter().any(|(n, p)| *n == name && input == [p.as_bytes(), &[0]].concat());
            if let Some(t) = st.tasks.get_mut(&tid) {
                if t.status == Some(0) {
                    t.status = Some(if ok { 0 } else { 7 });
                }
            }
        }));
    });
}

/// Runs `f`, expecting a panic whose message contains `what`.
pub fn expect_panic(what: &str, f: impl FnOnce()) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let e = r.err().expect("expected a panic");
    let msg = e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_default();
    assert!(msg.contains(what), "panic {:?} does not contain {:?}", msg, what);
}

// ------------------------------------------------------------------- the network server

/// Registers a running net-server (process `pid`) with its status area published (magic
/// only: no card yet); returns its window.
pub fn net_server(pid: u64) -> &'static mut [u8] {
    use k::ipc::protocol::*;
    fake::with(|s| {
        s.servers.insert(ENDPOINT_NET_SERVER, pid);
        s.online.insert(ENDPOINT_NET_SERVER);
    });
    status(NETS_ST_MAGIC, NETS_MAGIC);
    k::ipc::service::window(ENDPOINT_NET_SERVER).unwrap()
}

/// Sets status word `i` of net-server's window.
pub fn status(i: usize, v: u64) {
    let w = k::ipc::service::window(k::ipc::protocol::ENDPOINT_NET_SERVER).unwrap();
    let o = k::ipc::protocol::NETS_STATUS_OFF + i * 8;
    w[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// An address as the status area carries it.
pub fn ipw(ip: [u8; 4]) -> u64 {
    u32::from_le_bytes(ip) as u64
}

/// A card with a link, MAC 52:54:00:12:34:56, address `ip` (/24, gateway .2) and DNS
/// server `dns`.
pub fn iface_up(ip: [u8; 4], dns: [u8; 4]) {
    use k::ipc::protocol::*;
    status(NETS_ST_FLAGS, NETS_F_NIC | NETS_F_LINK);
    status(NETS_ST_MAC, u64::from_le_bytes([0x52, 0x54, 0, 0x12, 0x34, 0x56, 0, 0]));
    status(NETS_ST_IP, ipw(ip));
    status(NETS_ST_MASK, ipw([255, 255, 255, 0]));
    status(NETS_ST_GATEWAY, ipw([ip[0], ip[1], ip[2], 2]));
    status(NETS_ST_DNS, ipw(dns));
    status(NETS_ST_DHCP_SERVER, ipw([ip[0], ip[1], ip[2], 2]));
}

/// Publishes readiness word `w` for server socket `sid` (its low 32 bits are the handle).
pub fn sock_word(sid: u32, bits: u64, state: u64, err: u64) {
    use k::ipc::protocol::*;
    let w = k::ipc::service::window(ENDPOINT_NET_SERVER).unwrap();
    let v = sid as u64 | bits << 32 | state << 40 | err << 48;
    let o = NETS_SOCKS_OFF + (sid as usize & (NETS_SLOTS - 1)) * 8;
    w[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// A fake net-server answering the kernel's requests (handler of `fake::State`).
#[derive(Default)]
pub struct NetState {
    /// Next server handle.
    pub next_sid: u32,
    /// The DHCP answer: `Ok(address)` or `Err(errno)`.
    pub dhcp: Option<Result<[u8; 4], i64>>,
    /// Names DNS knows; other names answer this errno (default -2).
    pub names: Vec<(String, [u8; 4])>,
    pub dns_err: Option<i64>,
    /// Hosts that answer pings (with this many replies dropped first).
    pub pingable: Vec<[u8; 4]>,
    /// ICMP messages waiting, by handle: (source, message).
    pub icmp_queue: Vec<(u32, [u8; 4], Vec<u8>)>,
    /// TCP: connections refused; the response a connection gets; how much was sent.
    pub refuse: bool,
    pub http_response: Vec<u8>,
    pub sent: Vec<u8>,
    pub tcp_pending: Vec<(u32, Vec<u8>)>,
    /// Requests seen: (label, args).
    pub seen: Vec<(u32, [u64; 4])>,
    /// Requests answer this errno.
    pub fail: Option<i64>,
}

/// Installs a fake net-server (process 5) and returns its state.
pub fn fake_net() -> std::rc::Rc<std::cell::RefCell<NetState>> {
    use k::ipc::protocol::*;
    net_server(5);
    let st = std::rc::Rc::new(std::cell::RefCell::new(NetState { next_sid: 1, ..Default::default() }));
    let s2 = st.clone();
    fake::with(|s| {
        s.handler = Some(Box::new(move |ep, m, _| {
            assert_eq!(ep, ENDPOINT_NET_SERVER);
            let w = k::ipc::service::window(ENDPOINT_NET_SERVER).unwrap();
            let mut n = s2.borrow_mut();
            n.seen.push((m.label, m.args));
            let ok = |a: [u64; 4]| Ok(k::ipc::Message::with_args(0, a));
            if let Some(e) = n.fail {
                return ok([e as u64, 0, 0, 0]);
            }
            let a = m.args;
            match m.label {
                MSG_NETS_DHCP => match n.dhcp {
                    Some(Ok(ip)) => {
                        status(NETS_ST_IP, ipw(ip));
                        ok([0, ipw(ip), 0, 0])
                    }
                    Some(Err(e)) => ok([e as u64, 0, 0, 0]),
                    None => Err(-110),
                },
                MSG_NETS_RESOLVE => {
                    let name = String::from_utf8_lossy(&w[a[0] as usize..(a[0] + a[1]) as usize]).to_string();
                    match n.names.iter().find(|(nm, _)| *nm == name) {
                        Some((_, ip)) => ok([0, ipw(*ip), 0, 0]),
                        None => ok([n.dns_err.unwrap_or(-2) as u64, 0, 0, 0]),
                    }
                }
                MSG_NETS_ICMP_OPEN | MSG_NETS_TCP_CONNECT | MSG_NETS_UDP_OPEN => {
                    let sid = n.next_sid;
                    n.next_sid += 1;
                    if m.label == MSG_NETS_TCP_CONNECT {
                        if n.refuse {
                            sock_word(sid, NETS_R_HUP, NETS_TCP_CLOSED, 0);
                        } else {
                            let resp = n.http_response.clone();
                            n.tcp_pending.push((sid, resp));
                            sock_word(sid, NETS_R_OUT | NETS_R_IN, NETS_TCP_ESTABLISHED, 0);
                        }
                    } else {
                        sock_word(sid, NETS_R_OUT, 0, 0);
                    }
                    ok([sid as u64, 0, 0, 0])
                }
                MSG_NETS_ICMP_SEND => {
                    let sid = a[0] as u32;
                    let dst = (a[1] as u32).to_le_bytes();
                    let msg = w[..a[3] as usize].to_vec();
                    if n.pingable.contains(&dst) {
                        let mut reply = msg.clone();
                        reply[0] = 0; // echo reply
                        n.icmp_queue.push((sid, dst, reply));
                        sock_word(sid, NETS_R_IN | NETS_R_OUT, 0, 0);
                    }
                    ok([msg.len() as u64, 0, 0, 0])
                }
                MSG_NETS_ICMP_RECV => {
                    let sid = a[0] as u32;
                    match n.icmp_queue.iter().position(|q| q.0 == sid) {
                        Some(i) => {
                            let (_, src, msg) = n.icmp_queue.remove(i);
                            w[..msg.len()].copy_from_slice(&msg);
                            sock_word(sid, NETS_R_OUT, 0, 0);
                            ok([msg.len() as u64, ipw(src), 1234, 0])
                        }
                        None => ok([-11i64 as u64, 0, 0, 0]),
                    }
                }
                MSG_NETS_TCP_SEND => {
                    let len = a[2] as usize;
                    let data = w[..len].to_vec();
                    n.sent.extend_from_slice(&data);
                    ok([len as u64, 0, 0, 0])
                }
                MSG_NETS_TCP_RECV => {
                    let sid = a[0] as u32;
                    let cap = a[2] as usize;
                    let Some(i) = n.tcp_pending.iter().position(|p| p.0 == sid) else { return ok([0, 1, 0, 0]) };
                    let data = &mut n.tcp_pending[i].1;
                    let k = data.len().min(cap).min(1000);
                    let chunk: Vec<u8> = data.drain(..k).collect();
                    w[..k].copy_from_slice(&chunk);
                    let eof = data.is_empty();
                    if eof {
                        sock_word(sid, NETS_R_IN | NETS_R_HUP, NETS_TCP_CLOSE_WAIT, 0);
                    }
                    ok([k as u64, eof as u64, 0, 0])
                }
                _ => ok([0, 0, 0, 0]),
            }
        }));
    });
    st
}

/// [`status`] from inside a sleep hook (the fake machine is borrowed there).
pub fn status_in(st: &fake::State, i: usize, v: u64) {
    let base = st.windows[&k::ipc::protocol::ENDPOINT_NET_SERVER];
    let o = k::ipc::protocol::NETS_STATUS_OFF + i * 8;
    unsafe { core::ptr::write_unaligned((base + o) as *mut u64, v) };
}
