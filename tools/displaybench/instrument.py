#!/usr/bin/env python3
"""Applies (or removes) Group 15's THROWAWAY measurement hooks to a Hydra tree.

    python instrument.py TREE          # apply: copies dispstat.rs, hooks drm/evdev/snd/tty/pty/prof
    python instrument.py TREE --undo   # restore the six files with git checkout, delete dispstat.rs

The hooks count DRM, evdev, ALSA, tty and pty calls, time the page-flip copy and the
cursor update, and measure input latency (interrupt -> evdev read -> next flip / cursor
update). A kernel task prints a `[dstat]` block on the serial port every 5 s once a DRM
or PCM device is used; Linux system call totals need `linux prof on`
(see the appendix of docs/display-input-design.md).
Never commit an instrumented tree: build it, measure, undo.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ["mod.rs", "prof.rs", "drm.rs", "evdev.rs", "snd.rs", "tty.rs", "pty.rs"]


def edit(path, fn):
    raw = open(path, newline="").read()
    crlf = "\r\n" in raw
    s = raw.replace("\r\n", "\n")
    s = fn(s)
    if crlf:
        s = s.replace("\n", "\r\n")
    open(path, "w", newline="").write(s)


def once(s, a, b):
    if s.count(a) != 1:
        raise SystemExit(f"pattern found {s.count(a)} times: {a[:80]!r}")
    return s.replace(a, b)


def after(s, anchor, a, add):
    """Inserts `add` after the first `a` following `anchor`."""
    i = s.index(a, s.index(anchor))
    return s[: i + len(a)] + add + s[i + len(a):]


def apply(tree):
    L = os.path.join(tree, "src", "compat", "linux")
    shutil.copy(os.path.join(HERE, "dispstat.rs"), os.path.join(L, "dispstat.rs"))
    edit(os.path.join(L, "mod.rs"), lambda s: once(s, "pub mod drm;\n", "pub mod drm;\npub mod dispstat;\n"))
    edit(os.path.join(L, "prof.rs"), lambda s: once(s, "/// Clears every counter.\n",
         "pub fn calls(i: usize) -> u64 { CALLS[i].load(Relaxed) }\n\n/// Clears every counter.\n"))
    R = "core::sync::atomic::Ordering::Relaxed"

    def drm(s):
        s = once(s, "        let nr = cmd & 0xFF;\n        let size = ((cmd >> 16) & 0x3FFF) as usize;\n",
                 f"        let nr = cmd & 0xFF;\n        super::dispstat::DRM_IOCTL[nr as usize].fetch_add(1, {R});\n"
                 "        super::dispstat::start();\n        let size = ((cmd >> 16) & 0x3FFF) as usize;\n")
        s = once(s, "    fn poll_events(&self) -> u32 {\n        0x0004 | if self.events.lock()",
                 f"    fn poll_events(&self) -> u32 {{\n        super::dispstat::DRM_POLL.fetch_add(1, {R});\n        0x0004 | if self.events.lock()")
        s = once(s, "        self.copy_rect(0, 0, self.width, self.height);\n        self.drawn_cursor = None;\n        self.draw_cursor();\n",
                 "        let t0 = crate::arch::pit::now_ns();\n        self.copy_rect(0, 0, self.width, self.height);\n"
                 "        self.drawn_cursor = None;\n        self.draw_cursor();\n"
                 "        super::dispstat::present(crate::arch::pit::now_ns() - t0);\n        super::dispstat::flip();\n")
        s = once(s, "        if let Some((x, y, w, h)) = self.drawn_cursor.take() {",
                 "        let t0 = crate::arch::pit::now_ns();\n        if let Some((x, y, w, h)) = self.drawn_cursor.take() {")
        s = once(s, "            self.copy_rect(x0, y0, x1, y1);\n        }\n        self.draw_cursor();\n    }",
                 "            self.copy_rect(x0, y0, x1, y1);\n        }\n        self.draw_cursor();\n"
                 "        super::dispstat::cursor(crate::arch::pit::now_ns() - t0);\n    }")
        s = after(s, "fn set_property", "    fn read(&self, buf: &mut [u8]) -> i64 {\n",
                  f"        super::dispstat::DRM_READ.fetch_add(1, {R});\n")
        return s
    edit(os.path.join(L, "drm.rs"), drm)

    def evdev(s):
        s = once(s, "    let t = crate::arch::pit::ticks();\n    {\n        let mut ring = RING.lock();",
                 "    super::dispstat::raw_input();\n    let t = crate::arch::pit::ticks();\n    {\n        let mut ring = RING.lock();")
        s = once(s, "                if n > 0 {\n                    return n as i64;\n                }\n            }\n            if self.nonblock() {\n                return EAGAIN;",
                 "                if n > 0 {\n                    super::dispstat::ev_read(n as u64 / 24);\n                    return n as i64;\n"
                 "                }\n            }\n            if self.nonblock() {\n                super::dispstat::ev_read(0);\n                return EAGAIN;")
        s = once(s, "        if (cmd >> 8) & 0xFF != 0x45 {\n",
                 f"        super::dispstat::EV_IOCTL.fetch_add(1, {R});\n        if (cmd >> 8) & 0xFF != 0x45 {{\n")
        s = after(s, "impl CharDevice for EvdevFile", "    fn poll_events(&self) -> u32 {\n",
                  f"        super::dispstat::EV_POLL.fetch_add(1, {R});\n")
        return s
    edit(os.path.join(L, "evdev.rs"), evdev)

    def snd(s):
        s = once(s, "    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {\n        let r = (|| -> i64 {",
                 "    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {\n        super::dispstat::pcm_ioctl(cmd);\n        let r = (|| -> i64 {")
        s = once(s, "    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {\n        let Some(card) = CARD.lock().clone() else { return ENODEV };\n        match cmd as u32 {\n            0x8004_5500",
                 f"    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {{\n        super::dispstat::CTL_IOCTL.fetch_add(1, {R});\n"
                 "        let Some(card) = CARD.lock().clone() else { return ENODEV };\n        match cmd as u32 {\n            0x8004_5500")
        s = after(s, "impl CharDevice for CtlFile", "    fn read(&self, buf: &mut [u8]) -> i64 {\n",
                  f"        super::dispstat::CTL_READ.fetch_add(1, {R});\n")
        s = once(s, "avail >= s.stop_threshold {\n        s.state = ST_XRUN;\n", f"avail >= s.stop_threshold {{\n        s.state = ST_XRUN;\n        super::dispstat::XRUNS.fetch_add(1, {R});\n")
        s = once(s, "            let mut s = self.stream();\n            s.hw = Some(hw);\n",
                 "            crate::console::serial_write(&alloc::format!(\"[dstat] snd HW_PARAMS dir {} rate {} period {} x {} buffer {} access {}\\n\", self.dir, hw.rate, hw.period_size, hw.periods, hw.buffer_size, hw.access));\n"
                 "            let mut s = self.stream();\n            s.hw = Some(hw);\n")
        s = once(s, "fn position_task() {\n    loop {\n", f"fn position_task() {{\n    loop {{\n        super::dispstat::POS_WAKES.fetch_add(1, {R});\n")
        s = after(s, "fn transfer_frames", "    fn poll_events(&self) -> u32 {\n", f"        super::dispstat::PCM_POLL.fetch_add(1, {R});\n")
        return s
    edit(os.path.join(L, "snd.rs"), snd)

    def tty(s):
        for a in ["pub fn write(data: &[u8]) -> usize {\n", "pub fn ioctl(request: u64, arg: u64) -> i64 {\n",
                  "pub fn read(buf: &mut [u8], nonblock: bool) -> i64 {\n"]:
            s = once(s, a, a + f"    super::dispstat::TTY_OPS.fetch_add(1, {R});\n")
        return s
    edit(os.path.join(L, "tty.rs"), tty)

    def pty(s):
        for a in ["    pub fn read(&self, buf: &mut [u8]) -> i64 {\n", "    pub fn write(&self, data: &[u8]) -> i64 {\n",
                  "    pub fn ioctl(&self, request: u64, arg: u64, open_peer: &dyn Fn(Arc<PtyFile>, u32) -> i64) -> i64 {\n"]:
            s = once(s, a, a + f"        super::dispstat::PTY_OPS.fetch_add(1, {R});\n")
        return s
    edit(os.path.join(L, "pty.rs"), pty)
    print("instrumented", tree)


def undo(tree):
    L = os.path.join("src", "compat", "linux")
    subprocess.check_call(["git", "-C", tree, "checkout", "--"] + [os.path.join(L, f).replace("\\", "/") for f in FILES])
    p = os.path.join(tree, L, "dispstat.rs")
    if os.path.exists(p):
        os.remove(p)
    print("restored", tree)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    (undo if "--undo" in sys.argv else apply)(sys.argv[1])
