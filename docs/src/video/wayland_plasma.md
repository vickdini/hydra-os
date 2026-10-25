# Wayland Compositor & KDE Plasma Desktop Shell

## 1. Architectural Role & Design Rationale

Hydra OS introduces a native microkernel graphical desktop environment modeled after **KDE Plasma** running on a **Wayland Compositor**. Rather than relying on legacy monolithic X11 servers or bloated graphics stacks, Hydra implements a modern, memory-safe, double-buffered graphics pipeline executing in Ring 0 / Ring 3.

```text
+--------------------------------------------------------------------------+
|                       KDE Plasma Desktop Shell                           |
|       - Breeze Window Theme Engine (Titlebars, Close, Max, Min)          |
|       - 40px Taskbar Panel (Kickoff Launcher, Window Tabs, System Tray)  |
|       - Interactive Applications (Konsole Terminal, KSysGuard Monitor)   |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|                  Microkernel Wayland Compositor Core                     |
|       - Surface Registry (WlSurface: Position, Size, Z-Stacking)         |
|       - Input Routing & Focus Management (wl_seat)                       |
|       - Window Drag-and-Drop & Maximize State Machine                    |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|               Double-Buffered Framebuffer Compositor                     |
|       - 32-bit ARGB Canvas (Vec<u32>) in Fast System RAM                 |
|       - Fast Alpha-Blending (Color::blend) & Vertical Gradients          |
|       - 12x19 Anti-Aliased Arrow Mouse Cursor Sprite                     |
+--------------------------------------------------------------------------+
                  │                                     │
                  ▼                                     ▼
     Physical UEFI GOP Framebuffer              PS/2 Mouse Auxiliary Driver
      (Linear Video RAM Blit)                    (Ports 0x60/0x64, 3-byte packets)
```

---

## 2. Hardware Input: PS/2 Auxiliary Mouse Driver

Pointer interaction is handled autonomously by [`src/arch/mouse.rs`](file:///d:/os/src/arch/mouse.rs) via standard 8042 controller I/O ports:
- **Port 0x60**: Data Register.
- **Port 0x64**: Status / Command Register.

### Multiplexed Controller Routing
By checking bit 5 (`STATUS_AUX_OUTPUT`) of status port `0x64`, the driver distinguishes mouse packet bytes from keyboard scancodes without hardware collisions.

### 3-Byte Packet Protocol
Standard PS/2 mouse motion is streamed in 3-byte packets:
- **Byte 0**: Flags (Left Button, Right Button, Middle Button, Bit 3 verification, X/Y sign extensions, overflow bits).
- **Byte 1**: Delta X (9-bit signed relative horizontal movement).
- **Byte 2**: Delta Y (9-bit signed relative vertical movement, inverted for screen space).

The coordinates are clamped within the active display bounds `(0..width - 1, 0..height - 1)`.

---

## 3. Double-Buffered Compositor Engine

To eliminate screen flickering and tearing when moving windows, rendering widgets, or tracking the mouse pointer:
1. **Off-Screen Canvas**: Maintained in heap memory (`Vec<u32>` of size `width * height`).
2. **Color Primitives**: 32-bit ARGB packing with linear alpha blending:
   $$\text{Color::blend}(bg, fg, \alpha) = \frac{(fg \times \alpha) + (bg \times (255 - \alpha))}{255}$$
3. **Cursor Sprite**: High-definition 12x19 pixel arrow sprite with a dark outline (`#121212`) and opaque white interior (`#FFFFFF`).
4. **Hardware Flip**: Transfers the assembled raster buffer to the physical UEFI GOP linear framebuffer in a single pass, converting to BGRA if the hardware requires it.

---

## 4. KDE Plasma Breeze Desktop Elements

The desktop shell reproduces the signature aesthetics of KDE Plasma:
- **Breeze Dark Wallpaper**: Geometric gradient (`#1b1e20` -> `#232629` -> `#2a2e32`) with abstract angular polygon accents.
- **Breeze Window Frames**:
  - Translucent slate title bar (`#31363b` when active, `#232629` when inactive).
  - Breeze control buttons on the top right: Minimize (`-`), Maximize (`#`), and Close (`X`, highlighted in `#da4453` red).
  - Real-time window dragging by holding and dragging anywhere on the title bar.
  - Z-ordering: clicking any window brings it to the top of the stack.
- **Bottom Panel & System Tray (Height 40px)**:
  - **Kickoff Application Launcher**: Left-aligned Plasma button with blue glow indicator (`#1d99f3`).
  - **Task Manager Tabs**: Live window entries with bottom highlight underlines.
  - **System Tray**: Live ZFS storage health indicator (`ZFS: ONLINE`) and digital clock.
- **Integrated Applications**:
  - **Konsole (Terminal)**: Interactive command shell (`hydra:desktop>`) supporting commands like `zpool`, `uname`, `mem`, `clear`, and `help`.
  - **KSysGuard (System Monitor)**: Live performance dashboard with an animated CPU load gauge, kernel heap memory utilization meter, and persistent ZFS storage status.

---

## 5. Shell Integration & Controls

The desktop environment is launched from the Hydra microkernel shell:

```sh
hydra:/bin> plasma
```

Aliases: `startplasma`, `wayland`, `gui`, `desktop`.

### Keyboard & Mouse Controls
- **Mouse Left Click & Drag**: Move windows, select active applications, and click control buttons.
- **Keyboard Input**: Directed to the active focused window (e.g. Konsole terminal).
- **Escape Key (`Esc`)**: Gracefully terminates the Wayland session and restores the microkernel text console.
