"""Boot Hydra headless in QEMU, type shell commands, and capture the serial log.

Usage:
    python tools/hydra_run.py [--mem 4G] [--wait SECONDS] [--until TEXT] [--log PATH] "cmd1" "cmd2" ...

Each command is typed into the Hydra shell followed by Enter. After the last command the
script waits until TEXT appears in the serial log (or SECONDS elapse), prints the log tail
from the first command onwards, and shuts QEMU down.
"""
import argparse
import json
import os
import shutil
import re
import subprocess
import sys
import time

if os.name == "nt":
    QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
    OVMF = r"C:\Program Files\qemu\share\edk2-x86_64-code.fd"
    OVMF_VARS = r"C:\Program Files\qemu\share\edk2-i386-vars.fd"
else:
    # Linux (Ubuntu's qemu-system-x86 and ovmf packages), e.g. inside WSL with KVM
    QEMU = "qemu-system-x86_64"
    OVMF = "/usr/share/OVMF/OVMF_CODE_4M.fd"
    OVMF_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SHIFTED = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8',
    '(': '9', ')': '0', '_': 'minus', '+': 'equal', '{': 'bracket_left', '}': 'bracket_right',
    '|': 'backslash', ':': 'semicolon', '"': 'apostrophe', '<': 'comma', '>': 'dot', '?': 'slash',
    '~': 'grave_accent',
}
PLAIN = {
    ' ': 'spc', '\n': 'ret', '-': 'minus', '=': 'equal', '[': 'bracket_left', ']': 'bracket_right',
    '\\': 'backslash', ';': 'semicolon', "'": 'apostrophe', ',': 'comma', '.': 'dot', '/': 'slash',
    '`': 'grave_accent', '\t': 'tab',
}


class Qmp:
    """QMP over QEMU's stdin/stdout (no network sockets needed)."""

    def __init__(self, proc):
        self.proc = proc
        self.buf = b""
        self._read_reply()  # greeting
        self.cmd("qmp_capabilities")

    def _read_reply(self):
        while True:
            while b"\n" not in self.buf:
                chunk = self.proc.stdout.read1(65536)
                if not chunk:
                    return None
                self.buf += chunk
            line, self.buf = self.buf.split(b"\n", 1)
            try:
                msg = json.loads(line)
            except ValueError:
                # accelerator warnings share stdout with QMP
                sys.stderr.write(line.decode(errors="replace") + "\n")
                continue
            if "event" not in msg:
                return msg

    def cmd(self, name, args=None):
        payload = {"execute": name}
        if args:
            payload["arguments"] = args
        try:
            self.proc.stdin.write(json.dumps(payload).encode() + b"\r\n")
            self.proc.stdin.flush()
        except OSError:
            # QEMU has exited (the guest powered off or restarted)
            return {"error": "QEMU has exited"}
        return self._read_reply()

    def key(self, ch):
        if ch in PLAIN:
            keys = [PLAIN[ch]]
        elif ch in SHIFTED:
            keys = ["shift", SHIFTED[ch]]
        elif ch.isalpha() and ch.isupper():
            keys = ["shift", ch.lower()]
        elif ch.isalnum():
            keys = [ch]
        else:
            return
        self.cmd("send-key", {"keys": [{"type": "qcode", "data": k} for k in keys]})
        time.sleep(0.03)

    def type(self, text):
        for ch in text:
            self.key(ch)


def read_log(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def pointer(qmp, spec, screen):
    """Pointer step `spec` ("click X Y", "dclick X Y", "rclick X Y", "move X Y"): an absolute
    move to pixel (X, Y) of a `screen` = (width, height) display, then the button presses, each
    sent alone (QEMU delivers a batch's final state only) with short pauses between."""
    action, x, y = spec.split()
    w, h = screen
    ax = round(int(x) * 0x7FFF / max(w - 1, 1))
    ay = round(int(y) * 0x7FFF / max(h - 1, 1))
    qmp.cmd("input-send-event", {"events": [{"type": "abs", "data": {"axis": "x", "value": ax}},
                                            {"type": "abs", "data": {"axis": "y", "value": ay}}]})
    time.sleep(0.15)
    button = "right" if action == "rclick" else "left"
    for _ in range({"move": 0, "click": 1, "rclick": 1, "dclick": 2}[action]):
        for down in (True, False):
            qmp.cmd("input-send-event", {"events": [{"type": "btn", "data": {"down": down, "button": button}}]})
            time.sleep(0.08)


def control_loop(qmp, proc, a):
    """Control mode (--control DIR): runs the steps of each `DIR/*.cmd` file (oldest name
    first; one step per line, as on the command line), writes what monitor and QMP steps
    return to `<name>.out`, renames the file `<name>.done`, until a `quit` step, QEMU's exit
    or --wait seconds without a new file."""
    os.makedirs(a.control, exist_ok=True)
    idle_since = time.time()
    while proc.poll() is None and time.time() - idle_since < a.wait:
        files = sorted(f for f in os.listdir(a.control) if f.endswith(".cmd"))
        if not files:
            time.sleep(0.2)
            continue
        path = os.path.join(a.control, files[0])
        steps = [l.rstrip("\r\n") for l in open(path, encoding="utf-8") if l.strip()]
        out = []
        for c in steps:
            if c == "quit":
                os.replace(path, path[:-4] + ".done")
                qmp.cmd("quit")
                return
            if c.startswith("~"):
                time.sleep(float(c[1:]))
            elif c.startswith("!"):
                r = qmp.cmd("human-monitor-command", {"command-line": c[1:]})
                out.append(str(r.get("return", r)))
            elif c.startswith("?"):
                req = json.loads(c[1:])
                r = qmp.cmd(req["execute"], req.get("arguments", {}))
                out.append(str(r.get("return", r)))
            elif c.startswith(">"):
                pointer(qmp, c[1:], a.screen)
            elif c.startswith("%"):
                qmp.cmd("send-key", {"keys": [{"type": "qcode", "data": k} for k in c[1:].split("-")]})
            elif len(c) == 2 and c[0] == "^" and c[1].isalpha():
                qmp.cmd("send-key", {"keys": [{"type": "qcode", "data": "ctrl"}, {"type": "qcode", "data": c[1].lower()}]})
            elif c.startswith("@"):
                qmp.type(c[1:])  # text without Enter
            else:
                qmp.type(c + "\n")
            time.sleep(0.1)
        with open(path[:-4] + ".out", "w", encoding="utf-8") as f:
            f.write("\n".join(out))
        os.replace(path, path[:-4] + ".done")
        idle_since = time.time()


def running_qemus():
    """The running QEMU processes: `(pid, command line)`."""
    if os.name != "nt":
        out = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True).stdout
        found = []
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if pid.isdigit() and os.path.basename(cmd.split(" ")[0]) == "qemu-system-x86_64":
                found.append((int(pid), cmd))
        return found
    ps = ("Get-CimInstance Win32_Process -Filter \"name='qemu-system-x86_64.exe'\" | "
          "ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    found = []
    for line in out.splitlines():
        pid, _, cmd = line.partition("	")
        if pid.strip().isdigit():
            found.append((int(pid), cmd))
    return found


def main():
    sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--smp", type=int, default=1, help="number of CPUs")
    ap.add_argument("--mem", default="4G")
    ap.add_argument("--accel", default="whpx" if os.name == "nt" else "kvm", choices=["whpx", "kvm", "tcg"],
                    help="whpx: Windows hardware virtualization; kvm: Linux's (also inside WSL2); tcg: software emulation")
    ap.add_argument("--wait", type=float, default=60)
    ap.add_argument("--until", default=None)
    ap.add_argument("--log", default=os.path.join(ROOT, "scratch", "qemu_run.log"))
    ap.add_argument("--boot-wait", type=float, default=60)
    ap.add_argument("--gap", type=float, default=1.0, help="seconds between commands")
    ap.add_argument("--prompt", default=None, help="wait for one more occurrence of this text before typing each command after the first")
    ap.add_argument("--prompt-timeout", type=float, default=60, help="longest wait for each prompt (seconds)")
    ap.add_argument("--extra-disk", default=None, help="a second disk (qcow2 or raw), on the same bus as the pool disk")
    ap.add_argument("--boot-dir", default=None, help="boot from a host directory (QEMU's virtual FAT, read-only) holding EFI/BOOT/BOOTX64.EFI and bin/ instead of the ISO")
    ap.add_argument("--no-cd", action="store_true", help="no boot ISO: the firmware boots from the disks (an installed system)")
    ap.add_argument("--efivars", default=None, help="a writable UEFI variable store (copied from OVMF's template when missing): boot entries persist in it")
    ap.add_argument("--disk", default=os.path.join(ROOT, "dist", "x86_64", "hydrapool.qcow2"))
    ap.add_argument("--disk-bus", default="ide", choices=["ide", "ahci"],
                    help="how the pool disk is attached: the IDE controller (ata-driver) or an AHCI SATA adapter (ahci-driver)")
    ap.add_argument("--nic", default="e1000", choices=["e1000", "e1000e", "none"], help="network adapter model")
    ap.add_argument("--usb", action="store_true", help="add an xHCI controller with a USB keyboard and tablet")
    ap.add_argument("--shared-host", action="store_true",
                    help="only refuse to start when another QEMU uses the same disk image (other VMs on other images may run)")
    ap.add_argument("--stall-dump", type=float, default=0, help="save CPU state when the log stops growing for this many seconds")
    ap.add_argument("--no-cancel", action="store_true", help="boot into the desktop (otherwise QEMU's fw_cfg asks the kernel for the Hydra shell)")
    ap.add_argument("--cd", default="virtio", choices=["virtio", "ide"], help="how the boot ISO is attached: virtio-scsi (fast firmware reads) or the IDE CD-ROM")
    ap.add_argument("--kill-stale", action="store_true", help="first stop headless QEMUs left by earlier runs (never a VM with a window)")
    ap.add_argument("--login", default="hydra:hydra", help="user:password for the console login after the countdown ('' to skip)")
    ap.add_argument("--control", default=None, help="after the commands, take more steps from DIR/*.cmd files until 'quit' (see control_loop)")
    ap.add_argument("--screen", default="1280x800", help="guest screen size for pointer steps (>click X Y)")
    ap.add_argument("--machine", default="pc", choices=["pc", "q35"],
                    help="the chipset: pc (i440fx, IDE) or q35 (ICH9; -drive if=ide lands on its built-in AHCI)")
    ap.add_argument("--iommu", action="store_true", help="add an Intel VT-d IOMMU (intel-iommu; implies --machine q35)")
    ap.add_argument("--iommu-test", action="store_true",
                    help="tell the kernel (fw_cfg opt/hydra/iommu=test) to allow the rogue-DMA test (`iommu dmatest`)")
    ap.add_argument("--iommu-off", action="store_true", help="tell the kernel (fw_cfg opt/hydra/iommu=off) not to use the IOMMU")
    ap.add_argument("--pcid-off", action="store_true", help="tell the kernel (fw_cfg opt/hydra/pcid=off) not to use PCID (tagged TLB)")
    ap.add_argument("--global-off", action="store_true", help="tell the kernel (fw_cfg opt/hydra/pge=off) not to use global kernel pages")
    ap.add_argument("--lx-kernel", action="store_true", help="tell the kernel (fw_cfg opt/hydra/lx=kernel) to answer the Linux calls moved to linux-server itself")
    ap.add_argument("--lx", default=None, help="wave 6: per-service switch-back words for fw_cfg opt/hydra/lx, joined by '+', e.g. 'sec=kernel+ipc=kernel' or 'test=linux'")
    ap.add_argument("commands", nargs="*")
    a = ap.parse_args()
    if a.iommu:
        a.machine = "q35"
    a.screen = tuple(int(v) for v in a.screen.lower().split("x"))

    # One VM at a time: two QEMUs on the same pool image (or one on an overlay while the
    # pool changes underneath) corrupt it, and QEMU on Windows does not prevent it
    def conflicting():
        found = running_qemus()
        if a.shared_host:
            # Several VMs on separate overlay images may run side by side; only one on
            # the same image corrupts it
            found = [(pid, cmd) for pid, cmd in found if f"file={a.disk}," in cmd]
        return found
    others = conflicting()
    if a.kill_stale:
        for pid, cmd in others:
            if "-display none" in cmd:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                else:
                    subprocess.run(["kill", "-9", str(pid)], capture_output=True)
        time.sleep(1.0)
        others = conflicting()
    if others:
        for pid, cmd in others:
            print(f"[hydra_run] another QEMU is running (pid {pid}{', headless' if '-display none' in cmd else ', with a window'}): not starting a second VM on the pool")
        sys.exit(3)

    if os.path.exists(a.log):
        os.remove(a.log)
    if a.accel == "whpx":
        # WHPX cannot emulate OVMF's flash chip, so the firmware is loaded as a ROM: the
        # usual OVMF.fd layout (variable store, then code) built from QEMU's split files
        fw = os.path.join(ROOT, "target", "OVMF-whpx.fd")
        if not os.path.exists(fw):
            os.makedirs(os.path.dirname(fw), exist_ok=True)
            with open(fw, "wb") as out:
                for part in (OVMF_VARS, OVMF):
                    with open(part, "rb") as f:
                        out.write(f.read())
        firmware = ["-accel", "whpx,kernel-irqchip=off", "-bios", fw]
    elif a.accel == "kvm":
        firmware = ["-accel", "kvm", "-cpu", "host", "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF}"]
        if a.efivars:
            if not os.path.exists(a.efivars):
                shutil.copyfile(OVMF_VARS, a.efivars)
            firmware += ["-drive", f"if=pflash,format=raw,file={a.efivars}"]
    else:
        firmware = ["-drive", f"if=pflash,format=raw,readonly=on,file={OVMF}"]
    args = [
        QEMU,
        *firmware,
        "-m", a.mem, "-smp", str(a.smp), "-vga", "std", "-display", "none",
        "-serial", f"file:{a.log}",
        "-qmp", "stdio",
        "-no-reboot",
    ]
    if a.machine == "q35":
        args += ["-machine", "q35"]
        if a.iommu:
            # The IOMMU must come before every other PCI device. Interrupt remapping is
            # not used by Hydra; caching-mode makes QEMU see each new mapping (the kernel
            # flushes the IOTLB on map when CAP.CM is set).
            args += ["-device", "intel-iommu,intremap=off,caching-mode=on"]
    if a.iommu_test:
        args += ["-fw_cfg", "name=opt/hydra/iommu,string=test"]
    elif a.iommu_off:
        args += ["-fw_cfg", "name=opt/hydra/iommu,string=off"]
    if a.pcid_off:
        args += ["-fw_cfg", "name=opt/hydra/pcid,string=off"]
    if a.global_off:
        args += ["-fw_cfg", "name=opt/hydra/pge,string=off"]
    if a.lx_kernel:
        args += ["-fw_cfg", "name=opt/hydra/lx,string=kernel"]
    elif a.lx:
        args += ["-fw_cfg", "name=opt/hydra/lx,string=" + a.lx]
    disk_format = 'qcow2' if a.disk.endswith('.qcow2') else 'raw'
    if a.disk == "none":
        pass  # no pool disk (e.g. the pool on a USB stick given through HYDRA_QEMU_EXTRA)
    elif a.disk_bus == "ahci":
        # An ICH9 AHCI adapter (as on real Intel chipsets) with the pool disk on port 0
        args += ["-device", "ahci,id=ahci", "-drive", f"file={a.disk},format={disk_format},if=none,id=pooldisk",
                 "-device", "ide-hd,drive=pooldisk,bus=ahci.0"]
    else:
        args += ["-drive", f"file={a.disk},format={disk_format},if=ide,index=0,media=disk"]
    if a.nic == "none":
        args += ["-nic", "none"]
    elif a.nic != "e1000" or a.machine == "q35":
        # QEMU's default for the pc machine is an e1000 with user networking (q35's is
        # an e1000e, so the model is named there)
        args += ["-nic", f"user,model={a.nic}"]
    if a.usb:
        args += ["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0", "-device", "usb-tablet,bus=xhci.0"]
    # HYDRA_ISO: another boot ISO (the live-session test ISO of tools/build-image, or a copy
    # on the VM host's own disk instead of a 9p mount)
    iso = os.environ.get("HYDRA_ISO") or os.path.join(ROOT, "dist", "x86_64", "kernel.iso")
    if a.no_cd:
        pass
    elif a.boot_dir:
        args += ["-device", "virtio-scsi-pci,id=scsi0", "-drive", (f"file={a.boot_dir},if=none,id=bootfat,format=raw,readonly=on" if a.boot_dir.endswith(".img") else f"file=fat:{a.boot_dir},if=none,id=bootfat,format=raw,readonly=on"),
                 "-device", "scsi-hd,drive=bootfat,bootindex=0"]
    elif a.cd == "virtio":
        # The firmware reads the boot volume (the kernel and the files staged for the pool)
        # by DMA instead of the IDE CD-ROM's port I/O; Hydra needs no driver for it
        args += ["-device", "virtio-scsi-pci,id=scsi0", "-drive", f"file={iso},if=none,id=bootcd,media=cdrom,format=raw",
                 "-device", "scsi-cd,drive=bootcd,bootindex=0"]
    else:
        args += ["-cdrom", iso, "-boot", "d"]
    if not a.no_cancel:
        # The kernel stays in the Hydra shell instead of starting the desktop
        args += ["-fw_cfg", "name=opt/hydra/boot,string=shell"]
    # e.g. HYDRA_QEMU_EXTRA="-d cpu_reset -D D:/os/scratch/qemu_dbg.log"
    args += os.environ.get("HYDRA_QEMU_EXTRA", "").split()
    if a.extra_disk:
        extra_format = 'qcow2' if a.extra_disk.endswith('.qcow2') else 'raw'
        if a.disk_bus == "ahci":
            args += ["-drive", f"file={a.extra_disk},format={extra_format},if=none,id=extradisk", "-device", "ide-hd,drive=extradisk,bus=ahci.1"]
        else:
            args += ["-drive", f"file={a.extra_disk},format={extra_format},if=ide,index=1,media=disk"]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        qmp = Qmp(proc)
        # Wait for the end of the kernel's boot: the desktop starting, or the Hydra shell
        # (asked for through fw_cfg above)
        deadline = time.time() + a.boot_wait
        while time.time() < deadline and not any(t in read_log(a.log) for t in ("Starting KDE Plasma", "[*] Hydra shell (")):
            time.sleep(0.5)
        time.sleep(1.0)
        def wait_for(text, since, timeout):
            end = time.time() + timeout
            while time.time() < end:
                if text in read_log(a.log)[since:]:
                    return True
                time.sleep(0.25)
            return False
        user, _, password = a.login.partition(":")
        if a.login and not a.no_cancel:
            # The console asks an administrator to log in (the prompt is already up)
            mark = 0
            if wait_for("login: ", mark, 60):
                qmp.type(user + "\n")
                wait_for("Password: ", mark, 10)
                qmp.type(password + "\n")
                wait_for("Logged in as", mark, 30)
        start = len(read_log(a.log))
        prompts_seen = 0
        typed = [c.lstrip("@") for c in a.commands if c and c[0] not in "~!%?>"]
        for i, c in enumerate(a.commands):
            if proc.poll() is not None:
                # Powered off or restarted (-no-reboot): nothing left to type into, and
                # writing to QEMU's closed pipe would raise
                print(f"[hydra_run] QEMU exited before command {i + 1} of {len(a.commands)}: the rest are skipped")
                break
            no_wait = c.startswith("@")  # "@cmd": type without waiting for a prompt
            if no_wait:
                c = c[1:]
            if a.prompt and i > 0 and not no_wait:
                # Wait until the program prints a new prompt after the previous command
                deadline = time.time() + a.prompt_timeout
                while time.time() < deadline and read_log(a.log)[start:].count(a.prompt) <= prompts_seen:
                    time.sleep(0.25)
            if a.prompt:
                prompts_seen = read_log(a.log)[start:].count(a.prompt)
            if c.startswith("~"):
                # "~30": pause 30 seconds before the next item
                time.sleep(float(c[1:]))
                continue
            if c.startswith("!"):
                # "!info registers": QEMU monitor command, output printed to stderr
                r = qmp.cmd("human-monitor-command", {"command-line": c[1:]})
                sys.stderr.write(str(r.get("return", r)) + "\n")
                continue
            if c.startswith("?"):
                # '?{"execute": "input-send-event", "arguments": {...}}': a QMP command
                req = json.loads(c[1:])
                r = qmp.cmd(req["execute"], req.get("arguments", {}))
                sys.stderr.write(str(r.get("return", r)) + "\n")
                continue
            if c.startswith(">"):
                # ">click 640 400", ">dclick X Y", ">rclick X Y", ">move X Y": the pointer, in
                # screen pixels (needs Hydra's absolute pointer, i.e. KVM's vmmouse)
                pointer(qmp, c[1:], a.screen)
                continue
            if c.startswith("%"):
                # "%f12", "%esc": a single named key (QEMU qcode)
                qmp.cmd("send-key", {"keys": [{"type": "qcode", "data": c[1:]}]})
            elif len(c) == 2 and c[0] == "^" and c[1].isalpha():
                # Ctrl+letter, e.g. ^C, ^Z, ^D
                qmp.cmd("send-key", {"keys": [{"type": "qcode", "data": "ctrl"}, {"type": "qcode", "data": c[1].lower()}]})
            elif c == "su root" and a.login:
                # Becoming root takes the administrator's password: "sudo -s", as on Ubuntu
                mark = len(read_log(a.log))
                qmp.type("sudo -s\n")
                end = time.time() + 15
                while time.time() < end:
                    tail = read_log(a.log)[mark:]
                    if "[sudo] password" in tail:
                        qmp.type(password + "\n")
                        break
                    if "Switched to superuser" in tail or "sudoers" in tail:
                        break
                    time.sleep(0.25)
            else:
                qmp.type(c + "\n")
            time.sleep(a.gap)
        if a.control:
            control_loop(qmp, proc, a)
            return
        deadline = time.time() + a.wait
        last_len, last_change, dumped = -1, time.time(), False
        while time.time() < deadline:
            log = read_log(a.log)
            # --stall-dump N: when the log has not grown for N seconds, save the CPU state
            # and the kernel stack to scratch/hydra_stall.txt (once per run)
            if len(log) != last_len:
                last_len, last_change = len(log), time.time()
            elif a.stall_dump and not dumped and time.time() - last_change > a.stall_dump:
                dumped = True
                with open(os.path.join(ROOT, "scratch", "hydra_stall.txt"), "w", encoding="utf-8") as out:
                    regs = ""
                    for _ in range(3):
                        r = qmp.cmd("human-monitor-command", {"command-line": "info registers"})
                        regs = str(r.get("return", r))
                        out.write(regs + "\n")
                        time.sleep(0.5)
                    m = re.search(r"RSP=([0-9a-f]+)", regs)
                    if m:
                        r = qmp.cmd("human-monitor-command", {"command-line": f"x /256gx 0x{m.group(1)}"})
                        out.write("$ stack\n" + str(r.get("return", r)) + "\n")
                    # The other CPUs: registers and stack of each
                    if a.smp > 1:
                        r = qmp.cmd("human-monitor-command", {"command-line": "info registers -a"})
                        allregs = str(r.get("return", r))
                        for c, regs in enumerate(re.split(r"\n(?=CPU#\d)", allregs)):
                            if c == 0:
                                continue
                            out.write(f"$ cpu {c}\n" + regs + "\n")
                            m = re.search(r"RSP=([0-9a-f]+)", regs)
                            if m:
                                r = qmp.cmd("human-monitor-command", {"command-line": f"x /256gx 0x{m.group(1)}"})
                                out.write(f"$ stack {c}\n" + str(r.get("return", r)) + "\n")
                print(f"[hydra_run] log stalled for {a.stall_dump} s: CPU state saved to scratch/hydra_stall.txt")
            # --until is a regular expression (alternatives with |; `\|` also accepted). The
            # shell echoes typed commands, so their text is removed first: otherwise a
            # pattern that also appears in a command matches its echo and ends the run early
            seen = log[start:]
            for c in typed:
                seen = seen.replace(c, "")
            if a.until and re.search(a.until.replace(r'\|', '|'), seen):
                time.sleep(1.0)
                break
            if proc.poll() is not None:
                break
            # Debug back door while waiting: commands dropped into scratch/hydra_ctl.txt
            # ("%f12", "!info registers", "~1", text) run now; monitor output goes to
            # scratch/hydra_ctl.out
            ctl = os.path.join(ROOT, "scratch", "hydra_ctl.txt")
            if os.path.exists(ctl):
                with open(ctl, encoding="utf-8") as f:
                    lines = [l.rstrip("\n") for l in f if l.strip()]
                os.remove(ctl)
                with open(os.path.join(ROOT, "scratch", "hydra_ctl.out"), "a", encoding="utf-8") as out:
                    for c in lines:
                        if c.startswith("!"):
                            r = qmp.cmd("human-monitor-command", {"command-line": c[1:]})
                            out.write(f"$ {c[1:]}\n{r.get('return', r)}\n")
                        elif c.startswith("%"):
                            qmp.cmd("send-key", {"keys": [{"type": "qcode", "data": c[1:]}]})
                        elif c.startswith("~"):
                            time.sleep(float(c[1:]))
                        else:
                            qmp.type(c + "\n")
            time.sleep(0.5)
        log = read_log(a.log)
        sys.stdout.write(log[start:])
        sys.stdout.write("\n")
    finally:
        if proc.poll() is not None:
            print(f"[hydra_run] QEMU exited on its own with status {proc.returncode}")
        try:
            qmp.cmd("quit")
        except Exception:
            pass
        time.sleep(1)
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    main()
