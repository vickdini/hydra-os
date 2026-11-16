"""Family & accounts: the Home face of Hydra's access control.

Accounts are Administrator, Standard or Child. For a child: screen time (allowed hours per
day), blocked apps and a web filter; for anyone: private folders. Behind the scenes these
are access rules like the ones Hydra Access Center edits (see core.compile_policy), but
nobody here sees a rule.
"""
import copy
import glob
import os
import sys

from PyQt6.QtCore import QSize, Qt, QTime
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog,
                             QDialogButtonBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout,
                             QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
                             QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QScrollArea, QSplitter,
                             QTabWidget, QTimeEdit, QVBoxLayout, QWidget)

from . import core
from .ui_common import edition_combo, error, helper, initials_icon, note, save_config, title

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def installed_apps():
    """(name, program path) of the desktop's apps."""
    out = {}
    for f in glob.glob("/usr/share/applications/*.desktop"):
        name = exe = None
        nodisplay = False
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                section = None
                for line in fh:
                    line = line.strip()
                    if line.startswith("["):
                        section = line
                    elif section == "[Desktop Entry]":
                        if line.startswith("Name=") and name is None:
                            name = line[5:]
                        elif line.startswith("Exec=") and exe is None:
                            exe = line[5:].split()[0] if line[5:].split() else None
                        elif line in ("NoDisplay=true", "Hidden=true"):
                            nodisplay = True
        except OSError:
            continue
        if not name or not exe or nodisplay:
            continue
        if not exe.startswith("/"):
            for d in ("/usr/bin", "/usr/games", "/usr/local/bin", "/bin"):
                if os.path.exists(os.path.join(d, exe)):
                    exe = os.path.join(d, exe)
                    break
            else:
                continue
        out[os.path.realpath(exe)] = name
    return sorted(((n, p) for p, n in out.items()), key=lambda x: x[0].lower())


class AddAccount(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Add an account")
        f = QFormLayout(self)
        self.full = QLineEdit()
        self.name = QLineEdit()
        self.full.textChanged.connect(lambda t: self.name.setText("".join(ch for ch in t.lower() if ch.isalnum())[:30]))
        self.typ = QComboBox()
        for t in core.ACCOUNT_TYPES:
            self.typ.addItem(core.ACCOUNT_NAMES[t], t)
        self.typ.setCurrentIndex(1)
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow("Full name:", self.full)
        f.addRow("User name:", self.name)
        f.addRow("Account type:", self.typ)
        f.addRow("Password:", self.pw)
        f.addRow("Repeat password:", self.pw2)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.check)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def check(self):
        if not self.name.text():
            return error(self, "Enter a name.")
        if self.pw.text() != self.pw2.text():
            return error(self, "The passwords do not match.")
        self.accept()


class ChildPage(QWidget):
    """Screen time, apps and web for one child."""

    def __init__(self, data, hours_only=False):
        super().__init__()
        self.data = data
        self.hours_only = hours_only
        tabs = QTabWidget()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(tabs)

        # Screen time
        st = QWidget()
        sl = QVBoxLayout(st)
        self.hours_on = QCheckBox("Limit when this child can use the computer")
        self.hours_on.setChecked(bool(data.get("hours_enabled")))
        sl.addWidget(self.hours_on)
        sl.addWidget(note("Outside these hours the child cannot sign in, and a session still open is ended. "
                          "Untick a day to block it completely."))
        grid = QGridLayout()
        self.days = []
        hours = data.get("hours", {})
        for i, d in enumerate(DAYS):
            on = QCheckBox(d)
            a, b = QTimeEdit(), QTimeEdit()
            a.setDisplayFormat("HH:mm")
            b.setDisplayFormat("HH:mm")
            h = hours.get(str(i + 1))
            on.setChecked(bool(h) or not hours)
            s, e = (h if h else [700, 2100])
            a.setTime(QTime(int(s) // 100, int(s) % 100))
            b.setTime(QTime(min(23, int(e) // 100), int(e) % 100 if int(e) < 2400 else 59))
            grid.addWidget(on, i, 0)
            grid.addWidget(QLabel("from"), i, 1)
            grid.addWidget(a, i, 2)
            grid.addWidget(QLabel("to"), i, 3)
            grid.addWidget(b, i, 4)
            self.days.append((on, a, b))
        sl.addLayout(grid)
        sl.addStretch()
        tabs.addTab(st, "Screen time" if not hours_only else "Sign-in hours")
        if hours_only:
            self.hours_on.setText("Limit when this person can sign in")
            return

        # Apps
        ap = QWidget()
        al = QVBoxLayout(ap)
        al.addWidget(note("Ticked apps cannot be started by this child."))
        self.apps = QListWidget()
        blocked = set(data.get("blocked_apps", []))
        seen = set()
        for name, path in installed_apps():
            it = QListWidgetItem("%s   (%s)" % (name, path))
            it.setData(Qt.ItemDataRole.UserRole, path)
            it.setCheckState(Qt.CheckState.Checked if path in blocked else Qt.CheckState.Unchecked)
            self.apps.addItem(it)
            seen.add(path)
        for path in sorted(blocked - seen):
            it = QListWidgetItem(path)
            it.setData(Qt.ItemDataRole.UserRole, path)
            it.setCheckState(Qt.CheckState.Checked)
            self.apps.addItem(it)
        al.addWidget(self.apps)
        more = QPushButton("Block another program…")
        more.clicked.connect(self.add_program)
        al.addWidget(more, alignment=Qt.AlignmentFlag.AlignLeft)
        tabs.addTab(ap, "Apps")

        # Web
        wb = QWidget()
        wl = QVBoxLayout(wb)
        web = data.get("web", {"mode": "off", "sites": []})
        self.web_mode = QButtonGroup(self)
        for i, (mode, text) in enumerate([("off", "No web filter"), ("block", "Block these websites"),
                                          ("allow", "Allow only these websites")]):
            rb = QRadioButton(text)
            rb.setProperty("mode", mode)
            rb.setChecked(web.get("mode", "off") == mode)
            self.web_mode.addButton(rb, i)
            wl.addWidget(rb)
        self.sites = QPlainTextEdit("\n".join(web.get("sites", [])))
        self.sites.setPlaceholderText("One website per line, e.g.\nexample.com\nvideos.example.org")
        wl.addWidget(self.sites)
        wl.addWidget(note("Applies to Firefox for this child (other people are not affected). "
                          "To keep other browsers out, block them on the Apps tab."))
        tabs.addTab(wb, "Web")

    def add_program(self):
        p, _ = QFileDialog.getOpenFileName(self, "Program to block", "/usr/bin")
        if p:
            it = QListWidgetItem(p)
            it.setData(Qt.ItemDataRole.UserRole, os.path.realpath(p))
            it.setCheckState(Qt.CheckState.Checked)
            self.apps.addItem(it)

    def collect(self):
        d = self.data
        d["hours_enabled"] = self.hours_on.isChecked()
        d["hours"] = {}
        for i, (on, a, b) in enumerate(self.days):
            if on.isChecked():
                s = a.time().hour() * 100 + a.time().minute()
                e = b.time().hour() * 100 + b.time().minute()
                if e == 2359:
                    e = 2400
                d["hours"][str(i + 1)] = [s, e]
        if self.hours_only:
            return d
        d["blocked_apps"] = [self.apps.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.apps.count())
                             if self.apps.item(i).checkState() == Qt.CheckState.Checked]
        b = self.web_mode.checkedButton()
        d["web"] = {"mode": b.property("mode") if b else "off",
                    "sites": [s.strip() for s in self.sites.toPlainText().splitlines() if s.strip()]}
        return d


class Family(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Family & accounts")
        self.resize(900, 620)
        self.cfg = core.load_config()
        self.child_page = None
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        head = QHBoxLayout()
        head.addWidget(title("Family & accounts", 18))
        head.addStretch()
        head.addWidget(QLabel("Edition:"))
        self.edition = edition_combo(self.cfg)
        self.edition.activated.connect(self.change_edition)
        head.addWidget(self.edition)
        outer.addLayout(head)
        outer.addWidget(note("Choose who can use this computer and what children can do. "
                             "Changes ask for an administrator's password."))
        split = QSplitter()
        outer.addWidget(split, 1)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.users = QListWidget()
        self.users.setIconSize(QSize(36, 36))
        self.users.setSpacing(2)
        self.users.currentRowChanged.connect(self.show_user)
        ll.addWidget(self.users)
        add = QPushButton("Add account…")
        add.clicked.connect(self.add_account)
        ll.addWidget(add)
        priv = QPushButton("Private folders…")
        priv.clicked.connect(self.private_folders)
        ll.addWidget(priv)
        split.addWidget(left)

        self.right = QScrollArea()
        self.right.setWidgetResizable(True)
        split.addWidget(self.right)
        split.setSizes([260, 640])
        self.reload_users()

    # -- accounts -----------------------------------------------------------
    def reload_users(self, select=None):
        self.cfg = core.load_config()
        self.users.blockSignals(True)
        self.users.clear()
        for name, uid, full in core.system_users():
            t = core.account_type(self.cfg, name)
            it = QListWidgetItem(initials_icon(full or name), "%s\n%s" % (full or name, core.ACCOUNT_NAMES[t]))
            it.setData(Qt.ItemDataRole.UserRole, name)
            self.users.addItem(it)
        self.users.blockSignals(False)
        row = 0
        for i in range(self.users.count()):
            if self.users.item(i).data(Qt.ItemDataRole.UserRole) == select:
                row = i
        if self.users.count():
            self.users.setCurrentRow(row)
            self.show_user(row)

    def show_user(self, row):
        if row < 0:
            return
        name = self.users.item(row).data(Qt.ItemDataRole.UserRole)
        self.current = name
        w = QWidget()
        lay = QVBoxLayout(w)
        full = [f for n, _, f in core.system_users() if n == name]
        lay.addWidget(title(full[0] if full and full[0] else name))
        lay.addWidget(note("User name: %s" % name))
        form = QFormLayout()
        self.typ = QComboBox()
        for t in core.ACCOUNT_TYPES:
            self.typ.addItem(core.ACCOUNT_NAMES[t], t)
        cur = core.account_type(self.cfg, name)
        self.typ.setCurrentIndex(core.ACCOUNT_TYPES.index(cur))
        self.typ.activated.connect(self.change_type)
        form.addRow("Account type:", self.typ)
        lay.addLayout(form)
        explain = {"admin": "Can change settings, install apps and manage other accounts.",
                   "standard": "Can use apps and change their own settings. Changes to the computer need an administrator's password.",
                   "child": "A standard account with family limits: screen time, apps and websites."}
        lay.addWidget(note(explain[cur]))
        btns = QHBoxLayout()
        pw = QPushButton("Change password…")
        pw.clicked.connect(self.change_password)
        rm = QPushButton("Remove account…")
        rm.clicked.connect(self.remove_account)
        btns.addWidget(pw)
        btns.addWidget(rm)
        btns.addStretch()
        lay.addLayout(btns)
        self.child_page = None
        if cur == "child":
            data = copy.deepcopy(self.cfg["family"]["children"].get(name) or
                                 {"hours_enabled": False, "hours": {}, "blocked_apps": [], "web": {"mode": "off", "sites": []}})
            box = QGroupBox("Family settings for %s" % name)
            bl = QVBoxLayout(box)
            self.child_page = ChildPage(data)
            bl.addWidget(self.child_page)
            lay.addWidget(box, 1)
            save = QPushButton("Apply family settings")
            save.setDefault(True)
            save.clicked.connect(self.save_child)
            lay.addWidget(save, alignment=Qt.AlignmentFlag.AlignRight)
        else:
            lay.addStretch()
        self.right.setWidget(w)

    def change_type(self):
        t = self.typ.currentData()
        if t == core.account_type(self.cfg, self.current):
            return
        if helper(self, ["usertype", self.current, t]) is not None:
            self.reload_users(self.current)
        else:
            self.reload_users(self.current)

    def save_child(self):
        data = self.child_page.collect()
        cfg = core.load_config()
        cfg["family"]["children"][self.current] = data
        cfg["users"].setdefault(self.current, {})["account"] = "child"
        if save_config(self, cfg):
            self.cfg = cfg
            QMessageBox.information(self, "Family & accounts", "Family settings for %s are on." % self.current)

    def add_account(self):
        d = AddAccount(self)
        if d.exec():
            if helper(self, ["useradd", d.name.text(), d.typ.currentData(), d.full.text()], d.pw.text() + "\n") is not None:
                self.reload_users(d.name.text())

    def change_password(self):
        pw, ok = QInputDialog.getText(self, "Change password", "New password for %s:" % self.current, QLineEdit.EchoMode.Password)
        if ok and pw:
            if helper(self, ["passwd", self.current], pw + "\n") is not None:
                QMessageBox.information(self, "Family & accounts", "The password was changed.")

    def remove_account(self):
        if QMessageBox.question(self, "Remove account", "Remove %s's account? Their files stay in /home/%s." % (self.current, self.current)) \
                == QMessageBox.StandardButton.Yes:
            if helper(self, ["userdel", self.current]) is not None:
                self.reload_users()

    def private_folders(self):
        PrivateFolders(self).exec()
        self.cfg = core.load_config()

    def change_edition(self):
        e = self.edition.currentData()
        cfg = core.load_config()
        if e == cfg.get("edition"):
            return
        cfg["edition"] = e
        if save_config(self, cfg):
            if e != "home":
                QMessageBox.information(self, "Edition", "Hydra is now %s. Hydra Access Center opens for the additional settings."
                                        % core.EDITION_NAMES[e])
                os.spawnlp(os.P_NOWAIT, "hydra-access-center", "hydra-access-center")
        else:
            self.edition.setCurrentIndex(core.EDITIONS.index(core.edition(core.load_config())))


class PrivateFolders(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Private folders")
        self.resize(560, 360)
        lay = QVBoxLayout(self)
        lay.addWidget(note("A private folder can only be opened by its owner, whatever its permissions say "
                           "(other administrators included, unless they use administrator tools)."))
        self.list = QListWidget()
        lay.addWidget(self.list)
        row = QHBoxLayout()
        add = QPushButton("Make a folder private…")
        add.clicked.connect(self.add)
        rm = QPushButton("Stop keeping it private")
        rm.clicked.connect(self.remove)
        row.addWidget(add)
        row.addWidget(rm)
        row.addStretch()
        lay.addLayout(row)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.fill()

    def fill(self):
        self.list.clear()
        for p in core.load_config()["family"]["private_folders"]:
            it = QListWidgetItem("%s   — %s" % (p["path"], p["owner"]))
            it.setData(Qt.ItemDataRole.UserRole, p["path"])
            self.list.addItem(it)

    def add(self):
        path = QFileDialog.getExistingDirectory(self, "Folder to keep private", os.path.expanduser("~"))
        if not path:
            return
        users = [u for u, _, _ in core.system_users()]
        me = os.environ.get("USER", users[0] if users else "")
        owner, ok = QInputDialog.getItem(self, "Owner", "Who may open %s?" % path, users, users.index(me) if me in users else 0, False)
        if ok and helper(self, ["private", path, owner]) is not None:
            self.fill()

    def remove(self):
        it = self.list.currentItem()
        if it and helper(self, ["private", it.data(Qt.ItemDataRole.UserRole), "-"]) is not None:
            self.fill()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Family & accounts")
    app.setDesktopFileName("hydra-family")
    w = Family()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
