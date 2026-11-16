"""Hydra Access Center: the Pro and Enterprise face of Hydra's access control, after
Windows Server's Active Directory Administrative Center + Dynamic Access Control.

Pages: Overview (edition, kernel status), Users & attributes, Resource properties (and
labelling files), Rules, Policies (and where they apply), Effective Access, Audit log,
Administrative actions; Enterprise adds App control and Compliance (managed device,
report). Rules can be staged (Enterprise): evaluated and logged, not enforced.

Edits are kept in memory until "Apply changes", which saves through the root helper
(an administrator's password, once per few minutes).
"""
import copy
import json
import os
import sys
import time

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                             QFileDialog, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog,
                             QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
                             QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QStackedWidget, QTableWidget,
                             QTableWidgetItem, QTextBrowser, QToolBar, QVBoxLayout, QWidget)

from . import core
from .ui_common import (CondList, edition_combo, error, helper, note, operand_choices, save_config, title,
                        values_for)


def is_ent(cfg):
    return core.edition(cfg) == "enterprise"


class Page(QWidget):
    name = ""

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.lay = QVBoxLayout(self)
        self.lay.addWidget(title(self.name))

    @property
    def cfg(self):
        return self.win.cfg

    def refresh(self):
        pass

    def changed(self):
        self.win.set_dirty()


# ---------------------------------------------------------------------------
class Overview(Page):
    name = "Overview"

    def __init__(self, win):
        super().__init__(win)
        form = QFormLayout()
        self.edition = edition_combo(self.cfg)
        self.edition.activated.connect(self.set_edition)
        form.addRow("Edition:", self.edition)
        self.lay.addLayout(form)
        self.ed_note = note("")
        self.lay.addWidget(self.ed_note)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lay.addWidget(self.status)
        self.lay.addStretch()

    def set_edition(self):
        self.cfg["edition"] = self.edition.currentData()
        self.changed()
        self.win.rebuild_nav()
        self.refresh()

    def refresh(self):
        self.edition.setCurrentIndex(core.EDITIONS.index(core.edition(self.cfg)))
        self.ed_note.setText({
            "home": "Home: accounts, family limits and private folders (the Family & accounts app). "
                    "Choose Pro to classify files and write access rules.",
            "pro": "Pro: user attributes, resource properties, rules and policies applied to folders, effective access, "
                   "audit, and rules for administrative actions.",
            "enterprise": "Enterprise: everything in Pro, plus conditions on time, device and session, staged rules, "
                          "app control and a compliance report.",
        }[core.edition(self.cfg)])
        try:
            st = core.status()
            k = ("The kernel enforces policy generation %s: %s rule(s), %s app rule(s). "
                 "%s decisions answered from the cache, %s evaluated." % (st.get("generation"), st.get("rules"), st.get("app_rules"),
                                                                           st.get("hits"), st.get("misses")))
        except OSError as e:
            k = "The kernel does not answer access-control calls (%s)." % e
        c = self.cfg
        self.status.setText("<b>Configuration</b>: %d user attribute(s), %d resource propert(ies), %d rule(s), %d polic(ies), "
                            "applied to %d folder(s), %d app rule(s), %d administrative rule(s).<br><br><b>Enforcement</b>: %s"
                            % (len(c["user_attributes"]), len(c["properties"]), len(c["rules"]), len(c["policies"]), len(c["applied"]),
                               len(c["apps"]), len(c["admin_rules"]), k))


# ---------------------------------------------------------------------------
class Users(Page):
    name = "Users & attributes"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("Each user's attributes go with everything they run after they next sign in. "
                                "Account types are managed in Family & accounts."))
        self.table = QTableWidget()
        self.table.verticalHeader().hide()
        self.lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        attrs = QPushButton("Edit attribute list…")
        attrs.clicked.connect(self.edit_attrs)
        row.addWidget(attrs)
        self.hours = QPushButton("Sign-in hours…")
        self.hours.clicked.connect(self.edit_hours)
        row.addWidget(self.hours)
        row.addStretch()
        self.lay.addLayout(row)

    def refresh(self):
        self.hours.setVisible(is_ent(self.cfg))
        users = core.system_users()
        attrs = self.cfg["user_attributes"]
        self.table.blockSignals(True)
        self.table.clear()
        self.table.setColumnCount(2 + len(attrs))
        self.table.setHorizontalHeaderLabels(["User", "Account"] + [a.get("display", a["name"]) for a in attrs])
        self.table.setRowCount(len(users))
        for r, (name, uid, full) in enumerate(users):
            it = QTableWidgetItem("%s (%s)" % (full or name, name) if full and full != name else name)
            it.setFlags(Qt.ItemFlag.ItemIsEnabled)
            it.setData(Qt.ItemDataRole.UserRole, name)
            self.table.setItem(r, 0, it)
            it = QTableWidgetItem(core.ACCOUNT_NAMES[core.account_type(self.cfg, name)])
            it.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(r, 1, it)
            u = self.cfg["users"].get(name, {})
            for c, a in enumerate(attrs):
                v = u.get(a["name"], [] if a.get("multi") else "")
                if a.get("multi"):
                    btn = QPushButton(", ".join(v) or "(none)")
                    btn.setFlat(True)
                    btn.clicked.connect(lambda _=False, n=name, at=a, b=None: self.edit_multi(n, at))
                    self.table.setCellWidget(r, 2 + c, btn)
                else:
                    cb = QComboBox()
                    cb.addItem("(none)", "")
                    for val in core.user_attr_values(self.cfg, a):
                        cb.addItem(val, val)
                    if v and cb.findData(v) < 0:
                        cb.addItem(v, v)
                    cb.setCurrentIndex(max(0, cb.findData(v)))
                    cb.activated.connect(lambda _=0, n=name, at=a, w=cb: self.set_attr(n, at, w.currentData()))
                    self.table.setCellWidget(r, 2 + c, cb)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.blockSignals(False)

    def set_attr(self, name, a, value):
        u = self.cfg["users"].setdefault(name, {})
        if value:
            u[a["name"]] = value
        else:
            u.pop(a["name"], None)
        self.changed()

    def edit_multi(self, name, a):
        u = self.cfg["users"].setdefault(name, {})
        d = QDialog(self)
        d.setWindowTitle("%s: %s" % (name, a.get("display", a["name"])))
        lay = QVBoxLayout(d)
        lst = QListWidget()
        cur = set(u.get(a["name"], []))
        for v in sorted(set(core.user_attr_values(self.cfg, a)) | cur):
            it = QListWidgetItem(v)
            it.setCheckState(Qt.CheckState.Checked if v in cur else Qt.CheckState.Unchecked)
            lst.addItem(it)
        lay.addWidget(lst)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        if d.exec():
            u[a["name"]] = [lst.item(i).text() for i in range(lst.count()) if lst.item(i).checkState() == Qt.CheckState.Checked]
            self.changed()
            self.refresh()

    def edit_attrs(self):
        d = AttrListDialog(self, self.cfg)
        if d.exec():
            self.cfg["user_attributes"] = d.result_list
            self.changed()
            self.refresh()

    def edit_hours(self):
        r = self.table.currentRow()
        if r < 0:
            return error(self, "Select a user first.")
        name = self.table.item(r, 0).data(Qt.ItemDataRole.UserRole)
        from .family import ChildPage
        u = self.cfg["users"].setdefault(name, {})
        d = QDialog(self)
        d.setWindowTitle("Sign-in hours for %s" % name)
        lay = QVBoxLayout(d)
        page = ChildPage({"hours_enabled": u.get("hours_enabled", False), "hours": u.get("hours", {})})
        # Only the hours tab applies to adults
        tabs = page.findChild(QWidget, None)
        lay.addWidget(page)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        if d.exec():
            data = page.collect()
            u["hours_enabled"], u["hours"] = data["hours_enabled"], data["hours"]
            self.changed()


class AttrListDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.setWindowTitle("User attributes")
        self.resize(560, 380)
        self.cfg = cfg
        lay = QVBoxLayout(self)
        lay.addWidget(note("Name, values (one per line), or 'values from' a resource property (so a user's clearance "
                           "uses the classification levels)."))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Name", "Shown as", "Values from property", "Values (comma separated)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for a in cfg["user_attributes"]:
            self.add_row(a)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        add = QPushButton("Add")
        add.clicked.connect(lambda: self.add_row({"name": "", "display": ""}))
        rm = QPushButton("Remove")
        rm.clicked.connect(lambda: self.table.removeRow(self.table.currentRow()))
        row.addWidget(add)
        row.addWidget(rm)
        row.addStretch()
        lay.addLayout(row)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def add_row(self, a):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(a.get("name", "")))
        self.table.setItem(r, 1, QTableWidgetItem(a.get("display", "")))
        cb = QComboBox()
        cb.addItem("(own values)", "")
        for p in self.cfg["properties"]:
            cb.addItem(p.get("display", p["name"]), p["name"])
        cb.setCurrentIndex(max(0, cb.findData(a.get("values_from", ""))))
        self.table.setCellWidget(r, 2, cb)
        self.table.setItem(r, 3, QTableWidgetItem(", ".join(a.get("values", []))))
        self.table.item(r, 0).setData(Qt.ItemDataRole.UserRole, a.get("multi", False))

    def ok(self):
        out = []
        for r in range(self.table.rowCount()):
            name = (self.table.item(r, 0).text() if self.table.item(r, 0) else "").strip().lower()
            if not name:
                continue
            a = {"name": name, "display": (self.table.item(r, 1).text() if self.table.item(r, 1) else "") or name}
            src = self.table.cellWidget(r, 2).currentData()
            if src:
                a["values_from"] = src
            else:
                a["values"] = [v.strip() for v in (self.table.item(r, 3).text() if self.table.item(r, 3) else "").split(",") if v.strip()]
            if self.table.item(r, 0).data(Qt.ItemDataRole.UserRole):
                a["multi"] = True
            out.append(a)
        self.result_list = out
        self.accept()


# ---------------------------------------------------------------------------
class Properties(Page):
    name = "Resource properties"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("Properties describe files and folders (like Windows' resource properties). Ordered "
                                "properties have levels: a rule can say 'clearance is at least classification'."))
        split = QSplitter()
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self.show)
        split.addWidget(self.list)
        ed = QWidget()
        f = QFormLayout(ed)
        self.pname = QLineEdit()
        self.pdisp = QLineEdit()
        self.pord = QCheckBox("Values are ordered levels (lowest first)")
        self.pmulti = QCheckBox("A file may have several values")
        self.pvals = QPlainTextEdit()
        f.addRow("Name:", self.pname)
        f.addRow("Shown as:", self.pdisp)
        f.addRow("", self.pord)
        f.addRow("", self.pmulti)
        f.addRow("Values (one per line):", self.pvals)
        for w in (self.pname, self.pdisp):
            w.editingFinished.connect(self.store)
        self.pord.toggled.connect(self.store)
        self.pmulti.toggled.connect(self.store)
        self.pvals.textChanged.connect(self.store)
        split.addWidget(ed)
        self.lay.addWidget(split, 1)
        row = QHBoxLayout()
        for text, fn in (("Add property", self.add), ("Remove property", self.remove), ("Classify files or folders…", self.classify)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        self.lay.addLayout(row)
        self.cur = -1

    def refresh(self):
        self.list.blockSignals(True)
        self.list.clear()
        for p in self.cfg["properties"]:
            self.list.addItem(p.get("display", p["name"]))
        self.list.blockSignals(False)
        if self.cfg["properties"]:
            self.list.setCurrentRow(max(0, min(self.cur, len(self.cfg["properties"]) - 1)))
            self.show(self.list.currentRow())

    def show(self, i):
        self.cur = -1
        if i < 0 or i >= len(self.cfg["properties"]):
            return
        p = self.cfg["properties"][i]
        for w, v in ((self.pname, p["name"]), (self.pdisp, p.get("display", ""))):
            w.setText(v)
        self.pord.setChecked(bool(p.get("ordered")))
        self.pmulti.setChecked(bool(p.get("multi")))
        self.pvals.setPlainText("\n".join(p.get("values", [])))
        self.cur = i

    def store(self):
        if self.cur < 0:
            return
        p = self.cfg["properties"][self.cur]
        p["name"] = self.pname.text().strip().lower()
        p["display"] = self.pdisp.text().strip() or p["name"]
        p["ordered"] = self.pord.isChecked()
        p["multi"] = self.pmulti.isChecked()
        p["values"] = [v.strip() for v in self.pvals.toPlainText().splitlines() if v.strip()]
        self.list.item(self.cur).setText(p["display"])
        self.changed()

    def add(self):
        name, ok = QInputDialog.getText(self, "New property", "Name (lower case, e.g. confidentiality):")
        if ok and name.strip():
            self.cfg["properties"].append({"name": name.strip().lower(), "display": name.strip().capitalize(), "values": [], "ordered": False})
            self.changed()
            self.cur = len(self.cfg["properties"]) - 1
            self.refresh()

    def remove(self):
        if 0 <= self.cur < len(self.cfg["properties"]):
            del self.cfg["properties"][self.cur]
            self.changed()
            self.refresh()

    def classify(self):
        ClassifyDialog(self, self.cfg).exec()


class ClassifyDialog(QDialog):
    """Sets labels on a file or folder (the Classification tab of Windows' file properties)."""

    def __init__(self, parent, cfg, path=None):
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("Classification")
        self.resize(520, 0)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.path = QLineEdit(path or "")
        row.addWidget(self.path)
        for text, folder in (("File…", False), ("Folder…", True)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, f=folder: self.browse(f))
            row.addWidget(b)
        lay.addLayout(row)
        self.form = QFormLayout()
        lay.addLayout(self.form)
        self.combos = {}
        for p in cfg["properties"]:
            cb = QComboBox()
            cb.setEditable(bool(p.get("multi")))
            cb.addItem("(not set)", None)
            for v in p.get("values", []):
                cb.addItem(v, v)
            self.form.addRow(p.get("display", p["name"]) + ":", cb)
            self.combos[p["name"]] = cb
        self.recursive = QCheckBox("Also everything already inside the folder (new files get the folder's labels anyway)")
        lay.addWidget(self.recursive)
        self.current = note("")
        lay.addWidget(self.current)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Close)
        bb.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.apply)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.path.editingFinished.connect(self.load)
        self.load()

    def browse(self, folder):
        p = QFileDialog.getExistingDirectory(self, "Folder") if folder else QFileDialog.getOpenFileName(self, "File")[0]
        if p:
            self.path.setText(p)
            self.load()

    def load(self):
        p = self.path.text()
        if not p or not os.path.exists(p):
            self.current.setText("")
            return
        lab = core.get_labels(p)
        for name, cb in self.combos.items():
            v = lab.get(name, [])
            txt = ",".join(v)
            i = cb.findData(v[0]) if len(v) == 1 else -1
            if i >= 0:
                cb.setCurrentIndex(i)
            elif v:
                cb.setEditable(True)
                cb.setEditText(txt)
            else:
                cb.setCurrentIndex(0)
        other = {k: v for k, v in lab.items() if k not in self.combos}
        self.current.setText("Other labels: " + ", ".join("%s=%s" % (k, ",".join(v)) for k, v in other.items()) if other else "")
        self.recursive.setVisible(os.path.isdir(p))

    def apply(self):
        p = self.path.text()
        if not os.path.exists(p):
            return error(self, "Choose a file or folder.")
        set_, remove = {}, []
        for name, cb in self.combos.items():
            txt = cb.currentText()
            if cb.currentIndex() == 0 and cb.currentData() is None and txt in ("(not set)", ""):
                remove.append(name)
            else:
                set_[name] = [x.strip() for x in txt.split(",") if x.strip()]
        args = ["label", p] + (["-r"] if self.recursive.isChecked() and os.path.isdir(p) else [])
        if helper(self, args, json.dumps({"set": set_, "remove": remove})) is not None:
            self.load()


# ---------------------------------------------------------------------------
class RuleEditor(QDialog):
    def __init__(self, parent, cfg, rule):
        super().__init__(parent)
        self.cfg, self.rule = cfg, copy.deepcopy(rule)
        ent = is_ent(cfg)
        self.setWindowTitle("Rule")
        self.resize(820, 600)
        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        f = QFormLayout()
        self.name = QLineEdit(rule.get("name", ""))
        self.desc = QLineEdit(rule.get("description", ""))
        f.addRow("Name:", self.name)
        f.addRow("Description:", self.desc)
        self.staged = QCheckBox("Staged: evaluate and log only (do not enforce)")
        self.staged.setChecked(bool(rule.get("staged")))
        self.staged.setVisible(ent)
        f.addRow("", self.staged)
        self.replaces = QComboBox()
        self.replaces.addItem("(nothing)", "")
        for r in cfg["rules"]:
            if r.get("name") != rule.get("name"):
                self.replaces.addItem(r["name"], r["name"])
        self.replaces.setCurrentIndex(max(0, self.replaces.findData(rule.get("replaces") or "")))
        if ent:
            f.addRow("Proposed replacement for:", self.replaces)
        lay.addLayout(f)
        box = QGroupBox("Applies to files and folders where")
        bl = QVBoxLayout(box)
        self.target = CondList(cfg, operand_choices(cfg, ("res", "user"), ent), rule.get("target"), ent, "All files and folders of the policy")
        bl.addWidget(self.target)
        lay.addWidget(box)
        self.entries_box = QGroupBox("Permissions (each line grants its actions when all its conditions hold)")
        self.el = QVBoxLayout(self.entries_box)
        self.entries = []
        for e in rule.get("entries", []):
            self.add_entry(e)
        add = QPushButton("Add permission")
        add.clicked.connect(lambda: self.add_entry({"actions": "r", "when": []}))
        self.el.addWidget(add, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.entries_box)
        lay.addWidget(note("Access needs both: the usual permissions (owner, group, ACLs) and every rule of the "
                           "policy that applies. Rules can only take rights away."))
        lay.addStretch()
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.ok)
        bb.rejected.connect(self.reject)
        outer.addWidget(bb)

    def add_entry(self, e):
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        fl = QVBoxLayout(frame)
        row = QHBoxLayout()
        row.addWidget(QLabel("Allow"))
        checks = {}
        for ch, word in core.ACTIONS:
            c = QCheckBox(word)
            c.setChecked(ch in e.get("actions", ""))
            row.addWidget(c)
            checks[ch] = c
        row.addStretch()
        rm = QPushButton("Remove")
        row.addWidget(rm)
        fl.addLayout(row)
        fl.addWidget(QLabel("when:"))
        ent = is_ent(self.cfg)
        cl = CondList(self.cfg, operand_choices(self.cfg, ("user", "res"), ent), e.get("when"), ent, "Always (everyone)")
        fl.addWidget(cl)
        entry = (frame, checks, cl)
        rm.clicked.connect(lambda: (self.entries.remove(entry), frame.setParent(None)))
        self.el.insertWidget(len(self.entries), frame)
        self.entries.append(entry)

    def ok(self):
        name = self.name.text().strip()
        if not core.NAME_RE.match(name):
            return error(self, "Give the rule a name (letters, digits, spaces, . _ - ( )).")
        if any(r["name"] == name for r in self.cfg["rules"]) and name != self.rule.get("name"):
            return error(self, "Another rule has this name.")
        self.rule.update({
            "name": name,
            "description": self.desc.text(),
            "staged": self.staged.isChecked() and is_ent(self.cfg),
            "replaces": self.replaces.currentData() or None,
            "target": self.target.get(),
            "entries": [{"actions": "".join(ch for ch, c in checks.items() if c.isChecked()), "when": cl.get()}
                        for _, checks, cl in self.entries],
        })
        self.accept()


class Rules(Page):
    name = "Rules"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("A rule says who may do what to the files it applies to. Rules take effect "
                                "when a policy that contains them is applied to a folder."))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Rule", "Applies to", "Permissions", "Mode"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.doubleClicked.connect(self.edit)
        self.lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        for text, fn in (("New rule…", self.new), ("Edit…", self.edit), ("Remove", self.remove), ("Example rule", self.example)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        self.lay.addLayout(row)

    def refresh(self):
        rules = self.cfg["rules"]
        self.table.setRowCount(len(rules))
        for i, r in enumerate(rules):
            perms = "; ".join("%s if %s" % ("/".join(w for ch, w in core.ACTIONS if ch in e.get("actions", "")) or "nothing",
                                            core.describe_conds(e.get("when"))) for e in r.get("entries", [])) or "nothing"
            mode = "staged" if r.get("staged") else "enforced"
            if r.get("replaces"):
                mode += " (replaces %s)" % r["replaces"]
            for c, t in enumerate([r["name"], core.describe_conds(r.get("target")) if r.get("target") else "all files", perms, mode]):
                it = QTableWidgetItem(t)
                it.setToolTip(t)
                self.table.setItem(i, c, it)
        self.table.resizeRowsToContents()

    def new(self):
        d = RuleEditor(self, self.cfg, {"name": "", "entries": [{"actions": "rx", "when": []}]})
        if d.exec():
            self.cfg["rules"].append(d.rule)
            self.changed()
            self.refresh()

    def edit(self):
        i = self.table.currentRow()
        if i < 0:
            return
        old = self.cfg["rules"][i]
        d = RuleEditor(self, self.cfg, old)
        if d.exec():
            if d.rule["name"] != old["name"]:
                for p in self.cfg["policies"]:
                    p["rules"] = [d.rule["name"] if x == old["name"] else x for x in p.get("rules", [])]
            self.cfg["rules"][i] = d.rule
            self.changed()
            self.refresh()

    def remove(self):
        i = self.table.currentRow()
        if i >= 0:
            name = self.cfg["rules"].pop(i)["name"]
            for p in self.cfg["policies"]:
                p["rules"] = [x for x in p.get("rules", []) if x != name]
            self.changed()
            self.refresh()

    def example(self):
        r = {"name": "Department and clearance", "description": "Same department; clearance at least the file's classification",
             "target": [], "entries": [
                 {"actions": "rwxd", "when": [{"left": "user.department", "op": "==", "right": "res.department"},
                                              {"left": "user.clearance", "op": ">=", "right": "res.classification"}]},
                 {"actions": "rx", "when": [{"left": "user.role", "op": "==", "right": {"value": "Auditor"}}]}]}
        n, k = r["name"], 2
        while any(x["name"] == r["name"] for x in self.cfg["rules"]):
            r["name"] = "%s %d" % (n, k)
            k += 1
        self.cfg["rules"].append(r)
        self.changed()
        self.refresh()


# ---------------------------------------------------------------------------
class Policies(Page):
    name = "Policies"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("A policy groups rules. Apply it to folders: they and everything in them (new files too) "
                                "are then protected by its rules. A policy for 'all labelled files' applies wherever a file "
                                "has classification labels."))
        split = QSplitter()
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self.show)
        split.addWidget(self.list)
        ed = QWidget()
        el = QVBoxLayout(ed)
        f = QFormLayout()
        self.pname = QLineEdit()
        self.pname.editingFinished.connect(self.store)
        self.pdesc = QLineEdit()
        self.pdesc.editingFinished.connect(self.store)
        self.pglobal = QCheckBox("Applies to all labelled files (no folder needed)")
        self.pglobal.toggled.connect(self.store)
        self.pstaged = QCheckBox("Staged: evaluate and log only")
        self.pstaged.toggled.connect(self.store)
        f.addRow("Name:", self.pname)
        f.addRow("Description:", self.pdesc)
        f.addRow("", self.pglobal)
        f.addRow("", self.pstaged)
        el.addLayout(f)
        el.addWidget(QLabel("Rules in this policy:"))
        self.rules = QListWidget()
        self.rules.itemChanged.connect(self.store)
        el.addWidget(self.rules, 1)
        el.addWidget(QLabel("Applied to:"))
        self.applied = QListWidget()
        el.addWidget(self.applied)
        row = QHBoxLayout()
        ap = QPushButton("Apply to a folder…")
        ap.clicked.connect(self.apply_folder)
        un = QPushButton("Remove from folder")
        un.clicked.connect(self.unapply_folder)
        row.addWidget(ap)
        row.addWidget(un)
        row.addStretch()
        el.addLayout(row)
        split.addWidget(ed)
        split.setSizes([220, 600])
        self.lay.addWidget(split, 1)
        row = QHBoxLayout()
        for text, fn in (("New policy", self.new), ("Remove policy", self.remove)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        self.lay.addLayout(row)
        self.cur = -1

    def refresh(self):
        self.pstaged.setVisible(is_ent(self.cfg))
        self.list.blockSignals(True)
        self.list.clear()
        for p in self.cfg["policies"]:
            self.list.addItem(p["name"])
        self.list.blockSignals(False)
        if self.cfg["policies"]:
            self.list.setCurrentRow(max(0, min(self.cur, len(self.cfg["policies"]) - 1)))
            self.show(self.list.currentRow())

    def show(self, i):
        self.cur = -1
        if i < 0 or i >= len(self.cfg["policies"]):
            return
        p = self.cfg["policies"][i]
        self.pname.setText(p["name"])
        self.pdesc.setText(p.get("description", ""))
        self.pglobal.setChecked(bool(p.get("global")))
        self.pstaged.setChecked(bool(p.get("staged")))
        self.rules.blockSignals(True)
        self.rules.clear()
        for r in self.cfg["rules"]:
            it = QListWidgetItem(r["name"])
            it.setCheckState(Qt.CheckState.Checked if r["name"] in p.get("rules", []) else Qt.CheckState.Unchecked)
            self.rules.addItem(it)
        self.rules.blockSignals(False)
        self.applied.clear()
        for a in self.cfg["applied"]:
            if a["policy"] == p["name"]:
                self.applied.addItem(a["path"])
        self.cur = i

    def store(self, *_):
        if self.cur < 0:
            return
        p = self.cfg["policies"][self.cur]
        new = self.pname.text().strip()
        if new and new != p["name"]:
            if any(a["policy"] == p["name"] for a in self.cfg["applied"]):
                error(self, "This policy is applied to folders; remove it from them before renaming it.")
                self.pname.setText(p["name"])
            else:
                p["name"] = new
                self.list.item(self.cur).setText(new)
        p["description"] = self.pdesc.text()
        p["global"] = self.pglobal.isChecked()
        p["staged"] = self.pstaged.isChecked() and is_ent(self.cfg)
        p["rules"] = [self.rules.item(i).text() for i in range(self.rules.count()) if self.rules.item(i).checkState() == Qt.CheckState.Checked]
        self.changed()

    def new(self):
        name, ok = QInputDialog.getText(self, "New policy", "Policy name:")
        if ok and core.NAME_RE.match(name.strip() or "-") and not any(p["name"] == name.strip() for p in self.cfg["policies"]):
            self.cfg["policies"].append({"name": name.strip(), "rules": [r["name"] for r in self.cfg["rules"][:1]]})
            self.cur = len(self.cfg["policies"]) - 1
            self.changed()
            self.refresh()

    def remove(self):
        if 0 <= self.cur < len(self.cfg["policies"]):
            p = self.cfg["policies"][self.cur]
            if any(a["policy"] == p["name"] for a in self.cfg["applied"]):
                return error(self, "Remove the policy from its folders first.")
            del self.cfg["policies"][self.cur]
            self.changed()
            self.refresh()

    def apply_folder(self):
        if self.cur < 0:
            return
        if self.win.dirty and not self.win.apply():
            return
        p = self.cfg["policies"][self.cur]["name"]
        path = QFileDialog.getExistingDirectory(self, "Apply '%s' to folder" % p, "/home")
        if path and helper(self, ["apply", path, p]) is not None:
            self.win.reload()

    def unapply_folder(self):
        it = self.applied.currentItem()
        if self.cur < 0 or not it:
            return
        if helper(self, ["unapply", it.text(), self.cfg["policies"][self.cur]["name"]]) is not None:
            self.win.reload()


# ---------------------------------------------------------------------------
class Effective(Page):
    name = "Effective Access"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("Pick a user and a file or folder: what may they do, and which rule decides? "
                                "(The kernel answers with the policy it enforces.)"))
        f = QFormLayout()
        self.user = QComboBox()
        f.addRow("User:", self.user)
        row = QHBoxLayout()
        self.path = QLineEdit()
        b1 = QPushButton("File…")
        b1.clicked.connect(lambda: self.browse(False))
        b2 = QPushButton("Folder…")
        b2.clicked.connect(lambda: self.browse(True))
        row.addWidget(self.path)
        row.addWidget(b1)
        row.addWidget(b2)
        f.addRow("File or folder:", row)
        self.when = QLineEdit()
        self.when.setPlaceholderText("now (or e.g. weekday=6 time=2230)")
        self.when_label = QLabel("At:")
        f.addRow(self.when_label, self.when)
        self.lay.addLayout(f)
        go = QPushButton("Check access")
        go.setDefault(True)
        go.clicked.connect(self.check)
        self.lay.addWidget(go, alignment=Qt.AlignmentFlag.AlignLeft)
        self.out = QTextBrowser()
        self.lay.addWidget(self.out, 1)

    def refresh(self):
        cur = self.user.currentText()
        self.user.clear()
        for name, _, full in core.system_users():
            self.user.addItem(name)
        if cur:
            self.user.setCurrentText(cur)
        ent = is_ent(self.cfg)
        self.when.setVisible(ent)
        self.when_label.setVisible(ent)

    def set_path(self, p):
        self.path.setText(p)

    def browse(self, folder):
        p = QFileDialog.getExistingDirectory(self, "Folder") if folder else QFileDialog.getOpenFileName(self, "File")[0]
        if p:
            self.path.setText(p)

    def check(self):
        user, path = self.user.currentText(), self.path.text()
        if not user or not os.path.exists(path):
            return error(self, "Choose a user and an existing file or folder.")
        env = "\n".join(x for x in self.when.text().split() if "=" in x)
        exe = os.path.isfile(path) and os.access(path, os.X_OK)
        if exe and is_ent(self.cfg):
            env += "\nexec=" + os.path.realpath(path)
        try:
            r = core.effective_access(self.win.saved_cfg, user, path, env)
        except OSError as e:
            return self.out.setHtml("<p>The kernel could not answer: %s</p>" % e)
        pol = r["policy"]
        isdir = os.path.isdir(path)
        names = dict(core.ACTIONS)
        if isdir:
            names["x"] = "Open folder"

        def words(s):
            return ", ".join(names[c] for c in "rwxd" if c in s) or "nothing"
        unix = r["unix"] + ("d" if "w" in core.unix_allows(os.path.dirname(path) or "/", user) else "")
        enforced = pol.get("enforced", "rwxd").replace("-", "")
        if isdir and "r" in enforced:
            enforced += "x"
        eff = "".join(c for c in "rwxd" if c in unix and c in enforced)
        h = ["<h3>%s may: %s</h3>" % (user, words(eff))]
        h.append("<p><b>Usual permissions</b> (owner, group, others) allow: %s</p>" % words(unix))
        if pol.get("covered") == "1":
            h.append("<p><b>Access policy</b> allows: %s" % words(enforced))
            if pol.get("rule", "-") != "-" and enforced != "rwxd":
                h.append(" &mdash; limited by rule <b>%s</b> of policy <b>%s</b>" % (pol["rule"], pol.get("policy", "?")))
            h.append("</p>")
            if pol.get("proposed") != pol.get("enforced"):
                h.append("<p><b>Staged rules</b> would allow: %s (rule %s)</p>" % (words(pol.get("proposed", "").replace("-", "")), pol.get("would_rule", "-")))
        else:
            h.append("<p>No access policy covers this %s.</p>" % ("folder" if isdir else "file"))
        if "app" in pol:
            h.append("<p><b>App control</b>: the program %s for %s%s.</p>" % ("may run" if pol["app"] == "allow" else "is blocked", user,
                                                                             (" (rule %s)" % pol["app_rule"]) if pol.get("app_rule", "-") != "-" else ""))
        labs = r["labels"]
        h.append("<p><b>Labels</b>: %s</p>" % (", ".join("%s = %s" % (k, ", ".join(v)) for k, v in labs.items()) or "none"))
        h.append("<p style='color:gray'>User attributes: %s</p>" % core.subject_text(self.win.saved_cfg, user).replace("\n", "; "))
        if self.win.dirty:
            h.append("<p style='color:#b60'>You have changes that are not applied yet; this answer uses the applied policy.</p>")
        self.out.setHtml("".join(h))


# ---------------------------------------------------------------------------
class Audit(Page):
    name = "Audit log"

    def __init__(self, win):
        super().__init__(win)
        row = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter (user, file, rule)…")
        self.filter.textChanged.connect(self.fill)
        self.staged = QCheckBox("Staged rules only")
        self.staged.toggled.connect(self.fill)
        ref = QPushButton("Refresh")
        ref.clicked.connect(lambda: self.refresh(drain=True))
        row.addWidget(self.filter, 1)
        row.addWidget(self.staged)
        row.addWidget(ref)
        self.lay.addLayout(row)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Event", "User", "Program", "File or program", "Rule (policy)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.lay.addWidget(self.table, 1)
        self.info = note("")
        self.lay.addWidget(self.info)
        self.recs = []

    def refresh(self, drain=False):
        if drain:
            helper(self, ["audit"])
        recs = core.read_log()
        if recs is None:
            self.info.setText("The log (%s) is readable by administrators only." % core.LOG)
            recs = []
        else:
            self.info.setText("%d event(s). Denials and staged-rule differences are recorded; repeated events are counted." % len(recs))
        self.recs = recs
        self.fill()

    def fill(self):
        f = self.filter.text().lower()
        rows = [r for r in reversed(self.recs) if (not self.staged.isChecked() or "staged" in r["kind"])
                and (not f or f in json.dumps(r).lower())][:2000]
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["time"])),
                    core.KIND_WORDS.get(r["kind"], r["kind"]) + ("" if r.get("count", "1") == "1" else " ×%s" % r["count"]),
                    r["user"], r.get("exe", ""), r.get("path", "(inode %s)" % r.get("ino", "?")),
                    "%s (%s)" % (r.get("rule", "-"), r.get("policy", "-"))]
            for c, v in enumerate(vals):
                self.table.setItem(i, c, QTableWidgetItem(v))


# ---------------------------------------------------------------------------
class AdminActions(Page):
    name = "Administrative actions"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("Who may perform administrative tasks at all. When a rule here says no, the "
                                "password dialog does not even appear. Without a rule, the usual rules apply "
                                "(administrators are asked for their password)."))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Task", "Allowed when", "Mode"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.doubleClicked.connect(self.edit)
        self.lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        for text, fn in (("Add…", self.add), ("Edit…", self.edit), ("Remove", self.remove)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        self.lay.addLayout(row)

    def refresh(self):
        rs = self.cfg["admin_rules"]
        self.table.setRowCount(len(rs))
        cats = dict(core.ADMIN_CATEGORIES)
        for i, a in enumerate(rs):
            for c, v in enumerate([cats.get(a["category"], a["category"]), core.describe_conds(a.get("when")), "staged" if a.get("staged") else "enforced"]):
                self.table.setItem(i, c, QTableWidgetItem(v))

    def dialog(self, a):
        d = QDialog(self)
        d.setWindowTitle("Administrative task rule")
        d.resize(700, 300)
        lay = QVBoxLayout(d)
        f = QFormLayout()
        cat = QComboBox()
        for k, w in core.ADMIN_CATEGORIES:
            cat.addItem(w, k)
        cat.setCurrentIndex(max(0, cat.findData(a.get("category"))))
        f.addRow("Task:", cat)
        staged = QCheckBox("Staged (log only)")
        staged.setChecked(bool(a.get("staged")))
        staged.setVisible(is_ent(self.cfg))
        f.addRow("", staged)
        lay.addLayout(f)
        lay.addWidget(QLabel("Allowed only when:"))
        cl = CondList(self.cfg, operand_choices(self.cfg, ("user",), is_ent(self.cfg)), a.get("when"), is_ent(self.cfg), "Always")
        lay.addWidget(cl)
        lay.addStretch()
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        if d.exec():
            return {"name": "%s-%d" % (cat.currentData(), int(time.time()) % 100000), "category": cat.currentData(),
                    "when": cl.get(), "staged": staged.isChecked() and is_ent(self.cfg)}
        return None

    def add(self):
        a = self.dialog({"category": "software", "when": [{"left": "user.role", "op": "==", "right": {"value": "IT"}}]})
        if a:
            self.cfg["admin_rules"].append(a)
            self.changed()
            self.refresh()

    def edit(self):
        i = self.table.currentRow()
        if i >= 0:
            a = self.dialog(self.cfg["admin_rules"][i])
            if a:
                a["name"] = self.cfg["admin_rules"][i].get("name", a["name"])
                self.cfg["admin_rules"][i] = a
                self.changed()
                self.refresh()

    def remove(self):
        i = self.table.currentRow()
        if i >= 0:
            del self.cfg["admin_rules"][i]
            self.changed()
            self.refresh()


# ---------------------------------------------------------------------------
class Apps(Page):
    name = "App control"

    def __init__(self, win):
        super().__init__(win)
        self.lay.addWidget(note("Decide which programs may run. A 'block' rule stops a program for the users it applies to. "
                                "'Allow' rules turn on an allow list for their users: only matching programs run "
                                "(\"installed by the administrator\" = system programs that ordinary users cannot change)."))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Rule", "Action", "Programs", "For", "Mode"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.doubleClicked.connect(self.edit)
        self.lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        for text, fn in (("Add…", self.add), ("Edit…", self.edit), ("Remove", self.remove),
                         ("Allow-list preset", self.preset)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        self.lay.addLayout(row)

    KINDS = [("path", "Program file or folder (ends with /)"), ("name", "Program name"), ("hash", "File hash (SHA-256)"),
             ("trusted", "Installed by the administrator")]

    def refresh(self):
        rs = self.cfg["apps"]
        self.table.setRowCount(len(rs))
        kinds = dict(self.KINDS)
        for i, a in enumerate(rs):
            what = kinds.get(a.get("match"), a.get("match")) + ("" if a.get("match") == "trusted" else ": " + a.get("pattern", ""))
            for c, v in enumerate([a.get("name", ""), "Block" if a.get("action") == "deny" else "Allow", what,
                                   core.describe_conds(a.get("who")) if a.get("who") else "everyone", "staged" if a.get("staged") else "enforced"]):
                self.table.setItem(i, c, QTableWidgetItem(v))

    def dialog(self, a):
        d = QDialog(self)
        d.setWindowTitle("App control rule")
        d.resize(720, 360)
        lay = QVBoxLayout(d)
        f = QFormLayout()
        name = QLineEdit(a.get("name", ""))
        act = QComboBox()
        act.addItem("Block", "deny")
        act.addItem("Allow", "allow")
        act.setCurrentIndex(0 if a.get("action", "deny") == "deny" else 1)
        kind = QComboBox()
        for k, w in self.KINDS:
            kind.addItem(w, k)
        kind.setCurrentIndex(max(0, kind.findData(a.get("match", "path"))))
        pat = QLineEdit(a.get("pattern", ""))
        row = QHBoxLayout()
        row.addWidget(pat)
        br = QPushButton("Program…")

        def browse():
            p, _ = QFileDialog.getOpenFileName(d, "Program", "/usr/bin")
            if not p:
                return
            if kind.currentData() == "hash":
                import hashlib
                with open(p, "rb") as fh:
                    pat.setText(hashlib.sha256(fh.read()).hexdigest())
            elif kind.currentData() == "name":
                pat.setText(os.path.basename(p))
            else:
                pat.setText(os.path.realpath(p))
        br.clicked.connect(browse)
        row.addWidget(br)
        staged = QCheckBox("Staged (log only)")
        staged.setChecked(bool(a.get("staged")))
        f.addRow("Name:", name)
        f.addRow("Action:", act)
        f.addRow("Match by:", kind)
        f.addRow("Program:", row)
        f.addRow("", staged)
        lay.addLayout(f)
        lay.addWidget(QLabel("For users where:"))
        cl = CondList(self.cfg, operand_choices(self.cfg, ("user",), True), a.get("who"), True, "Everyone (except root)")
        lay.addWidget(cl)
        lay.addStretch()
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        if d.exec():
            return {"name": name.text().strip() or "app rule", "action": act.currentData(), "match": kind.currentData(),
                    "pattern": pat.text().strip(), "who": cl.get(), "staged": staged.isChecked()}
        return None

    def add(self):
        a = self.dialog({})
        if a:
            self.cfg["apps"].append(a)
            self.changed()
            self.refresh()

    def edit(self):
        i = self.table.currentRow()
        if i >= 0:
            a = self.dialog(self.cfg["apps"][i])
            if a:
                self.cfg["apps"][i] = a
                self.changed()
                self.refresh()

    def remove(self):
        i = self.table.currentRow()
        if i >= 0:
            del self.cfg["apps"][i]
            self.changed()
            self.refresh()

    def preset(self):
        who = [{"left": "user.account", "op": "!=", "right": {"value": "admin"}}]
        self.cfg["apps"].append({"name": "Installed programs only", "action": "allow", "match": "trusted", "pattern": "",
                                 "who": who, "staged": True})
        self.changed()
        self.refresh()
        QMessageBox.information(self, "App control", "Added a staged allow list for non-administrators: only programs "
                                "installed by the administrator. Check the audit log, then untick 'staged' to enforce it.")


# ---------------------------------------------------------------------------
class Compliance(Page):
    name = "Device & compliance"

    def __init__(self, win):
        super().__init__(win)
        self.managed = QCheckBox("This device is managed by the organisation (env.device.managed = yes)")
        self.managed.toggled.connect(self.store)
        self.lay.addWidget(self.managed)
        self.lay.addWidget(note("Rules can require a managed device, a local (not remote) session or office hours."))
        b = QPushButton("Export compliance report…")
        b.clicked.connect(self.export)
        self.lay.addWidget(b, alignment=Qt.AlignmentFlag.AlignLeft)
        self.lay.addWidget(note("The report lists users and their attributes, rules, policies and where they apply, app "
                                "control, administrative rules, the kernel's enforcement state and recent audit events."))
        self.lay.addStretch()

    def refresh(self):
        self.managed.blockSignals(True)
        self.managed.setChecked(bool(self.cfg["device"].get("managed")))
        self.managed.blockSignals(False)

    def store(self):
        self.cfg["device"]["managed"] = self.managed.isChecked()
        self.changed()

    def export(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save report", os.path.expanduser("~/hydra-access-report.html"), "HTML (*.html)")
        if p and helper(self, ["report", p]) is not None:
            QMessageBox.information(self, "Report", "Saved %s." % p)


# ---------------------------------------------------------------------------
class Center(QMainWindow):
    PAGES_PRO = [Overview, Users, Properties, Rules, Policies, Effective, Audit, AdminActions]
    PAGES_ENT = [Apps, Compliance]

    def __init__(self, open_path=None, page=None):
        super().__init__()
        self.setWindowTitle("Hydra Access Center")
        self.resize(1100, 700)
        self.dirty = False
        self.saved_cfg = core.load_config()
        self.cfg = copy.deepcopy(self.saved_cfg)
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)
        self.apply_act = QAction("Apply changes", self)
        self.apply_act.setShortcut(QKeySequence.StandardKey.Save)
        self.apply_act.triggered.connect(self.apply)
        self.revert_act = QAction("Discard changes", self)
        self.revert_act.triggered.connect(self.reload)
        tb.addAction(self.apply_act)
        tb.addAction(self.revert_act)
        fam = QAction("Family & accounts", self)
        fam.triggered.connect(lambda: os.spawnlp(os.P_NOWAIT, "hydra-family", "hydra-family"))
        tb.addAction(fam)
        split = QSplitter()
        self.nav = QListWidget()
        self.nav.setMaximumWidth(240)
        self.nav.currentRowChanged.connect(self.go)
        self.stack = QStackedWidget()
        split.addWidget(self.nav)
        split.addWidget(self.stack)
        self.setCentralWidget(split)
        self.pages = [cls(self) for cls in self.PAGES_PRO + self.PAGES_ENT]
        for p in self.pages:
            self.stack.addWidget(p)
        self.rebuild_nav()
        self.set_dirty(False)
        if open_path:
            eff = self.page_of(Effective)
            eff.set_path(open_path)
            self.select(Effective if page != "classify" else Properties)
            if page == "classify":
                ClassifyDialog(self, self.cfg, open_path).exec()
        elif page:
            for p in self.pages:
                if p.name.lower().startswith(page.lower()):
                    self.select(type(p))

    def page_of(self, cls):
        return next(p for p in self.pages if isinstance(p, cls))

    def visible_pages(self):
        e = core.edition(self.cfg)
        if e == "home":
            return [Overview]
        return self.PAGES_PRO + (self.PAGES_ENT if e == "enterprise" else [])

    def rebuild_nav(self):
        cur = self.stack.currentWidget()
        self.nav.blockSignals(True)
        self.nav.clear()
        self.visible = self.visible_pages()
        for cls in self.visible:
            self.nav.addItem(cls.name)
        self.nav.blockSignals(False)
        idx = 0
        for i, cls in enumerate(self.visible):
            if isinstance(cur, cls):
                idx = i
        self.nav.setCurrentRow(idx)
        self.go(idx)

    def select(self, cls):
        if cls in self.visible:
            self.nav.setCurrentRow(self.visible.index(cls))

    def go(self, row):
        if 0 <= row < len(self.visible):
            p = self.page_of(self.visible[row])
            p.refresh()
            self.stack.setCurrentWidget(p)

    def set_dirty(self, dirty=True):
        self.dirty = dirty
        self.apply_act.setEnabled(dirty)
        self.revert_act.setEnabled(dirty)
        self.setWindowTitle("Hydra Access Center" + (" *" if dirty else ""))

    def apply(self):
        errs = core.validate(self.cfg)
        if errs:
            error(self, "\n".join(errs))
            return False
        if save_config(self, self.cfg):
            self.saved_cfg = copy.deepcopy(self.cfg)
            self.set_dirty(False)
            self.stack.currentWidget().refresh()
            return True
        return False

    def reload(self):
        self.saved_cfg = core.load_config()
        self.cfg = copy.deepcopy(self.saved_cfg)
        self.set_dirty(False)
        self.rebuild_nav()

    def closeEvent(self, ev):
        if self.dirty:
            r = QMessageBox.question(self, "Hydra Access Center", "Apply your changes before closing?",
                                     QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel)
            if r == QMessageBox.StandardButton.Cancel or (r == QMessageBox.StandardButton.Save and not self.apply()):
                ev.ignore()
                return
        ev.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Hydra Access Center")
    app.setDesktopFileName("hydra-access-center")
    args = sys.argv[1:]
    page = None
    if args and args[0].startswith("--"):
        page = args.pop(0)[2:]
    w = Center(args[0] if args else None, page)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
