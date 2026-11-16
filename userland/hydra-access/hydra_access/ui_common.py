"""Widgets shared by Family & accounts and Hydra Access Center (PyQt6, Qt Widgets: the
toolkit the Hydra apps use, so they look like the rest of KDE)."""
import json

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QToolButton,
                             QVBoxLayout, QWidget)

from . import core


def title(text, size=16):
    lab = QLabel(text)
    f = lab.font()
    f.setPointSize(size)
    f.setWeight(QFont.Weight.DemiBold)
    lab.setFont(f)
    return lab


def note(text):
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setStyleSheet("color: palette(placeholder-text);")
    return lab


def error(parent, text):
    QMessageBox.warning(parent, "Hydra access", text)


def helper(parent, args, stdin_text=None):
    """Runs the root helper (an administrator password may be asked). None on failure."""
    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        return core.run_helper(args, stdin_text)
    except PermissionError:
        error(parent, "The change was not made: an administrator's password is needed.")
    except Exception as e:  # noqa: BLE001 - shown to the user
        error(parent, "The change was not made:\n\n%s" % e)
    finally:
        QApplication.restoreOverrideCursor()
    return None


def save_config(parent, cfg):
    return helper(parent, ["save"], json.dumps(cfg)) is not None


def operand_choices(cfg, sides=("user", "res"), enterprise=False):
    """(label, token) pairs for the left side of a condition."""
    out = []
    if "user" in sides:
        for a in cfg.get("user_attributes", []):
            out.append(("User: " + a.get("display", a["name"]), "user." + a["name"]))
        out += [("User: name", "user.name"), ("User: account type", "user.account"), ("User: groups", "user.groups")]
        if enterprise:
            out.append(("Session: remote (1) or local (0)", "user.session.remote"))
    if "res" in sides:
        for p in cfg.get("properties", []):
            out.append(("Resource: " + p.get("display", p["name"]), "res." + p["name"]))
    if enterprise or "env" in sides:
        out += [("Time of day (HHMM, e.g. 0830)", "env.time"), ("Weekday (1 Mon .. 7 Sun)", "env.weekday"),
                ("Device is managed (yes/no)", "env.device.managed")]
    return out


def values_for(cfg, token):
    """Suggested values for an operand."""
    side, _, name = token.partition(".")
    if side == "user":
        if name == "account":
            return core.ACCOUNT_TYPES
        if name == "name":
            return [u for u, _, _ in core.system_users()]
        if name == "groups":
            return ["sudo", "users"]
        if name == "session.remote":
            return ["0", "1"]
        for a in cfg.get("user_attributes", []):
            if a["name"] == name:
                return core.user_attr_values(cfg, a)
    if side == "res":
        p = core.property_by_name(cfg, name)
        return list(p["values"]) if p else []
    if token == "env.weekday":
        return [str(i) for i in range(1, 8)]
    if token == "env.device.managed":
        return ["yes", "no"]
    return []


class CondRow(QWidget):
    removed = pyqtSignal(object)

    def __init__(self, cfg, choices, cond=None, enterprise=False):
        super().__init__()
        self.cfg, self.choices, self.enterprise = cfg, choices, enterprise
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.left = QComboBox()
        for lab, tok in choices:
            self.left.addItem(lab, tok)
        self.op = QComboBox()
        for tok, words in core.OPS:
            self.op.addItem(words, tok)
        self.right = QComboBox()
        self.right.setEditable(True)
        self.right.setMinimumWidth(160)
        rm = QToolButton()
        rm.setText("✕")
        rm.setToolTip("Remove this condition")
        rm.clicked.connect(lambda: self.removed.emit(self))
        for w in (self.left, self.op, self.right):
            lay.addWidget(w)
        lay.addWidget(rm)
        self.left.currentIndexChanged.connect(self._refill)
        self.op.currentIndexChanged.connect(self._op_changed)
        if cond:
            i = self.left.findData(cond.get("left"))
            if i < 0:
                self.left.addItem(cond.get("left"), cond.get("left"))
                i = self.left.count() - 1
            self.left.setCurrentIndex(i)
            self.op.setCurrentIndex(max(0, self.op.findData(cond.get("op", "=="))))
        self._refill()
        if cond and "right" in cond:
            r = cond["right"]
            self.right.setEditText(("value: " + str(r["value"])) if isinstance(r, dict) else self._label_of(r))
        self._op_changed()

    def _label_of(self, tok):
        for lab, t in self.choices + operand_choices(self.cfg, ("user", "res"), self.enterprise):
            if t == tok:
                return lab
        return tok

    def _refill(self):
        cur = self.right.currentText()
        self.right.clear()
        tok = self.left.currentData() or ""
        for v in values_for(self.cfg, tok):
            self.right.addItem("value: " + v, {"value": v})
        # Comparing with the other side's attribute of the same name is the usual ABAC case
        side, _, name = tok.partition(".")
        other = {"user": "res", "res": "user"}.get(side)
        for lab, t in operand_choices(self.cfg, ("user", "res"), self.enterprise):
            if t.startswith((other or "-") + "."):
                self.right.addItem(lab, t)
        if cur:
            self.right.setEditText(cur)

    def _op_changed(self):
        self.right.setVisible(self.op.currentData() not in ("exists", "not exists"))

    def get(self):
        c = {"left": self.left.currentData(), "op": self.op.currentData()}
        if c["op"] in ("exists", "not exists"):
            return c
        text = self.right.currentText().strip()
        i = self.right.findText(text)
        if i >= 0 and self.right.itemData(i) is not None:
            c["right"] = self.right.itemData(i)
        elif text.startswith("value: "):
            c["right"] = {"value": text[7:]}
        else:
            c["right"] = {"value": text}
        return c


class CondList(QWidget):
    """Conditions joined by "and"."""

    def __init__(self, cfg, choices, conds=None, enterprise=False, empty_text="Always"):
        super().__init__()
        self.cfg, self.choices, self.enterprise = cfg, choices, enterprise
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.rows = []
        self.empty = QLabel(empty_text)
        self.empty.setStyleSheet("color: palette(placeholder-text);")
        self.lay.addWidget(self.empty)
        add = QPushButton("Add condition")
        add.clicked.connect(lambda: self.add())
        bar = QHBoxLayout()
        bar.addWidget(add)
        bar.addStretch()
        self.lay.addLayout(bar)
        for c in conds or []:
            self.add(c)
        self._update()

    def add(self, cond=None):
        r = CondRow(self.cfg, self.choices, cond, self.enterprise)
        r.removed.connect(self.remove)
        self.lay.insertWidget(len(self.rows) + 1, r)
        self.rows.append(r)
        self._update()

    def remove(self, r):
        self.rows.remove(r)
        r.setParent(None)
        r.deleteLater()
        self._update()

    def _update(self):
        self.empty.setVisible(not self.rows)

    def get(self):
        return [r.get() for r in self.rows]


def edition_combo(cfg):
    c = QComboBox()
    for e in core.EDITIONS:
        c.addItem(core.EDITION_NAMES[e], e)
    c.setCurrentIndex(core.EDITIONS.index(core.edition(cfg)))
    return c


def initials_icon(name, size=36):
    from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    hue = sum(map(ord, name)) * 47 % 360
    p.setBrush(QColor.fromHsv(hue, 120, 200))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.setPen(QColor("white"))
    f = p.font()
    f.setPixelSize(size // 2)
    f.setBold(True)
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, (name[:1] or "?").upper())
    p.end()
    return QIcon(pm)
