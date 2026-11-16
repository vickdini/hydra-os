"""Hydra access control: the configuration, its compiler and the kernel interface.

One engine, three faces. Everything the apps show (Family & accounts for Home; Hydra
Access Center for Pro and Enterprise) is kept in one root-owned JSON file,
/etc/hydra/access/config.json. Saving it (through the root helper) compiles it into:

- /etc/hydra/access/policy.compiled: the kernel's policy text (see
  src/compat/linux/abac_core.rs), loaded at boot and after every change;
- /etc/hydra/access/subjects/<user>: each user's attributes, which hydra-logind and the
  console login attach to the user's sessions.

Files and folders carry labels in the security.hydra.labels extended attribute (only root
may change them; new files inherit their folder's). Applying a policy to a folder adds
the label policy=<name> to it and everything inside.
"""
import ctypes
import grp
import json
import os
import pwd
import re
import time

ETC = "/etc/hydra/access"
CONFIG = ETC + "/config.json"
POLICY = ETC + "/policy.compiled"
SUBJECTS = ETC + "/subjects"
LOG = "/var/log/hydra/access.log"
LABELS = "security.hydra.labels"
HELPER = "/usr/libexec/hydra-access-helper"

EDITIONS = ["home", "pro", "enterprise"]
EDITION_NAMES = {"home": "Home", "pro": "Pro", "enterprise": "Enterprise"}
ACCOUNT_TYPES = ["admin", "standard", "child"]
ACCOUNT_NAMES = {"admin": "Administrator", "standard": "Standard user", "child": "Child"}

# Comparison operators: (token, words shown in the editor)
OPS = [
    ("==", "equals"),
    ("!=", "does not equal"),
    (">=", "is at least"),
    ("<=", "is at most"),
    (">", "is above"),
    ("<", "is below"),
    ("in", "are all among (member of)"),
    ("any", "has any of"),
    ("exists", "has a value"),
    ("not exists", "has no value"),
]
OP_WORDS = dict(OPS)

ACTIONS = [("r", "Read"), ("w", "Write"), ("x", "Run / open folder"), ("d", "Delete")]

# Administrative actions (polkit) by category, see hydra-access-check.c
ADMIN_CATEGORIES = [
    ("software", "Install or remove software"),
    ("network", "Change network settings"),
    ("time", "Change date and time"),
    ("users", "Manage accounts and access"),
    ("power", "Shut down or restart"),
    ("devices", "Mount disks and devices"),
    ("system", "Other system settings"),
]

ENV_ATTRS = [("env.time", "Time of day (HHMM)"), ("env.weekday", "Weekday (1=Mon .. 7=Sun)"),
             ("env.hour", "Hour"), ("env.device.managed", "Device is managed")]
SESSION_ATTRS = [("user.session.remote", "Remote session (1) or local (0)"), ("user.name", "User name"),
                 ("user.groups", "Groups"), ("user.account", "Account type")]

DEFAULT_CONFIG = {
    "version": 1,
    "edition": "home",
    "properties": [
        {"name": "classification", "display": "Classification", "ordered": True,
         "values": ["Public", "Internal", "Confidential", "Secret"]},
        {"name": "department", "display": "Department", "ordered": False,
         "values": ["Finance", "HR", "Engineering", "Sales"]},
        {"name": "project", "display": "Project", "ordered": False, "multi": True, "values": []},
    ],
    "user_attributes": [
        {"name": "department", "display": "Department", "values_from": "department"},
        {"name": "clearance", "display": "Clearance", "values_from": "classification"},
        {"name": "role", "display": "Role", "values": ["Employee", "Manager", "IT", "Auditor"]},
        {"name": "project", "display": "Projects", "values_from": "project", "multi": True},
        {"name": "employment", "display": "Employment type", "values": ["Employee", "Contractor", "Intern"]},
    ],
    "users": {},
    "rules": [],
    "policies": [],
    "applied": [],
    "admin_rules": [],
    "apps": [],
    "device": {"managed": False},
    "family": {"children": {}, "private_folders": []},
}

NAME_RE = re.compile(r"^[A-Za-z0-9 ._()-]{1,64}$")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path=CONFIG):
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    out = json.loads(json.dumps(DEFAULT_CONFIG))
    out.update(cfg)
    out.setdefault("family", {}).setdefault("children", {})
    out["family"].setdefault("private_folders", [])
    out.setdefault("device", {}).setdefault("managed", False)
    return out


def edition(cfg):
    e = cfg.get("edition", "home")
    return e if e in EDITIONS else "home"


def property_by_name(cfg, name):
    for p in cfg.get("properties", []):
        if p["name"] == name:
            return p
    return None


def user_attr_values(cfg, attr):
    """Allowed values of a user attribute (its own list or its property's)."""
    src = attr.get("values_from")
    if src:
        p = property_by_name(cfg, src)
        return list(p["values"]) if p else []
    return list(attr.get("values", []))


def system_users():
    """Human accounts: (name, uid, full name), uid 1000..59999."""
    out = []
    for p in pwd.getpwall():
        if 1000 <= p.pw_uid < 60000 and p.pw_shell not in ("/usr/sbin/nologin", "/bin/false"):
            out.append((p.pw_name, p.pw_uid, p.pw_gecos.split(",")[0]))
    return sorted(out, key=lambda x: x[1])


def user_groups(name):
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        return []
    try:
        gids = os.getgrouplist(name, pw.pw_gid)
    except OSError:
        gids = [pw.pw_gid]
    names = []
    for g in gids:
        try:
            names.append(grp.getgrgid(g).gr_name)
        except KeyError:
            pass
    return names


def account_type(cfg, name):
    """admin / standard / child: admin = member of sudo (or admin)."""
    u = cfg.get("users", {}).get(name, {})
    if u.get("account") == "child":
        return "child"
    groups = user_groups(name)
    if "sudo" in groups or "admin" in groups:
        return "admin"
    return "standard"


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------

def esc(s):
    """Escapes a token of the compiled format (and of label / attribute values)."""
    out = []
    for ch in str(s):
        o = ord(ch)
        if o <= 32 or ch in "%=,'#" or o == 127:
            out.append("%%%02X" % o if o < 256 else ch)
        else:
            out.append(ch)
    return "".join(out)


def operand(x):
    """A condition operand: an attribute ("user.x", "res.x", "env.x") or a value."""
    if isinstance(x, dict):
        v = str(x.get("value", ""))
        if v.isdigit():
            return "#" + v
        return "'" + esc(v)
    x = str(x)
    if x.startswith(("user.", "res.", "env.")):
        side, name = x.split(".", 1)
        return side + "." + esc(name)
    if x.isdigit():
        return "#" + x
    return "'" + esc(x)


def compile_conds(conds):
    """A list of conditions (ANDed) as postfix tokens."""
    toks = []
    for c in conds or []:
        op = c.get("op", "==")
        if op == "exists":
            t = [operand(c["left"]), "exists"]
        elif op == "not exists":
            t = [operand(c["left"]), "exists", "not"]
        else:
            t = [operand(c["left"]), operand(c["right"]), op]
        toks += t
        if len(toks) > len(t):
            toks.append("and")
    return toks or ["true"]


def describe_cond(c):
    def side(x):
        if isinstance(x, dict):
            return '"%s"' % x.get("value", "")
        x = str(x)
        if x.startswith("user."):
            return "user's " + x[5:]
        if x.startswith("res."):
            return "resource's " + x[4:]
        if x.startswith("env."):
            return x[4:]
        return x
    op = c.get("op", "==")
    if op in ("exists", "not exists"):
        return "%s %s" % (side(c["left"]), OP_WORDS[op])
    return "%s %s %s" % (side(c["left"]), OP_WORDS.get(op, op), side(c.get("right")))


def describe_conds(conds):
    return " and ".join(describe_cond(c) for c in conds) if conds else "always"


def _hours_entries(hours):
    """Screen-time allow lines: hours = {"1": [800, 2000], ...} (weekday 1 = Monday)."""
    lines = []
    for d in range(1, 8):
        h = hours.get(str(d))
        if h and len(h) == 2 and int(h[0]) < int(h[1]):
            lines.append("allow x env.weekday #%d == env.time #%d >= and env.time #%d < and" % (d, int(h[0]), int(h[1])))
    return lines


def compile_policy(cfg):
    """The kernel's policy text."""
    L = ["hydra-access 1", "# Generated by hydra-access from %s; do not edit." % CONFIG]
    ordered = [p for p in cfg.get("properties", []) if p.get("ordered") and p.get("values")]
    for p in ordered:
        L.append("type %s %s" % (esc(p["name"]), " ".join(esc(v) for v in p["values"])))
        L.append("attrtype %s %s" % (esc(p["name"]), esc(p["name"])))
    names = {p["name"] for p in ordered}
    for a in cfg.get("user_attributes", []):
        if a.get("values_from") in names:
            L.append("attrtype %s %s" % (esc(a["name"]), esc(a["values_from"])))
    L.append("env device.managed %s" % ("yes" if cfg.get("device", {}).get("managed") else "no"))
    L.append("tz %d" % time.localtime().tm_gmtoff)

    def emit_rule(r, policy_staged=False):
        flags = []
        if r.get("staged"):
            flags.append("staged")
        if r.get("replaces"):
            flags.append("replaces=" + esc(r["replaces"]))
        L.append(("rule %s %s" % (esc(r["name"]), " ".join(flags))).rstrip())
        if r.get("target"):
            L.append("target " + " ".join(compile_conds(r["target"])))
        for e in r.get("entries", []):
            acts = "".join(ch for ch in e.get("actions", "") if ch in "rwxd") or "-"
            L.append("allow %s %s" % (acts, " ".join(compile_conds(e.get("when")))))

    rules = {r["name"]: r for r in cfg.get("rules", [])}
    for p in cfg.get("policies", []):
        flags = (" global" if p.get("global") else "") + (" staged" if p.get("staged") else "")
        L.append("policy %s%s" % (esc(p["name"]), flags))
        for rn in p.get("rules", []):
            if rn in rules:
                emit_rule(rules[rn])

    # Administrative actions (polkit): who may do what, by category
    admin = cfg.get("admin_rules", [])
    if admin:
        L.append("policy Administrative%20actions global")
        for i, a in enumerate(admin):
            L.append("rule %s%s" % (esc(a.get("name") or "admin-%d" % i), " staged" if a.get("staged") else ""))
            L.append("target res.category '%s ==" % esc(a["category"]))
            L.append("allow x " + " ".join(compile_conds(a.get("when"))))

    # Family (Home): screen time, private folders
    fam = cfg.get("family", {})
    fam_lines = []
    for name, c in sorted(fam.get("children", {}).items()):
        if c.get("hours_enabled") and c.get("hours"):
            fam_lines.append("rule Screen%%20time%%20for%%20%s" % esc(name))
            fam_lines.append("target res.action 'session == user.name '%s == and" % esc(name))
            fam_lines += _hours_entries(c["hours"])
    if fam.get("private_folders"):
        fam_lines.append("rule Private%20folders")
        fam_lines.append("target res.private exists")
        fam_lines.append("allow rwxd user.name res.private ==")
    if fam_lines:
        L.append("policy Family global")
        L += fam_lines

    # Sign-in hours (Enterprise): users with allowed hours set
    for name, u in sorted(cfg.get("users", {}).items()):
        if u.get("hours_enabled") and u.get("hours") and u.get("account") != "child":
            L.append("policy Sign-in%%20hours%%20for%%20%s global" % esc(name))
            L.append("rule Sign-in%%20hours%%20for%%20%s" % esc(name))
            L.append("target res.action 'session == user.name '%s == and" % esc(name))
            L += _hours_entries(u["hours"])

    # App control: Home blocked apps, Enterprise rules
    for name, c in sorted(fam.get("children", {}).items()):
        for i, path in enumerate(c.get("blocked_apps", [])):
            L.append("app Blocked%%20for%%20%s%%20%d deny path %s user.name '%s ==" % (esc(name), i + 1, esc(path), esc(name)))
    for i, a in enumerate(cfg.get("apps", [])):
        kind = a.get("match", "path")
        pat = a.get("pattern") or "-"
        L.append("app %s %s%s %s %s %s" % (esc(a.get("name") or "app-%d" % i), "deny" if a.get("action") == "deny" else "allow",
                                           " staged" if a.get("staged") else "", kind, esc(pat), " ".join(compile_conds(a.get("who")))))
    return "\n".join(L) + "\n"


def subject_text(cfg, name):
    """The attributes of user `name` (what /etc/hydra/access/subjects/<name> holds)."""
    u = cfg.get("users", {}).get(name, {})
    lines = ["name=" + esc(name), "account=" + account_type(cfg, name)]
    for a in cfg.get("user_attributes", []):
        v = u.get(a["name"])
        if v in (None, "", []):
            continue
        vals = v if isinstance(v, list) else [v]
        lines.append("%s=%s" % (esc(a["name"]), ",".join(esc(x) for x in vals)))
    return "\n".join(lines) + "\n"


def session_subject(cfg, name):
    """What a session of `name` carries (hydra-logind adds uid, groups, session.*)."""
    extra = ["uid=%d" % pwd.getpwnam(name).pw_uid] if _has_user(name) else []
    g = user_groups(name)
    if g:
        extra.append("groups=" + ",".join(esc(x) for x in g))
    extra.append("session.remote=0")
    return subject_text(cfg, name) + "\n".join(extra) + "\n"


def _has_user(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def validate(cfg):
    """Problems that would make the configuration unusable (list of strings)."""
    errs = []
    seen = set()
    for r in cfg.get("rules", []):
        if not NAME_RE.match(r.get("name", "")):
            errs.append("Rule name '%s' is not allowed (letters, digits, spaces, . _ - ( ))." % r.get("name", ""))
        if r.get("name") in seen:
            errs.append("Two rules are called '%s'." % r["name"])
        seen.add(r.get("name"))
    pseen = set()
    for p in cfg.get("policies", []):
        if not NAME_RE.match(p.get("name", "")):
            errs.append("Policy name '%s' is not allowed." % p.get("name", ""))
        if p.get("name") in pseen:
            errs.append("Two policies are called '%s'." % p["name"])
        pseen.add(p.get("name"))
    for p in cfg.get("properties", []):
        if not re.match(r"^[a-z][a-z0-9_.-]{0,31}$", p.get("name", "")):
            errs.append("Property name '%s' must be lower-case letters/digits." % p.get("name", ""))
    return errs


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

def parse_labels(text):
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = unesc(k.strip())
        out[k] = [unesc(x.strip()) for x in v.split(",") if x.strip()]
    return out


def format_labels(d):
    return "".join("%s=%s\n" % (esc(k), ",".join(esc(x) for x in v)) for k, v in sorted(d.items()) if v)


def unesc(s):
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


def get_labels(path):
    try:
        return parse_labels(os.getxattr(path, LABELS).decode("utf-8", "replace"))
    except OSError:
        return {}


def set_labels(path, labels):
    """Root only."""
    text = format_labels(labels)
    if text:
        os.setxattr(path, LABELS, text.encode())
    else:
        try:
            os.removexattr(path, LABELS)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Kernel interface: prctl(PR_HYDRA_ACCESS, ...)
# ---------------------------------------------------------------------------

PR_HYDRA_ACCESS = 0x48594401
_libc = None


def _prctl(cmd, a2=0, a3=0, a4=0):
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        _libc.prctl.restype = ctypes.c_long
    r = _libc.prctl(PR_HYDRA_ACCESS, cmd, a2, a3, a4)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


def kernel_supported():
    try:
        status()
        return True
    except OSError:
        return False


def status():
    buf = ctypes.create_string_buffer(1024)
    n = _prctl(6, 0, ctypes.addressof(buf), 1023)
    return dict(kv.split("=", 1) for kv in buf.raw[:n].decode().split() if "=" in kv)


def load_policy(text):
    b = text.encode()
    buf = ctypes.create_string_buffer(b, len(b))
    return _prctl(1, ctypes.addressof(buf), len(b))


def get_subject(pid=0):
    buf = ctypes.create_string_buffer(8192)
    n = _prctl(3, pid, ctypes.addressof(buf), 8191)
    return buf.raw[:n].decode("utf-8", "replace")


def read_audit():
    buf = ctypes.create_string_buffer(65536)
    n = _prctl(4, 0, ctypes.addressof(buf), 65535)
    return buf.raw[:n].decode("utf-8", "replace")


def evaluate(user_text, res_text, env_text=""):
    """The kernel's answer for a what-if question: dict with enforced, proposed, covered,
    rule, would_rule, policy (and app, app_staged, app_rule with exec= in env_text)."""
    q = (user_text.rstrip("\n") + "\n--\n" + res_text.rstrip("\n") + "\n--\n" + env_text).encode()
    qb = ctypes.create_string_buffer(q, len(q))
    out = ctypes.create_string_buffer(4096)
    n = _prctl(5, ctypes.addressof(qb), len(q) | (4095 << 32), ctypes.addressof(out))
    text = out.raw[:n].decode("utf-8", "replace")
    return {k: unesc(v) for k, v in (kv.split("=", 1) for kv in text.split() if "=" in kv)}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

KIND_WORDS = {
    "deny": "Denied",
    "staged-would-deny": "Allowed now; staged rule would deny",
    "deny-staged-would-allow": "Denied; staged rule would allow",
    "app-deny": "Program blocked",
    "app-staged-would-deny": "Program allowed; staged rule would block",
    "app-deny-staged-would-allow": "Program blocked; staged rule would allow",
}


def parse_audit_line(line):
    parts = line.split()
    if len(parts) < 2 or not parts[0].isdigit():
        return None
    rec = {"time": int(parts[0]), "kind": parts[1]}
    for kv in parts[2:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            rec[k] = unesc(v)
    try:
        rec["user"] = pwd.getpwuid(int(rec.get("uid", "-1"))).pw_name
    except (KeyError, ValueError):
        rec["user"] = rec.get("uid", "?")
    return rec


def read_log(path=LOG, limit=5000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return None
    return [r for r in (parse_audit_line(x) for x in lines) if r]


# ---------------------------------------------------------------------------
# Effective access
# ---------------------------------------------------------------------------

def unix_allows(path, user):
    """Actions the mode bits (not ACLs) give `user` on `path` ("rwx" letters)."""
    try:
        st = os.stat(path)
        pw = pwd.getpwnam(user)
    except (OSError, KeyError):
        return ""
    if pw.pw_uid == 0:
        return "rwx"
    gids = set()
    try:
        gids = set(os.getgrouplist(user, pw.pw_gid))
    except OSError:
        gids = {pw.pw_gid}
    if st.st_uid == pw.pw_uid:
        bits = (st.st_mode >> 6) & 7
    elif st.st_gid in gids:
        bits = (st.st_mode >> 3) & 7
    else:
        bits = st.st_mode & 7
    return "".join(ch for ch, b in (("r", 4), ("w", 2), ("x", 1)) if bits & b)


def effective_access(cfg, user, path, env_text=""):
    labels = get_labels(path)
    res = format_labels(labels)
    ans = evaluate(session_subject(cfg, user), res, env_text) if res else {"enforced": "rwxd", "proposed": "rwxd", "covered": "0"}
    return {"labels": labels, "unix": unix_allows(path, user), "policy": ans}


def run_helper(args, stdin_text=None):
    """Runs the root helper through pkexec (polkit asks for an administrator password)."""
    import subprocess
    cmd = ["pkexec", HELPER] + list(args)
    if os.geteuid() == 0:
        cmd = [HELPER] + list(args)
    p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True)
    if p.returncode == 126 or p.returncode == 127:
        raise PermissionError("Not authorised")
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "the helper failed").strip())
    return p.stdout
