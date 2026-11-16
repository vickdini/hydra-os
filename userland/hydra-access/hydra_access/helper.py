"""hydra-access-helper: the root side of Hydra's access apps.

The apps run as the user; every change goes through this program, started with pkexec
(polkit action org.hydra.access.manage: an administrator's password, remembered for a
few minutes). Commands:

  save                 stdin: the whole configuration (JSON); validates, writes
                       /etc/hydra/access, compiles, loads it into the kernel, applies the
                       Home side effects (web filter)
  reload               recompiles and reloads the saved configuration
  label PATH [-r]      stdin: {"set": {key: [values]}, "remove": [keys]} on PATH (and,
                       with -r, everything inside)
  apply PATH POLICY    applies POLICY to the folder PATH (label policy=POLICY, recursive)
  unapply PATH POLICY  removes it
  private PATH OWNER   makes PATH a private folder of OWNER (Family); "-" undoes it
  useradd NAME TYPE [FULL NAME]   stdin: password; TYPE admin|standard|child
  usertype NAME TYPE   changes an account's type
  passwd NAME          stdin: new password
  userdel NAME         deletes the account (keeps the home folder)
  audit                moves the kernel's pending audit records to the log
  report PATH          writes a compliance report (HTML) to PATH (Enterprise)
"""
import json
import os
import pwd
import subprocess
import sys
import time

from . import core
from . import webfilter


def die(msg, code=1):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


def write_atomic(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.rename(tmp, path)


def compile_and_load(cfg):
    errs = core.validate(cfg)
    if errs:
        die("\n".join(errs))
    text = core.compile_policy(cfg)
    os.makedirs(core.SUBJECTS, exist_ok=True)
    os.chmod(core.ETC, 0o755)
    try:
        core.load_policy(text)
    except OSError as e:
        die("The kernel refused the policy (%s). Nothing was changed." % e)
    write_atomic(core.CONFIG, json.dumps(cfg, indent=1, sort_keys=True) + "\n")
    write_atomic(core.POLICY, text)
    # Users' attributes: every human account gets a file (name and account type at least)
    keep = set()
    for name, _uid, _full in core.system_users():
        write_atomic(os.path.join(core.SUBJECTS, name), core.subject_text(cfg, name))
        keep.add(name)
    for f in os.listdir(core.SUBJECTS):
        if f not in keep and not f.endswith(".new"):
            os.unlink(os.path.join(core.SUBJECTS, f))
    webfilter.apply(cfg)
    # Running sessions keep their attributes until they sign in again; the policy itself
    # applies at once


def walk(path, recursive):
    yield path
    if recursive and os.path.isdir(path) and not os.path.islink(path):
        for root, dirs, files in os.walk(path):
            for n in dirs + files:
                p = os.path.join(root, n)
                if not os.path.islink(p):
                    yield p


def change_labels(path, set_=None, remove=(), recursive=False, add=None, discard=None):
    """add/discard: {key: value} to add to / remove from multi-valued labels."""
    n = 0
    for p in walk(path, recursive):
        lab = core.get_labels(p)
        for k, v in (set_ or {}).items():
            lab[k] = list(v)
        for k in remove:
            lab.pop(k, None)
        for k, v in (add or {}).items():
            if v not in lab.setdefault(k, []):
                lab[k].append(v)
        for k, v in (discard or {}).items():
            if v in lab.get(k, []):
                lab[k].remove(v)
                if not lab[k]:
                    del lab[k]
        core.set_labels(p, lab)
        n += 1
    return n


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        die("%s: %s" % (cmd[0], (p.stderr or p.stdout).strip()))
    return p.stdout


def set_account_type(cfg, name, typ):
    if typ not in core.ACCOUNT_TYPES:
        die("unknown account type " + typ)
    if typ == "admin":
        run(["gpasswd", "-a", name, "sudo"])
    else:
        # Never remove the last administrator
        admins = [u for u, _, _ in core.system_users() if "sudo" in core.user_groups(u)]
        if admins == [name]:
            die("%s is the only administrator; make another account an administrator first." % name)
        if "sudo" in core.user_groups(name):
            run(["gpasswd", "-d", name, "sudo"])
    u = cfg["users"].setdefault(name, {})
    u["account"] = typ
    if typ == "child":
        cfg["family"]["children"].setdefault(name, {"hours_enabled": False, "hours": {}, "blocked_apps": [], "web": {"mode": "off", "sites": []}})
    else:
        cfg["family"]["children"].pop(name, None)


def report(cfg, path):
    """A self-contained HTML compliance report."""
    import html
    h = html.escape
    st = {}
    try:
        st = core.status()
    except OSError:
        pass
    rows = []
    rows.append("<h1>Hydra access control - compliance report</h1><p>Generated %s on %s. Edition: %s.</p>"
                % (h(time.strftime("%Y-%m-%d %H:%M")), h(os.uname().nodename), h(core.EDITION_NAMES[core.edition(cfg)])))
    rows.append("<h2>Enforcement</h2><p>Policy loaded in the kernel: %s (generation %s); %s rules, %s app rules.</p>"
                % ("yes" if st.get("active") == "1" or st.get("apps") == "1" else "no", h(st.get("generation", "?")), h(st.get("rules", "0")), h(st.get("app_rules", "0"))))
    rows.append("<h2>Users</h2><table><tr><th>User</th><th>Account</th><th>Attributes</th></tr>")
    for name, uid, full in core.system_users():
        rows.append("<tr><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>" % (h(name), h(core.ACCOUNT_NAMES[core.account_type(cfg, name)]), h(core.subject_text(cfg, name))))
    rows.append("</table><h2>Rules</h2><table><tr><th>Rule</th><th>Applies to</th><th>Grants</th><th>Mode</th></tr>")
    for r in cfg.get("rules", []):
        grants = "<br>".join(h("%s if %s" % (e.get("actions", ""), core.describe_conds(e.get("when")))) for e in r.get("entries", []))
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (h(r["name"]), h(core.describe_conds(r.get("target"))), grants, "staged" if r.get("staged") else "enforced"))
    rows.append("</table><h2>Policies and where they apply</h2><table><tr><th>Policy</th><th>Rules</th><th>Applied to</th></tr>")
    for p in cfg.get("policies", []):
        where = ["all labelled files"] if p.get("global") else [a["path"] for a in cfg.get("applied", []) if a["policy"] == p["name"]]
        rows.append("<tr><td>%s%s</td><td>%s</td><td>%s</td></tr>" % (h(p["name"]), " (staged)" if p.get("staged") else "", h(", ".join(p.get("rules", []))), h(", ".join(where) or "nowhere")))
    rows.append("</table><h2>App control</h2><table><tr><th>Rule</th><th>Action</th><th>Program</th><th>Who</th></tr>")
    for a in cfg.get("apps", []):
        rows.append("<tr><td>%s</td><td>%s</td><td>%s %s</td><td>%s</td></tr>" % (h(a.get("name", "")), h(a.get("action", "")), h(a.get("match", "")), h(a.get("pattern", "")), h(core.describe_conds(a.get("who")))))
    rows.append("</table><h2>Administrative actions</h2><table><tr><th>Category</th><th>Allowed when</th></tr>")
    for a in cfg.get("admin_rules", []):
        rows.append("<tr><td>%s</td><td>%s</td></tr>" % (h(dict(core.ADMIN_CATEGORIES).get(a["category"], a["category"])), h(core.describe_conds(a.get("when")))))
    log = core.read_log() or []
    rows.append("</table><h2>Audit (last 200 events)</h2><table><tr><th>Time</th><th>Event</th><th>User</th><th>File / program</th><th>Rule</th></tr>")
    for r in log[-200:]:
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            h(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["time"]))), h(core.KIND_WORDS.get(r["kind"], r["kind"])), h(r["user"]),
            h(r.get("path", "inode %s" % r.get("ino", "?"))), h(r.get("rule", ""))))
    rows.append("</table>")
    css = "body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top}pre{margin:0}"
    text = "<!doctype html><meta charset=utf-8><title>Hydra access report</title><style>%s</style>%s" % (css, "\n".join(rows))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    # The report belongs to whoever asked for it
    uid = int(os.environ.get("PKEXEC_UID", "0"))
    if uid:
        os.chown(path, uid, pwd.getpwuid(uid).pw_gid)


def drain_audit():
    try:
        text = core.read_audit()
    except OSError:
        return
    if not text:
        return
    os.makedirs(os.path.dirname(core.LOG), exist_ok=True)
    fd = os.open(core.LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        import grp
        os.fchown(fd, 0, grp.getgrnam("sudo").gr_gid)
    except (KeyError, OSError):
        pass
    os.write(fd, text.encode())
    os.close(fd)


def main(argv):
    if os.geteuid() != 0:
        die("hydra-access-helper must run as root (use pkexec)", 126)
    if not argv:
        die(__doc__)
    cmd, args = argv[0], argv[1:]
    cfg = core.load_config()
    if cmd == "save":
        new = json.loads(sys.stdin.read())
        if not isinstance(new, dict):
            die("bad configuration")
        # Account types are not set by saving (usertype does it, with group changes)
        compile_and_load(new)
    elif cmd == "reload":
        compile_and_load(cfg)
    elif cmd == "label":
        if not args:
            die("label PATH [-r]")
        req = json.loads(sys.stdin.read() or "{}")
        n = change_labels(os.path.realpath(args[0]), req.get("set"), req.get("remove", []), "-r" in args[1:])
        print("%d item(s) labelled" % n)
    elif cmd in ("apply", "unapply"):
        if len(args) != 2:
            die(cmd + " PATH POLICY")
        path, pol = os.path.realpath(args[0]), args[1]
        if not os.path.isdir(path):
            die(path + " is not a folder")
        if cmd == "apply":
            n = change_labels(path, recursive=True, add={"policy": pol})
            if not any(a["path"] == path and a["policy"] == pol for a in cfg["applied"]):
                cfg["applied"].append({"path": path, "policy": pol})
        else:
            n = change_labels(path, recursive=True, discard={"policy": pol})
            cfg["applied"] = [a for a in cfg["applied"] if not (a["path"] == path and a["policy"] == pol)]
        compile_and_load(cfg)
        print("%d item(s) updated" % n)
    elif cmd == "private":
        if len(args) != 2:
            die("private PATH OWNER|-")
        path, owner = os.path.realpath(args[0]), args[1]
        if owner == "-":
            change_labels(path, remove=["private"], recursive=True)
            cfg["family"]["private_folders"] = [p for p in cfg["family"]["private_folders"] if p["path"] != path]
        else:
            pwd.getpwnam(owner)
            os.makedirs(path, exist_ok=True)
            change_labels(path, set_={"private": [owner]}, recursive=True)
            cfg["family"]["private_folders"] = [p for p in cfg["family"]["private_folders"] if p["path"] != path] + [{"path": path, "owner": owner}]
        compile_and_load(cfg)
    elif cmd == "useradd":
        if len(args) < 2:
            die("useradd NAME TYPE [FULL NAME]")
        name, typ, full = args[0], args[1], " ".join(args[2:])
        if not core.re.match(r"^[a-z][a-z0-9_-]{0,30}$", name):
            die("User names use lower-case letters, digits, - and _, starting with a letter.")
        password = sys.stdin.read().rstrip("\n")
        run(["useradd", "-m", "-s", "/bin/bash", "-c", full or name, "-G", "users", name])
        if password:
            subprocess.run(["chpasswd"], input="%s:%s\n" % (name, password), text=True, check=True)
        set_account_type(cfg, name, typ)
        compile_and_load(cfg)
    elif cmd == "usertype":
        if len(args) != 2:
            die("usertype NAME TYPE")
        set_account_type(cfg, args[0], args[1])
        compile_and_load(cfg)
    elif cmd == "passwd":
        if len(args) != 1:
            die("passwd NAME")
        password = sys.stdin.read().rstrip("\n")
        subprocess.run(["chpasswd"], input="%s:%s\n" % (args[0], password), text=True, check=True)
    elif cmd == "userdel":
        if len(args) != 1:
            die("userdel NAME")
        if core.account_type(cfg, args[0]) == "admin":
            admins = [u for u, _, _ in core.system_users() if "sudo" in core.user_groups(u)]
            if admins == [args[0]]:
                die("This is the only administrator.")
        run(["userdel", args[0]])
        cfg["users"].pop(args[0], None)
        cfg["family"]["children"].pop(args[0], None)
        compile_and_load(cfg)
    elif cmd == "audit":
        drain_audit()
    elif cmd == "report":
        if len(args) != 1:
            die("report PATH")
        drain_audit()
        report(cfg, args[0])
    else:
        die("unknown command " + cmd)


if __name__ == "__main__":
    main(sys.argv[1:])
