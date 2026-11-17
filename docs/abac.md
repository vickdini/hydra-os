# Hydra access control (ABAC)

Hydra lets an administrator decide who may open which files, run which programs and
perform which administrative tasks from **attributes**: of the user (department,
clearance, role, projects, account type...), of the file (classification, department,
project...) and of the moment (time of day, weekday, managed device, local or remote
session). It is one engine with three faces, like Windows editions:

| Edition | App | What it offers |
|---|---|---|
| **Home** (default) | *Family & accounts* | Administrator / Standard / Child accounts; for children: screen time, blocked apps, web filter; private folders |
| **Pro** | *Hydra Access Center* | Users & attributes, resource properties and file classification, rules, policies applied to folders, Effective Access, audit log, rules for administrative tasks |
| **Enterprise** | *Hydra Access Center* | Pro + conditions on time / device / session, staged (proposed) rules and policies, app control (block lists, allow lists of administrator-installed programs, hashes), sign-in hours, compliance report |

Home users never see a rule: their settings compile into the same rules behind the scenes.
No terminal is needed for anything; every change asks for an administrator's password
(polkit) and is carried out by a small root helper.

## How a decision is made

```
open/exec/unlink ──> mode bits + POSIX ACLs ──allow──> access policy (ABAC) ──allow──> OK
                             │ deny                        │ deny
                             v                             v
                          EACCES                    EACCES + audit record
```

* The policy can only **take rights away** (as Windows central access policies do): the
  usual permissions must allow the access too.
* **root is not restricted** (a process running as root, e.g. through `sudo`, skips the
  check). Ordinary users, including administrators working normally, are.
* A file or folder **without labels**, a process **without attributes** (system services
  started before any login), or **no loaded policy** skip the check after one or two
  memory loads.
* Actions: `r` read, `w` write (and create in a folder), `x` run (for a folder: open it,
  which goes with its read right), `d` delete (unlink, rmdir, moving out of the folder).

### Subjects (users)

At sign-in, hydra-logind gives the session leader the user's attributes; every process
of the session inherits them (fork, exec), and only root can change them:

```
name=alice
uid=1001
groups=alice,users
session.class=user
session.remote=0
account=standard                 <- from /etc/hydra/access/subjects/alice
department=Finance
clearance=Confidential
project=Apollo,Gemini
```

The console login (the kernel's console session, `src/admin/session.rs`) attaches the same file to the programs it starts.

### Resources (files and folders)

Labels live in the `security.hydra.labels` extended attribute (`key=v1,v2` lines). Anyone
may read them; only root (`CAP_SYS_ADMIN`) may set or remove them. A new file or folder
gets its folder's labels. The label `policy=<name>` puts the file under that policy; the
Access Center adds it to a folder and everything inside when a policy is "applied" to it.
Administrative tasks are described with labels too (`action=<polkit id>`,
`category=software|network|time|users|power|devices|system|other`), as is signing in
(`action=session`).

### Rules and policies

A **rule** has a *target* (which files it covers, e.g. `classification exists`) and
*permissions*: each line grants actions when all its conditions hold. Lines of a rule are
ORed, the rules covering a file are ANDed. A **policy** groups rules; it applies where its
`policy` label is, or (a *global* policy) to every labelled file.

Conditions compare attributes: `==` (some value in common), `!=`, `>=` `<=` `>` `<`
(ordered values such as `Public < Internal < Confidential < Secret`, or numbers like
`env.time` = HHMM), `in` (member of: all left values among the right ones), `any`
(any of), `exists`, `not exists`. A missing attribute makes a comparison false, so a rule
never grants on unknown data.

Example (*Department and clearance*):

```
allow rwxd  if user.department == res.department and user.clearance >= res.classification
allow rx    if user.role == "Auditor"
```

### Staging (Enterprise)

A rule or policy can be **staged**: it is evaluated next to the enforced ones and only
logged — `staged-would-deny` when it would refuse something now allowed,
`deny-staged-would-allow` the other way round. A staged rule can be marked as the proposed
replacement of an enforced rule. Check the audit log, then untick "staged".

### App control (Enterprise; Home "blocked apps")

At `execve`, the program's path is checked against app rules for the user:

* **block** rules (by path or folder, program name, SHA-256 hash) stop it;
* **allow** rules turn on an *allow list* for the users they apply to: only matching
  programs run. "Installed by the administrator" matches programs owned by root, not
  writable by others, in a root-owned folder not writable by others (like Windows'
  Program Files rule).

Limits: libraries and programs loaded by an interpreter (`python3 script.py`,
`ld.so ./program`) are not checked separately; block the interpreter for such users.

### Administrative tasks

`/etc/polkit-1/rules.d/60-hydra-access.rules` asks `hydra-access-check polkit <action>
<user>` for every polkit decision; when a rule of *Administrative actions* refuses the
user, polkit answers no without even showing the password dialog. Otherwise polkit's usual
rules apply (administrators are asked for their password).

### Sign-in hours and screen time

`hydra-access-check login` runs in SDDM's PAM stack (`pam_exec`, account phase): outside
the allowed hours the sign-in is refused. hydra-logind re-checks open sessions every 30 s
and ends those outside their hours.

### Web filter (Home)

For a child with the web filter on, Firefox's AutoConfig file locks its proxy setting to a
per-child proxy auto-config script that refuses blocked sites (or everything but the
allowed ones). Other users are not affected; other browsers are not filtered (block them
on the Apps tab).

## Files

| Path | What |
|---|---|
| `/etc/hydra/access/config.json` | The configuration the apps edit (root, 0644) |
| `/etc/hydra/access/policy.compiled` | Kernel policy text; loaded at boot and after each change |
| `/etc/hydra/access/subjects/<user>` | Each user's attributes |
| `/var/log/hydra/access.log` | Audit log (root:sudo 0640), written by hydra-logind / the helper |
| `/usr/lib/hydra-access/hydra_access/` | The apps (Python 3, PyQt6) |
| `/usr/libexec/hydra-access-helper` | Root helper (pkexec, polkit action `org.hydra.access.manage`) |
| `/usr/libexec/hydra-access-check` | polkit / PAM check |
| `/usr/share/kio/servicemenus/hydra-access.desktop` | Dolphin: *Access control → Classification… / Effective access…* |

## Kernel interface

`prctl(PR_HYDRA_ACCESS = 0x48594401, cmd, ...)` (src/compat/linux/abac.rs):

| cmd | Arguments | Who |
|---|---|---|
| 1 LOAD | text, length (0 = unload) | root |
| 2 SET_SUBJECT | pid (0 = self), text, length | root |
| 3 GET_SUBJECT | pid, buffer, size | self; others: root |
| 4 READ_AUDIT | 0, buffer, size | root |
| 5 EVALUATE | query, length \| size << 32, buffer | anyone ("what if" for Effective Access; does not grow kernel tables) |
| 6 STATUS | 0, buffer, size | anyone |

The compiled format is documented at the top of `src/compat/linux/abac_core.rs`.

### Performance

The evaluator never allocates on a decision: attribute names and values are interned when
a policy, subject or label set is loaded; decisions are cached per (policy generation,
subject, label set, local minute when a rule reads the time) in a fixed table; labels are
cached per (inode, generation, change time). Without a policy the check is one atomic load;
with one, an unlabelled file costs one more flag test.

## Tests

* `tests/linux/abac_test.c` (in the KVM suite as `abac`, run as root): 32 checks — allow /
  deny, roles, root and unattributed processes, label protection, label inheritance,
  attributes across fork/exec, delete right, audit with paths, cache invalidation on
  relabel and reload, staging, time conditions, global policies and targets, app control
  (path block, allow list), EVALUATE, unload.
* `tests/host/tests/abac.rs`: the pure evaluator (15 tests, including the compiler's
  output for every feature).

## Verified (2026-11-16, KVM, overlay of the main pool)

* Kernel suite with `abac` (32 checks) all rc=0; host tests 650/0.
* fslat, baseline kernel vs this one (medians of 4-6 runs): equal without a policy and with
  a policy whose files have no labels; in a labelled folder 99.99 % of checks come from
  the decision cache.
* KDE: Family & accounts and Hydra Access Center start from KRunner; saving asks for the
  administrator password (polkit dialog with Hydra's message) and applies at once.
  A child's blocked app (Firefox) fails with "execve: Permission denied"; a folder of
  another department cannot be opened in Dolphin ("Could not enter folder"); Dolphin's
  *Access control → Effective access…* opens the Access Center on the file; changing the
  child's hours ends the running session within 30 s and the sign-in is then refused;
  polkit refuses software installs to a standard user when an administrative rule says
  so (pkcheck: "Not authorized"), other tasks still ask for the password; classification
  dialog, audit log and compliance report work.

Known limits: the first password dialog of a session can take 25-45 s to appear on the VM;
the child web filter (Firefox AutoConfig) was written but not tried in a browser; SDDM
shows only "Login failed" when sign-in hours refuse a sign-in; programs started by an
interpreter or by `ld.so` directly are not separately checked by app control.
