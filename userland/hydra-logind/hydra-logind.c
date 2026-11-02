/*
 * hydra-logind: the part of systemd-logind's D-Bus API that display managers, PAM and
 * Wayland compositors use.
 *
 * Sessions are created by pam_systemd (CreateSession) when a display manager (SDDM) logs
 * in its greeter or a user; a session ends when the process that created it exits (the
 * session's pipe closes) or ReleaseSession is called. Hydra has one seat, seat0, on which
 * one graphical session is active at a time: the newest, or the one activated
 * (ActivateSession, SwitchTo). A session's compositor becomes its controller
 * (TakeControl) and opens the DRM and input devices through TakeDevice; when another
 * session becomes active, its DRM master is dropped and its input devices revoked
 * (PauseDevice), and the newly active one gets fresh descriptors (ResumeDevice).
 *
 * It also answers for systemd-localed (org.freedesktop.locale1, read-only).
 *
 * With --uid N it starts with session 1 for user N, active (a desktop started without a
 * display manager, by hydra-session).
 *
 * Build: gcc -O2 -o hydra-logind hydra-logind.c -I/usr/include/dbus-1.0
 *            -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -ldbus-1
 */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/input.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define BUS_NAME "org.freedesktop.login1"
#define ROOT_PATH "/org/freedesktop/login1"
#define SEAT_PATH ROOT_PATH "/seat/seat0"
#define MANAGER_IFACE "org.freedesktop.login1.Manager"
#define SESSION_IFACE "org.freedesktop.login1.Session"
#define SEAT_IFACE "org.freedesktop.login1.Seat"
#define USER_IFACE "org.freedesktop.login1.User"
#define PROPS_IFACE "org.freedesktop.DBus.Properties"

#define DRM_IOCTL_DROP_MASTER 0x641f
#define DRM_IOCTL_SET_MASTER 0x641e
#define DRM_MAJOR 226
#define INPUT_MAJOR 13

#define MAX_SESSIONS 16
#define MAX_DEVICES 32

static int verbose;
static DBusConnection *bus;

static void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "hydra-logind: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ---------- sessions ---------- */

struct device {
    unsigned major, minor;
    int fd; /* -1 while revoked (the session is not active) */
};

struct session {
    int used;
    char id[16];
    char path[96];
    unsigned uid, gid;
    char user[64];
    pid_t leader;
    char service[32], type[16], klass[16], desktop[32], tty[32], display[32], remote_host[64], remote_user[64];
    int remote;
    unsigned vtnr;
    int on_seat; /* on seat0 */
    int fifo;    /* read end of the session's pipe (-1: none) */
    unsigned long long timestamp;
    char controller[256];
    struct device dev[MAX_DEVICES];
    int ndev;
    int idle_hint, locked_hint;
};

static struct session sessions[MAX_SESSIONS];
static int active = -1;
static unsigned next_id = 1;

static unsigned long long now_usec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
}

/* D-Bus object path element for `id` (sd_bus_path_encode: a leading digit and anything
 * but letters and digits become _XX). */
static void path_encode(const char *prefix, const char *id, char *out, size_t len) {
    size_t n = snprintf(out, len, "%s/", prefix);
    for (const char *p = id; *p && n + 4 < len; p++) {
        int ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9' && p != id);
        if (ok)
            out[n++] = *p;
        else
            n += snprintf(out + n, len - n, "_%02x", (unsigned char)*p);
    }
    out[n] = 0;
}

static void user_path(unsigned uid, char *out, size_t len) {
    snprintf(out, len, ROOT_PATH "/user/_%u", uid);
}

static int session_by_id(const char *id) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].used && !strcmp(sessions[i].id, id))
            return i;
    return -1;
}

static int session_by_path(const char *path) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].used && !strcmp(sessions[i].path, path))
            return i;
    return -1;
}

static int user_has_sessions(unsigned uid) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].used && sessions[i].uid == uid)
            return 1;
    return 0;
}

/* Parent and real uid of a process, from /proc/<pid>/status. */
static int proc_status(pid_t pid, pid_t *ppid, unsigned *uid) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return -1;
    *ppid = 0;
    *uid = (unsigned)-1;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "PPid:", 5))
            *ppid = atoi(line + 5);
        else if (!strncmp(line, "Uid:", 4))
            *uid = (unsigned)strtoul(line + 4, NULL, 10);
    }
    fclose(f);
    return 0;
}

/* Session of process `pid`: the session whose leader it descends from; failing that, the
 * active session of its user, or any session of its user. */
static int session_of_pid(pid_t pid) {
    unsigned uid = (unsigned)-1, u;
    pid_t p = pid, parent;
    for (int depth = 0; p > 1 && depth < 64; depth++) {
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (sessions[i].used && sessions[i].leader == p)
                return i;
        if (proc_status(p, &parent, &u) < 0)
            break;
        if (uid == (unsigned)-1)
            uid = u;
        p = parent;
    }
    if (active >= 0 && sessions[active].uid == uid)
        return active;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].used && sessions[i].uid == uid)
            return i;
    return -1;
}

/* Process id and uid of the sender of `m`, from the bus daemon. */
static int sender_creds(DBusMessage *m, pid_t *pid, unsigned *uid) {
    const char *sender = dbus_message_get_sender(m);
    DBusError err;
    dbus_error_init(&err);
    for (int k = 0; k < 2; k++) {
        DBusMessage *q = dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                                      k ? "GetConnectionUnixUser" : "GetConnectionUnixProcessID");
        dbus_message_append_args(q, DBUS_TYPE_STRING, &sender, DBUS_TYPE_INVALID);
        DBusMessage *r = dbus_connection_send_with_reply_and_block(bus, q, 2000, &err);
        dbus_message_unref(q);
        if (!r) {
            dbus_error_free(&err);
            return -1;
        }
        dbus_uint32_t v = 0;
        dbus_message_get_args(r, NULL, DBUS_TYPE_UINT32, &v, DBUS_TYPE_INVALID);
        dbus_message_unref(r);
        if (k)
            *uid = v;
        else
            *pid = (pid_t)v;
    }
    return 0;
}

static int caller_session(DBusMessage *m) {
    pid_t pid;
    unsigned uid;
    if (sender_creds(m, &pid, &uid) < 0)
        return -1;
    return session_of_pid(pid);
}

/* ---------- signals ---------- */

static void emit(DBusMessage *sig) {
    dbus_connection_send(bus, sig, NULL);
    dbus_message_unref(sig);
}

static void variant_basic(DBusMessageIter *it, int type, const void *value) {
    char sig[2] = {(char)type, 0};
    DBusMessageIter v;
    dbus_message_iter_open_container(it, DBUS_TYPE_VARIANT, sig, &v);
    dbus_message_iter_append_basic(&v, type, value);
    dbus_message_iter_close_container(it, &v);
}

/* A (so) or (uo) structure, optionally wrapped in a variant. */
static void struct_xo(DBusMessageIter *it, int first_type, const void *first, const char *path, int in_variant) {
    DBusMessageIter v, s;
    DBusMessageIter *outer = it;
    if (in_variant) {
        dbus_message_iter_open_container(it, DBUS_TYPE_VARIANT, first_type == DBUS_TYPE_STRING ? "(so)" : "(uo)", &v);
        outer = &v;
    }
    dbus_message_iter_open_container(outer, DBUS_TYPE_STRUCT, NULL, &s);
    dbus_message_iter_append_basic(&s, first_type, first);
    dbus_message_iter_append_basic(&s, DBUS_TYPE_OBJECT_PATH, &path);
    dbus_message_iter_close_container(outer, &s);
    if (in_variant)
        dbus_message_iter_close_container(it, &v);
}

static void dict_entry_start(DBusMessageIter *dict, DBusMessageIter *entry, const char *name) {
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, entry);
    dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &name);
}

static int append_property(DBusMessageIter *it, const char *iface, int s, const char *name);

/* PropertiesChanged for `names` of object `path` (the values as they are now). */
static void properties_changed(const char *path, const char *iface, int s, const char *const *names) {
    DBusMessage *sig = dbus_message_new_signal(path, PROPS_IFACE, "PropertiesChanged");
    DBusMessageIter it, dict, entry, inval;
    dbus_message_iter_init_append(sig, &it);
    dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &iface);
    dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "{sv}", &dict);
    for (int i = 0; names[i]; i++) {
        dict_entry_start(&dict, &entry, names[i]);
        append_property(&entry, iface, s, names[i]);
        dbus_message_iter_close_container(&dict, &entry);
    }
    dbus_message_iter_close_container(&it, &dict);
    dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "s", &inval);
    dbus_message_iter_close_container(&it, &inval);
    emit(sig);
}

/* A signal to the controller of session `s` only (PauseDevice, ResumeDevice). */
static DBusMessage *controller_signal(int s, const char *member) {
    DBusMessage *sig = dbus_message_new_signal(sessions[s].path, SESSION_IFACE, member);
    dbus_message_set_destination(sig, sessions[s].controller);
    return sig;
}

/* ---------- devices ---------- */

/* /dev path of a character device, from its sysfs uevent (DEVNAME=...). */
static int device_path(unsigned major, unsigned minor, char *out, size_t len) {
    char path[128], line[256];
    snprintf(path, sizeof path, "/sys/dev/char/%u:%u/uevent", major, minor);
    FILE *f = fopen(path, "re");
    if (!f)
        return -1;
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "DEVNAME=", 8) == 0) {
            line[strcspn(line, "\n")] = 0;
            snprintf(out, len, "/dev/%s", line + 8);
            found = 0;
        }
    }
    fclose(f);
    return found;
}

static int open_device(unsigned major, unsigned minor, int as_active) {
    char path[160];
    if (device_path(major, minor, path, sizeof path) < 0)
        return -ENODEV;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
        return -errno;
    if (major == DRM_MAJOR)
        ioctl(fd, as_active ? DRM_IOCTL_SET_MASTER : DRM_IOCTL_DROP_MASTER, 0);
    return fd;
}

/* Stops session `s`'s access to its devices: DRM master dropped, input revoked. */
static void pause_devices(int s) {
    struct session *se = &sessions[s];
    for (int i = 0; i < se->ndev; i++) {
        struct device *d = &se->dev[i];
        if (d->fd < 0)
            continue;
        if (d->major == DRM_MAJOR) {
            ioctl(d->fd, DRM_IOCTL_DROP_MASTER, 0);
        } else {
            ioctl(d->fd, EVIOCREVOKE, 0);
            close(d->fd);
            d->fd = -1;
        }
        if (*se->controller) {
            const char *how = "force";
            DBusMessage *sig = controller_signal(s, "PauseDevice");
            dbus_message_append_args(sig, DBUS_TYPE_UINT32, &d->major, DBUS_TYPE_UINT32, &d->minor, DBUS_TYPE_STRING, &how, DBUS_TYPE_INVALID);
            emit(sig);
        }
    }
}

/* Gives session `s` its devices back: DRM master, fresh input descriptors. */
static void resume_devices(int s) {
    struct session *se = &sessions[s];
    for (int i = 0; i < se->ndev; i++) {
        struct device *d = &se->dev[i];
        if (d->fd < 0) {
            d->fd = open_device(d->major, d->minor, 1);
            if (d->fd < 0)
                continue;
        } else if (d->major == DRM_MAJOR) {
            ioctl(d->fd, DRM_IOCTL_SET_MASTER, 0);
        }
        if (*se->controller) {
            DBusMessage *sig = controller_signal(s, "ResumeDevice");
            dbus_message_append_args(sig, DBUS_TYPE_UINT32, &d->major, DBUS_TYPE_UINT32, &d->minor, DBUS_TYPE_UNIX_FD, &d->fd, DBUS_TYPE_INVALID);
            emit(sig);
        }
    }
}

static void release_device(int s, unsigned major, unsigned minor) {
    struct session *se = &sessions[s];
    for (int i = 0; i < se->ndev; i++) {
        struct device *d = &se->dev[i];
        if (d->major == major && d->minor == minor) {
            if (d->fd >= 0) {
                if (major == INPUT_MAJOR)
                    ioctl(d->fd, EVIOCREVOKE, 0);
                else if (major == DRM_MAJOR)
                    ioctl(d->fd, DRM_IOCTL_DROP_MASTER, 0);
                close(d->fd);
            }
            se->dev[i] = se->dev[--se->ndev];
            return;
        }
    }
}

static void release_all(int s) {
    while (sessions[s].ndev > 0)
        release_device(s, sessions[s].dev[0].major, sessions[s].dev[0].minor);
}

/* ---------- activation ---------- */

static const char *const session_active_props[] = {"Active", "State", NULL};
static const char *const seat_active_props[] = {"ActiveSession", NULL};

/* Makes session `s` the one on the display (-1: none). */
static void activate(int s) {
    if (s == active)
        return;
    int old = active;
    if (old >= 0) {
        pause_devices(old);
        active = -1;
        properties_changed(sessions[old].path, SESSION_IFACE, old, session_active_props);
    }
    active = s;
    if (s >= 0) {
        resume_devices(s);
        properties_changed(sessions[s].path, SESSION_IFACE, s, session_active_props);
        logmsg("session %s (%s, %s) is active", sessions[s].id, sessions[s].user, sessions[s].klass);
    }
    properties_changed(SEAT_PATH, SEAT_IFACE, -1, seat_active_props);
}

/* The session to show when the active one goes away: the newest graphical one. */
static int next_graphical(void) {
    int best = -1;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].used && sessions[i].on_seat && (best < 0 || sessions[i].timestamp > sessions[best].timestamp))
            best = i;
    return best;
}

static void remove_session(int s) {
    struct session *se = &sessions[s];
    logmsg("session %s (%s) ended", se->id, se->user);
    release_all(s);
    if (se->fifo >= 0)
        close(se->fifo);
    se->fifo = -1;
    int was_active = (s == active);
    if (was_active) {
        active = -1;
        properties_changed(SEAT_PATH, SEAT_IFACE, -1, seat_active_props);
    }
    se->used = 0;
    const char *id = se->id;
    const char *path = se->path;
    DBusMessage *sig = dbus_message_new_signal(ROOT_PATH, MANAGER_IFACE, "SessionRemoved");
    dbus_message_append_args(sig, DBUS_TYPE_STRING, &id, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
    emit(sig);
    if (!user_has_sessions(se->uid)) {
        char upath[64];
        const char *up = upath;
        user_path(se->uid, upath, sizeof upath);
        dbus_uint32_t uid = se->uid;
        sig = dbus_message_new_signal(ROOT_PATH, MANAGER_IFACE, "UserRemoved");
        dbus_message_append_args(sig, DBUS_TYPE_UINT32, &uid, DBUS_TYPE_OBJECT_PATH, &up, DBUS_TYPE_INVALID);
        emit(sig);
    }
    if (was_active)
        activate(next_graphical());
}

/* Creates /run/user/<uid> for a user's first session. */
static void make_runtime_dir(unsigned uid, unsigned gid, char *out, size_t len) {
    snprintf(out, len, "/run/user/%u", uid);
    mkdir("/run/user", 0755);
    mkdir(out, 0700);
    if (chown(out, uid, gid) < 0)
        logmsg("chown %s: %s", out, strerror(errno));
    chmod(out, 0700);
}

static int add_session(unsigned uid, pid_t leader, const char *service, const char *type, const char *klass, const char *desktop,
                       const char *seat, unsigned vtnr, const char *tty, const char *display, int remote, const char *remote_user,
                       const char *remote_host) {
    int s = -1;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (!sessions[i].used) {
            s = i;
            break;
        }
    if (s < 0)
        return -1;
    int first_of_user = !user_has_sessions(uid);
    struct session *se = &sessions[s];
    memset(se, 0, sizeof *se);
    se->used = 1;
    se->fifo = -1;
    snprintf(se->id, sizeof se->id, "%u", next_id++);
    path_encode(ROOT_PATH "/session", se->id, se->path, sizeof se->path);
    se->uid = uid;
    struct passwd *pw = getpwuid(uid);
    se->gid = pw ? pw->pw_gid : uid;
    snprintf(se->user, sizeof se->user, "%s", pw ? pw->pw_name : "unknown");
    se->leader = leader;
    snprintf(se->service, sizeof se->service, "%s", service);
    snprintf(se->type, sizeof se->type, "%s", *type ? type : "unspecified");
    snprintf(se->klass, sizeof se->klass, "%s", *klass ? klass : "user");
    snprintf(se->desktop, sizeof se->desktop, "%s", desktop);
    snprintf(se->tty, sizeof se->tty, "%s", tty);
    snprintf(se->display, sizeof se->display, "%s", display);
    snprintf(se->remote_user, sizeof se->remote_user, "%s", remote_user);
    snprintf(se->remote_host, sizeof se->remote_host, "%s", remote_host);
    se->remote = remote;
    se->on_seat = !remote && (!*seat || !strcmp(seat, "seat0")) && strcmp(se->klass, "background") != 0;
    se->vtnr = se->on_seat ? (vtnr ? vtnr : 2) : 0;
    se->timestamp = now_usec();

    const char *id = se->id;
    const char *path = se->path;
    DBusMessage *sig = dbus_message_new_signal(ROOT_PATH, MANAGER_IFACE, "SessionNew");
    dbus_message_append_args(sig, DBUS_TYPE_STRING, &id, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
    emit(sig);
    if (first_of_user) {
        char upath[64];
        const char *up = upath;
        user_path(uid, upath, sizeof upath);
        dbus_uint32_t u = uid;
        sig = dbus_message_new_signal(ROOT_PATH, MANAGER_IFACE, "UserNew");
        dbus_message_append_args(sig, DBUS_TYPE_UINT32, &u, DBUS_TYPE_OBJECT_PATH, &up, DBUS_TYPE_INVALID);
        emit(sig);
    }
    logmsg("session %s for %s (uid %u, %s, %s, vt %u)", se->id, se->user, uid, se->klass, se->type, se->vtnr);
    /* A new graphical session takes the display, as a VT switch to it would */
    if (se->on_seat && (!strcmp(se->klass, "user") || !strcmp(se->klass, "greeter")))
        activate(s);
    return s;
}

/* ---------- properties ---------- */

static int append_property(DBusMessageIter *it, const char *iface, int s, const char *name) {
    const char *str;
    dbus_bool_t b;
    dbus_uint32_t u;
    dbus_uint64_t t;
    const char *seat = "seat0";
    if (!strcmp(iface, SESSION_IFACE) && s >= 0) {
        struct session *se = &sessions[s];
        if (!strcmp(name, "Id")) { str = se->id; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "User")) {
            char up[64];
            user_path(se->uid, up, sizeof up);
            u = se->uid;
            struct_xo(it, DBUS_TYPE_UINT32, &u, up, 1);
            return 1;
        }
        if (!strcmp(name, "Name")) { str = se->user; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Timestamp") || !strcmp(name, "TimestampMonotonic")) { t = se->timestamp; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
        if (!strcmp(name, "VTNr")) { u = se->vtnr; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "Seat")) {
            const char *sid = se->on_seat ? "seat0" : "";
            struct_xo(it, DBUS_TYPE_STRING, &sid, se->on_seat ? SEAT_PATH : "/", 1);
            return 1;
        }
        if (!strcmp(name, "TTY")) { str = se->tty; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Display")) { str = se->display; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "RemoteHost")) { str = se->remote_host; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "RemoteUser")) { str = se->remote_user; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Desktop")) { str = se->desktop; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Service")) { str = se->service; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Scope")) {
            static char scope[48];
            snprintf(scope, sizeof scope, "session-%s.scope", se->id);
            str = scope;
            variant_basic(it, DBUS_TYPE_STRING, &str);
            return 1;
        }
        if (!strcmp(name, "Type")) { str = se->type; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Class")) { str = se->klass; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "State")) { str = s == active ? "active" : "online"; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "Active")) { b = s == active; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "Remote")) { b = se->remote; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "IdleHint")) { b = se->idle_hint; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "LockedHint")) { b = se->locked_hint; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "CanIdle") || !strcmp(name, "CanLock")) { b = se->on_seat; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "Leader")) { u = se->leader; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "Audit")) { u = 0; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "IdleSinceHint") || !strcmp(name, "IdleSinceHintMonotonic")) { t = 0; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
    } else if (!strcmp(iface, SEAT_IFACE)) {
        if (!strcmp(name, "Id")) { variant_basic(it, DBUS_TYPE_STRING, &seat); return 1; }
        if (!strcmp(name, "ActiveSession")) {
            const char *sid = active >= 0 ? sessions[active].id : "";
            struct_xo(it, DBUS_TYPE_STRING, &sid, active >= 0 ? sessions[active].path : "/", 1);
            return 1;
        }
        if (!strcmp(name, "CanTTY") || !strcmp(name, "CanGraphical") || !strcmp(name, "CanMultiSession")) { b = TRUE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "IdleHint")) { b = FALSE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "IdleSinceHint") || !strcmp(name, "IdleSinceHintMonotonic")) { t = 0; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
        if (!strcmp(name, "Sessions")) {
            DBusMessageIter v, a;
            dbus_message_iter_open_container(it, DBUS_TYPE_VARIANT, "a(so)", &v);
            dbus_message_iter_open_container(&v, DBUS_TYPE_ARRAY, "(so)", &a);
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (sessions[i].used && sessions[i].on_seat) {
                    const char *sid = sessions[i].id;
                    struct_xo(&a, DBUS_TYPE_STRING, &sid, sessions[i].path, 0);
                }
            dbus_message_iter_close_container(&v, &a);
            dbus_message_iter_close_container(it, &v);
            return 1;
        }
    } else if (!strcmp(iface, MANAGER_IFACE)) {
        if (!strcmp(name, "NAutoVTs")) { u = 6; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "IdleHint") || !strcmp(name, "PreparingForSleep") || !strcmp(name, "PreparingForShutdown") || !strcmp(name, "Docked") ||
            !strcmp(name, "LidClosed") || !strcmp(name, "KillUserProcesses")) {
            b = FALSE;
            variant_basic(it, DBUS_TYPE_BOOLEAN, &b);
            return 1;
        }
        if (!strcmp(name, "BlockInhibited") || !strcmp(name, "DelayInhibited") || !strcmp(name, "HandleLidSwitch") || !strcmp(name, "HandlePowerKey")) {
            str = !strncmp(name, "Handle", 6) ? "ignore" : "";
            variant_basic(it, DBUS_TYPE_STRING, &str);
            return 1;
        }
        if (!strcmp(name, "InhibitDelayMaxUSec")) { t = 5000000; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
    } else if (!strcmp(iface, USER_IFACE)) {
        /* `s` is the uid here */
        unsigned uid = (unsigned)s;
        int primary = -1, n = 0;
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (sessions[i].used && sessions[i].uid == uid) {
                n++;
                if (primary < 0 || i == active)
                    primary = i;
            }
        if (!strcmp(name, "UID")) { u = uid; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "GID")) { u = primary >= 0 ? sessions[primary].gid : uid; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "Name")) { str = primary >= 0 ? sessions[primary].user : ""; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "State")) { str = n == 0 ? "offline" : (active >= 0 && sessions[active].uid == uid) ? "active" : "online"; variant_basic(it, DBUS_TYPE_STRING, &str); return 1; }
        if (!strcmp(name, "RuntimePath")) {
            static char rp[64];
            snprintf(rp, sizeof rp, "/run/user/%u", uid);
            str = rp;
            variant_basic(it, DBUS_TYPE_STRING, &str);
            return 1;
        }
        if (!strcmp(name, "Linger") || !strcmp(name, "IdleHint")) { b = FALSE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "Timestamp") || !strcmp(name, "TimestampMonotonic")) { t = primary >= 0 ? sessions[primary].timestamp : 0; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
        if (!strcmp(name, "Display")) {
            const char *sid = primary >= 0 ? sessions[primary].id : "";
            struct_xo(it, DBUS_TYPE_STRING, &sid, primary >= 0 ? sessions[primary].path : "/", 1);
            return 1;
        }
        if (!strcmp(name, "Sessions")) {
            DBusMessageIter v, a;
            dbus_message_iter_open_container(it, DBUS_TYPE_VARIANT, "a(so)", &v);
            dbus_message_iter_open_container(&v, DBUS_TYPE_ARRAY, "(so)", &a);
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (sessions[i].used && sessions[i].uid == uid) {
                    const char *sid = sessions[i].id;
                    struct_xo(&a, DBUS_TYPE_STRING, &sid, sessions[i].path, 0);
                }
            dbus_message_iter_close_container(&v, &a);
            dbus_message_iter_close_container(it, &v);
            return 1;
        }
    }
    return 0;
}

static const char *const session_props[] = {"Id", "User", "Name", "Timestamp", "TimestampMonotonic", "VTNr", "Seat", "TTY", "Display", "Remote",
    "RemoteHost", "RemoteUser", "Service", "Desktop", "Scope", "Leader", "Audit", "Type", "Class", "Active", "State", "IdleHint",
    "IdleSinceHint", "IdleSinceHintMonotonic", "LockedHint", "CanIdle", "CanLock", NULL};
static const char *const seat_props[] = {"Id", "ActiveSession", "CanTTY", "CanGraphical", "CanMultiSession", "Sessions", "IdleHint",
    "IdleSinceHint", "IdleSinceHintMonotonic", NULL};
static const char *const manager_props[] = {"NAutoVTs", "IdleHint", "PreparingForSleep", "PreparingForShutdown", "Docked", "LidClosed",
    "KillUserProcesses", "BlockInhibited", "DelayInhibited", "HandleLidSwitch", "HandlePowerKey", "InhibitDelayMaxUSec", NULL};
static const char *const user_props[] = {"UID", "GID", "Name", "State", "RuntimePath", "Linger", "IdleHint", "Timestamp",
    "TimestampMonotonic", "Display", "Sessions", NULL};

/* ---------- objects ---------- */

enum object_kind { OBJ_NONE, OBJ_MANAGER, OBJ_SESSION, OBJ_SEAT, OBJ_USER };

/* What `path` names; `*index` is a session index or a uid. */
static enum object_kind object_of_path(DBusMessage *m, const char *path, int *index) {
    *index = -1;
    if (!strcmp(path, ROOT_PATH))
        return OBJ_MANAGER;
    if (!strcmp(path, SEAT_PATH) || !strcmp(path, ROOT_PATH "/seat/auto") || !strcmp(path, ROOT_PATH "/seat/self"))
        return OBJ_SEAT;
    if (!strcmp(path, ROOT_PATH "/session/auto") || !strcmp(path, ROOT_PATH "/session/self")) {
        *index = caller_session(m);
        if (*index < 0 && !strcmp(path, ROOT_PATH "/session/auto"))
            *index = active;
        return *index >= 0 ? OBJ_SESSION : OBJ_NONE;
    }
    int s = session_by_path(path);
    if (s >= 0) {
        *index = s;
        return OBJ_SESSION;
    }
    if (!strcmp(path, ROOT_PATH "/user/self")) {
        pid_t pid;
        unsigned uid;
        if (sender_creds(m, &pid, &uid) < 0)
            return OBJ_NONE;
        *index = (int)uid;
        return OBJ_USER;
    }
    if (!strncmp(path, ROOT_PATH "/user/_", strlen(ROOT_PATH "/user/_"))) {
        unsigned uid = (unsigned)strtoul(path + strlen(ROOT_PATH "/user/_"), NULL, 10);
        if (!user_has_sessions(uid))
            return OBJ_NONE;
        *index = (int)uid;
        return OBJ_USER;
    }
    return OBJ_NONE;
}

static const char *iface_of(enum object_kind k) {
    switch (k) {
    case OBJ_MANAGER: return MANAGER_IFACE;
    case OBJ_SESSION: return SESSION_IFACE;
    case OBJ_SEAT: return SEAT_IFACE;
    case OBJ_USER: return USER_IFACE;
    default: return NULL;
    }
}

static DBusMessage *error(DBusMessage *m, const char *name, const char *text) {
    return dbus_message_new_error(m, name, text);
}

static DBusMessage *reply_path(DBusMessage *m, const char *path) {
    DBusMessage *r = dbus_message_new_method_return(m);
    dbus_message_append_args(r, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
    return r;
}

static DBusMessage *reply_string(DBusMessage *m, const char *s) {
    DBusMessage *r = dbus_message_new_method_return(m);
    dbus_message_append_args(r, DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID);
    return r;
}

static const char introspect_xml[] =
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" "
    "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
    "<node><interface name=\"org.freedesktop.DBus.Introspectable\"><method name=\"Introspect\"><arg name=\"xml\" type=\"s\" direction=\"out\"/></method></interface>"
    "<interface name=\"org.freedesktop.DBus.Properties\"><method name=\"Get\"><arg type=\"s\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" direction=\"out\"/></method>"
    "<method name=\"GetAll\"><arg type=\"s\" direction=\"in\"/><arg type=\"a{sv}\" direction=\"out\"/></method></interface></node>\n";

static DBusMessage *handle_properties(DBusMessage *m, enum object_kind kind, int index, const char *member) {
    const char *obj_iface = iface_of(kind);
    const char *iface = NULL, *name = NULL;
    if (!strcmp(member, "Get")) {
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
            return error(m, DBUS_ERROR_INVALID_ARGS, "Get(ss)");
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it;
        dbus_message_iter_init_append(r, &it);
        if ((*iface && strcmp(iface, obj_iface)) || !append_property(&it, obj_iface, index, name)) {
            dbus_message_unref(r);
            return error(m, DBUS_ERROR_UNKNOWN_PROPERTY, name);
        }
        return r;
    }
    if (!strcmp(member, "GetAll")) {
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &iface, DBUS_TYPE_INVALID))
            return error(m, DBUS_ERROR_INVALID_ARGS, "GetAll(s)");
        const char *const *list = kind == OBJ_SESSION ? session_props : kind == OBJ_SEAT ? seat_props : kind == OBJ_USER ? user_props : manager_props;
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it, dict, entry;
        dbus_message_iter_init_append(r, &it);
        dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "{sv}", &dict);
        if (!*iface || !strcmp(iface, obj_iface)) {
            for (int i = 0; list[i]; i++) {
                dict_entry_start(&dict, &entry, list[i]);
                append_property(&entry, obj_iface, index, list[i]);
                dbus_message_iter_close_container(&dict, &entry);
            }
        }
        dbus_message_iter_close_container(&it, &dict);
        return r;
    }
    if (!strcmp(member, "Set"))
        return error(m, DBUS_ERROR_PROPERTY_READ_ONLY, "read-only");
    return error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
}

/* ---------- manager ---------- */

static int session_arg(DBusMessage *m, const char *id) {
    if (!id || !*id || !strcmp(id, "self") || !strcmp(id, "auto")) {
        int s = caller_session(m);
        return (s < 0 && id && !strcmp(id, "auto")) ? active : s;
    }
    return session_by_id(id);
}

static DBusMessage *session_list(DBusMessage *m) {
    DBusMessage *r = dbus_message_new_method_return(m);
    DBusMessageIter it, a, s;
    dbus_message_iter_init_append(r, &it);
    dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "(susso)", &a);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].used)
            continue;
        const char *id = sessions[i].id, *name = sessions[i].user, *seat = sessions[i].on_seat ? "seat0" : "", *path = sessions[i].path;
        dbus_uint32_t uid = sessions[i].uid;
        dbus_message_iter_open_container(&a, DBUS_TYPE_STRUCT, NULL, &s);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &id);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_UINT32, &uid);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &name);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &seat);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_close_container(&a, &s);
    }
    dbus_message_iter_close_container(&it, &a);
    return r;
}

static DBusMessage *user_list(DBusMessage *m) {
    DBusMessage *r = dbus_message_new_method_return(m);
    DBusMessageIter it, a, s;
    dbus_message_iter_init_append(r, &it);
    dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "(uso)", &a);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].used)
            continue;
        int seen = 0;
        for (int j = 0; j < i; j++)
            if (sessions[j].used && sessions[j].uid == sessions[i].uid)
                seen = 1;
        if (seen)
            continue;
        char up[64];
        user_path(sessions[i].uid, up, sizeof up);
        const char *name = sessions[i].user, *path = up;
        dbus_uint32_t uid = sessions[i].uid;
        dbus_message_iter_open_container(&a, DBUS_TYPE_STRUCT, NULL, &s);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_UINT32, &uid);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &name);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_close_container(&a, &s);
    }
    dbus_message_iter_close_container(&it, &a);
    return r;
}

/* CreateSession(uid, pid, service, type, class, desktop, seat, vtnr, tty, display, remote,
 * remote_user, remote_host, properties) -> (id, path, runtime_path, fifo, uid, seat, vtnr,
 * existing): what pam_systemd calls when a user (or a greeter) logs in. */
static DBusMessage *create_session(DBusMessage *m) {
    dbus_uint32_t uid, pid, vtnr;
    const char *service, *type, *klass, *desktop, *seat, *tty, *display, *ruser, *rhost;
    dbus_bool_t remote;
    DBusMessageIter it;
    dbus_message_iter_init(m, &it);
#define NEXT(t, v) do { if (dbus_message_iter_get_arg_type(&it) != (t)) return error(m, DBUS_ERROR_INVALID_ARGS, "CreateSession(uusssssussbssa(sv))"); dbus_message_iter_get_basic(&it, (v)); dbus_message_iter_next(&it); } while (0)
    NEXT(DBUS_TYPE_UINT32, &uid);
    NEXT(DBUS_TYPE_UINT32, &pid);
    NEXT(DBUS_TYPE_STRING, &service);
    NEXT(DBUS_TYPE_STRING, &type);
    NEXT(DBUS_TYPE_STRING, &klass);
    NEXT(DBUS_TYPE_STRING, &desktop);
    NEXT(DBUS_TYPE_STRING, &seat);
    NEXT(DBUS_TYPE_UINT32, &vtnr);
    NEXT(DBUS_TYPE_STRING, &tty);
    NEXT(DBUS_TYPE_STRING, &display);
    NEXT(DBUS_TYPE_BOOLEAN, &remote);
    NEXT(DBUS_TYPE_STRING, &ruser);
    NEXT(DBUS_TYPE_STRING, &rhost);
#undef NEXT
    pid_t caller_pid;
    unsigned caller_uid;
    if (sender_creds(m, &caller_pid, &caller_uid) < 0 || caller_uid != 0)
        return error(m, DBUS_ERROR_ACCESS_DENIED, "only root creates sessions");
    if (pid == 0)
        pid = caller_pid;
    int s = add_session(uid, pid, service, type, klass, desktop, seat, vtnr, tty, display, remote, ruser, rhost);
    if (s < 0)
        return error(m, DBUS_ERROR_LIMITS_EXCEEDED, "too many sessions");
    struct session *se = &sessions[s];
    char runtime[64];
    make_runtime_dir(se->uid, se->gid, runtime, sizeof runtime);
    int p[2];
    if (pipe2(p, O_CLOEXEC) < 0) {
        remove_session(s);
        return error(m, DBUS_ERROR_FAILED, strerror(errno));
    }
    se->fifo = p[0];
    DBusMessage *r = dbus_message_new_method_return(m);
    const char *id = se->id, *path = se->path, *rp = runtime, *sid = se->on_seat ? "seat0" : "";
    dbus_uint32_t ruid = se->uid, rvt = se->vtnr;
    dbus_bool_t existing = FALSE;
    dbus_message_append_args(r, DBUS_TYPE_STRING, &id, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_STRING, &rp, DBUS_TYPE_UNIX_FD, &p[1],
                             DBUS_TYPE_UINT32, &ruid, DBUS_TYPE_STRING, &sid, DBUS_TYPE_UINT32, &rvt, DBUS_TYPE_BOOLEAN, &existing, DBUS_TYPE_INVALID);
    close(p[1]);
    return r;
}

static DBusMessage *handle_manager(DBusMessage *m, const char *member) {
    const char *id = NULL;
    if (!strcmp(member, "CreateSession"))
        return create_session(m);
    if (!strcmp(member, "CreateSessionWithPIDFD"))
        return error(m, DBUS_ERROR_UNKNOWN_METHOD, member); /* pam_systemd falls back to CreateSession */
    if (!strcmp(member, "ReleaseSession")) {
        dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
        int s = session_by_id(id ? id : "");
        if (s >= 0)
            remove_session(s);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "GetSession")) {
        dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
        int s = session_arg(m, id);
        return s >= 0 ? reply_path(m, sessions[s].path) : error(m, "org.freedesktop.login1.NoSuchSession", "No such session");
    }
    if (!strcmp(member, "GetSessionByPID")) {
        dbus_uint32_t pid = 0;
        dbus_message_get_args(m, NULL, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID);
        int s = pid ? session_of_pid(pid) : caller_session(m);
        return s >= 0 ? reply_path(m, sessions[s].path) : error(m, "org.freedesktop.login1.NoSessionForPID", "PID does not belong to any known session");
    }
    if (!strcmp(member, "GetSeat"))
        return reply_path(m, SEAT_PATH);
    if (!strcmp(member, "GetUser") || !strcmp(member, "GetUserByPID")) {
        dbus_uint32_t v = 0;
        dbus_message_get_args(m, NULL, DBUS_TYPE_UINT32, &v, DBUS_TYPE_INVALID);
        unsigned uid = v;
        if (!strcmp(member, "GetUserByPID")) {
            int s = v ? session_of_pid(v) : caller_session(m);
            if (s < 0)
                return error(m, "org.freedesktop.login1.NoUserForPID", "PID does not belong to any logged in user");
            uid = sessions[s].uid;
        }
        if (!user_has_sessions(uid))
            return error(m, "org.freedesktop.login1.NoSuchUser", "User not logged in");
        char up[64];
        user_path(uid, up, sizeof up);
        return reply_path(m, up);
    }
    if (!strcmp(member, "ListSessions"))
        return session_list(m);
    if (!strcmp(member, "ListUsers"))
        return user_list(m);
    if (!strcmp(member, "ListSeats")) {
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it, a;
        const char *seat = "seat0";
        dbus_message_iter_init_append(r, &it);
        dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "(so)", &a);
        struct_xo(&a, DBUS_TYPE_STRING, &seat, SEAT_PATH, 0);
        dbus_message_iter_close_container(&it, &a);
        return r;
    }
    if (!strcmp(member, "ListInhibitors")) {
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it, a;
        dbus_message_iter_init_append(r, &it);
        dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "(ssssuu)", &a);
        dbus_message_iter_close_container(&it, &a);
        return r;
    }
    if (!strcmp(member, "ActivateSession") || !strcmp(member, "ActivateSessionOnSeat")) {
        dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
        int s = session_by_id(id ? id : "");
        if (s < 0)
            return error(m, "org.freedesktop.login1.NoSuchSession", "No such session");
        activate(s);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "LockSession") || !strcmp(member, "UnlockSession") || !strcmp(member, "LockSessions") || !strcmp(member, "UnlockSessions")) {
        int all = !strcmp(member, "LockSessions") || !strcmp(member, "UnlockSessions");
        int lock = !strncmp(member, "Lock", 4);
        int only = -1;
        if (!all) {
            dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
            only = session_by_id(id ? id : "");
            if (only < 0)
                return error(m, "org.freedesktop.login1.NoSuchSession", "No such session");
        }
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (sessions[i].used && (all || i == only))
                emit(dbus_message_new_signal(sessions[i].path, SESSION_IFACE, lock ? "Lock" : "Unlock"));
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "TerminateSession") || !strcmp(member, "KillSession")) {
        dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
        int s = session_by_id(id ? id : "");
        if (s < 0)
            return error(m, "org.freedesktop.login1.NoSuchSession", "No such session");
        if (sessions[s].leader > 1)
            kill(sessions[s].leader, SIGTERM);
        return dbus_message_new_method_return(m);
    }
    if (!strncmp(member, "Can", 3))
        return reply_string(m, "na");
    if (!strcmp(member, "Inhibit")) {
        /* The caller holds the inhibitor until it closes the descriptor */
        int p[2];
        if (pipe2(p, O_CLOEXEC) < 0)
            return error(m, DBUS_ERROR_FAILED, strerror(errno));
        DBusMessage *r = dbus_message_new_method_return(m);
        dbus_message_append_args(r, DBUS_TYPE_UNIX_FD, &p[1], DBUS_TYPE_INVALID);
        close(p[1]);
        close(p[0]);
        return r;
    }
    return error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
}

/* ---------- seat and session ---------- */

static DBusMessage *handle_seat(DBusMessage *m, const char *member) {
    if (!strcmp(member, "SwitchTo")) {
        dbus_uint32_t vt = 0;
        dbus_message_get_args(m, NULL, DBUS_TYPE_UINT32, &vt, DBUS_TYPE_INVALID);
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (sessions[i].used && sessions[i].on_seat && sessions[i].vtnr == vt)
                activate(i);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "SwitchToNext") || !strcmp(member, "SwitchToPrevious")) {
        int step = !strcmp(member, "SwitchToNext") ? 1 : MAX_SESSIONS - 1;
        for (int k = 1; k < MAX_SESSIONS; k++) {
            int i = ((active < 0 ? 0 : active) + k * step) % MAX_SESSIONS;
            if (sessions[i].used && sessions[i].on_seat) {
                activate(i);
                break;
            }
        }
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "ActivateSession")) {
        const char *id = NULL;
        dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
        int s = session_by_id(id ? id : "");
        if (s >= 0)
            activate(s);
        return dbus_message_new_method_return(m);
    }
    return error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
}

static DBusMessage *handle_session(DBusMessage *m, int s, const char *member) {
    struct session *se = &sessions[s];
    const char *sender = dbus_message_get_sender(m);
    if (!strcmp(member, "TakeControl")) {
        dbus_bool_t force = FALSE;
        dbus_message_get_args(m, NULL, DBUS_TYPE_BOOLEAN, &force, DBUS_TYPE_INVALID);
        pid_t pid;
        unsigned uid;
        if (sender_creds(m, &pid, &uid) < 0 || (uid != se->uid && uid != 0))
            return error(m, DBUS_ERROR_ACCESS_DENIED, "not this session's user");
        if (*se->controller && strcmp(se->controller, sender) && !force)
            return error(m, "org.freedesktop.login1.DeviceIsTaken", "Session already has a controller");
        if (*se->controller && strcmp(se->controller, sender))
            release_all(s);
        snprintf(se->controller, sizeof se->controller, "%s", sender);
        logmsg("session %s controller is %s", se->id, sender);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "ReleaseControl")) {
        if (!strcmp(se->controller, sender)) {
            release_all(s);
            se->controller[0] = 0;
        }
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "TakeDevice") || !strcmp(member, "ReleaseDevice") || !strcmp(member, "PauseDeviceComplete")) {
        dbus_uint32_t major = 0, minor = 0;
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_UINT32, &major, DBUS_TYPE_UINT32, &minor, DBUS_TYPE_INVALID))
            return error(m, DBUS_ERROR_INVALID_ARGS, "(uu)");
        if (strcmp(se->controller, sender))
            return error(m, "org.freedesktop.login1.NotInControl", "You are not in control of this session");
        if (!strcmp(member, "ReleaseDevice")) {
            release_device(s, major, minor);
            return dbus_message_new_method_return(m);
        }
        if (!strcmp(member, "PauseDeviceComplete"))
            return dbus_message_new_method_return(m);
        if (se->ndev >= MAX_DEVICES)
            return error(m, DBUS_ERROR_LIMITS_EXCEEDED, "too many devices");
        int is_active = (s == active);
        int fd = open_device(major, minor, is_active);
        if (fd < 0)
            return error(m, "org.freedesktop.login1.DeviceNotFound", strerror(-fd));
        se->dev[se->ndev++] = (struct device){major, minor, fd};
        if (verbose)
            logmsg("session %s TakeDevice %u:%u%s", se->id, major, minor, is_active ? "" : " (inactive)");
        dbus_bool_t inactive = !is_active;
        DBusMessage *r = dbus_message_new_method_return(m);
        dbus_message_append_args(r, DBUS_TYPE_UNIX_FD, &fd, DBUS_TYPE_BOOLEAN, &inactive, DBUS_TYPE_INVALID);
        return r;
    }
    if (!strcmp(member, "Activate")) {
        activate(s);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "Lock") || !strcmp(member, "Unlock")) {
        emit(dbus_message_new_signal(se->path, SESSION_IFACE, member));
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "SetIdleHint") || !strcmp(member, "SetLockedHint")) {
        dbus_bool_t b = FALSE;
        dbus_message_get_args(m, NULL, DBUS_TYPE_BOOLEAN, &b, DBUS_TYPE_INVALID);
        if (!strcmp(member, "SetIdleHint"))
            se->idle_hint = b;
        else
            se->locked_hint = b;
        static const char *const idle[] = {"IdleHint", NULL}, *const locked[] = {"LockedHint", NULL};
        properties_changed(se->path, SESSION_IFACE, s, !strcmp(member, "SetIdleHint") ? idle : locked);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "SetType") || !strcmp(member, "SetClass") || !strcmp(member, "SetDisplay") || !strcmp(member, "SetTTY")) {
        const char *v = NULL;
        dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &v, DBUS_TYPE_INVALID);
        if (v) {
            if (!strcmp(member, "SetType"))
                snprintf(se->type, sizeof se->type, "%s", v);
            else if (!strcmp(member, "SetClass"))
                snprintf(se->klass, sizeof se->klass, "%s", v);
            else if (!strcmp(member, "SetDisplay"))
                snprintf(se->display, sizeof se->display, "%s", v);
        }
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "SetBrightness"))
        return dbus_message_new_method_return(m);
    if (!strcmp(member, "Terminate") || !strcmp(member, "Kill")) {
        if (se->leader > 1)
            kill(se->leader, SIGTERM);
        return dbus_message_new_method_return(m);
    }
    return error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
}

static DBusHandlerResult on_message(DBusConnection *c, DBusMessage *m, void *data) {
    (void)data;
    if (dbus_message_get_type(m) != DBUS_MESSAGE_TYPE_METHOD_CALL)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    const char *path = dbus_message_get_path(m), *iface = dbus_message_get_interface(m), *member = dbus_message_get_member(m);
    if (!path || !member)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    if (verbose)
        logmsg("%s %s.%s from %s", path, iface ? iface : "?", member, dbus_message_get_sender(m));
    DBusMessage *r = NULL;
    int index;
    enum object_kind kind = object_of_path(m, path, &index);
    if (iface && !strcmp(iface, DBUS_INTERFACE_INTROSPECTABLE))
        r = reply_string(m, introspect_xml);
    else if (kind == OBJ_NONE)
        r = error(m, DBUS_ERROR_UNKNOWN_OBJECT, path);
    else if (iface && !strcmp(iface, PROPS_IFACE))
        r = handle_properties(m, kind, index, member);
    else if (kind == OBJ_MANAGER)
        r = handle_manager(m, member);
    else if (kind == OBJ_SESSION)
        r = handle_session(m, index, member);
    else if (kind == OBJ_SEAT)
        r = handle_seat(m, member);
    else
        r = error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
    if (r) {
        dbus_connection_send(c, r, NULL);
        dbus_message_unref(r);
    }
    return DBUS_HANDLER_RESULT_HANDLED;
}

/* Forget a controller (and close its devices) when it leaves the bus. */
static DBusHandlerResult on_signal(DBusConnection *c, DBusMessage *m, void *data) {
    (void)c;
    (void)data;
    if (dbus_message_is_signal(m, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
        const char *name, *old, *new_owner;
        if (dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old, DBUS_TYPE_STRING, &new_owner, DBUS_TYPE_INVALID) && !*new_owner) {
            for (int i = 0; i < MAX_SESSIONS; i++)
                if (sessions[i].used && *sessions[i].controller && !strcmp(name, sessions[i].controller)) {
                    logmsg("session %s controller %s left", sessions[i].id, name);
                    release_all(i);
                    sessions[i].controller[0] = 0;
                }
        }
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


/*
 * org.freedesktop.locale1: systemd-localed's read side. startplasma takes the keyboard
 * layout of a new user from it; without systemd its activation file only runs /bin/false.
 * The settings come from the files localed reads on Debian and Ubuntu.
 */
#define LOCALE_NAME "org.freedesktop.locale1"
#define LOCALE_PATH "/org/freedesktop/locale1"

static char locale_vars[16][160];
static int nlocale_vars;
static char x11_layout[64], x11_model[64], x11_variant[64], x11_options[160], vc_keymap[64], vc_toggle[64];

/* Calls `fn` for each KEY=value line of `file` (quotes around the value removed). */
static void read_env_file(const char *file, void (*fn)(const char *key, const char *value)) {
    FILE *f = fopen(file, "r");
    char line[256];
    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        char *key = line + strspn(line, " \t"), *eq = strchr(key, '=');
        if (*key == '#' || !eq)
            continue;
        *eq = 0;
        char *v = eq + 1;
        v[strcspn(v, "\r\n")] = 0;
        size_t n = strlen(v);
        if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
            v[n - 1] = 0;
            v++;
        }
        fn(key, v);
    }
    fclose(f);
}

static void locale_var(const char *key, const char *value) {
    if (strcmp(key, "LANG") && strcmp(key, "LANGUAGE") && strncmp(key, "LC_", 3))
        return;
    for (int i = 0; i < nlocale_vars; i++)
        if (!strncmp(locale_vars[i], key, strlen(key)) && locale_vars[i][strlen(key)] == '=')
            return; /* the first file that sets a variable wins */
    if (nlocale_vars < 16)
        snprintf(locale_vars[nlocale_vars++], sizeof locale_vars[0], "%s=%s", key, value);
}

static void keyboard_var(const char *key, const char *value) {
    if (!strcmp(key, "XKBLAYOUT")) snprintf(x11_layout, sizeof x11_layout, "%s", value);
    else if (!strcmp(key, "XKBMODEL")) snprintf(x11_model, sizeof x11_model, "%s", value);
    else if (!strcmp(key, "XKBVARIANT")) snprintf(x11_variant, sizeof x11_variant, "%s", value);
    else if (!strcmp(key, "XKBOPTIONS")) snprintf(x11_options, sizeof x11_options, "%s", value);
    else if (!strcmp(key, "KEYMAP")) snprintf(vc_keymap, sizeof vc_keymap, "%s", value);
    else if (!strcmp(key, "KEYMAP_TOGGLE")) snprintf(vc_toggle, sizeof vc_toggle, "%s", value);
}

/* Rereads the settings, as localed does when they change on disk. */
static void load_locale(void) {
    nlocale_vars = 0;
    x11_layout[0] = x11_model[0] = x11_variant[0] = x11_options[0] = vc_keymap[0] = vc_toggle[0] = 0;
    read_env_file("/etc/locale.conf", locale_var);
    read_env_file("/etc/default/locale", locale_var);
    read_env_file("/etc/default/keyboard", keyboard_var);
    read_env_file("/etc/vconsole.conf", keyboard_var);
}

static const char *const locale_props[] = {"Locale", "VConsoleKeymap", "VConsoleKeymapToggle", "X11Layout", "X11Model", "X11Variant",
    "X11Options", NULL};

static int append_locale_property(DBusMessageIter *it, const char *name) {
    const char *s = !strcmp(name, "VConsoleKeymap") ? vc_keymap
                  : !strcmp(name, "VConsoleKeymapToggle") ? vc_toggle
                  : !strcmp(name, "X11Layout") ? x11_layout
                  : !strcmp(name, "X11Model") ? x11_model
                  : !strcmp(name, "X11Variant") ? x11_variant
                  : !strcmp(name, "X11Options") ? x11_options : NULL;
    if (s) {
        variant_basic(it, DBUS_TYPE_STRING, &s);
        return 1;
    }
    if (strcmp(name, "Locale"))
        return 0;
    DBusMessageIter v, a;
    dbus_message_iter_open_container(it, DBUS_TYPE_VARIANT, "as", &v);
    dbus_message_iter_open_container(&v, DBUS_TYPE_ARRAY, "s", &a);
    for (int i = 0; i < nlocale_vars; i++) {
        const char *var = locale_vars[i];
        dbus_message_iter_append_basic(&a, DBUS_TYPE_STRING, &var);
    }
    dbus_message_iter_close_container(&v, &a);
    dbus_message_iter_close_container(it, &v);
    return 1;
}

static DBusHandlerResult on_locale_message(DBusConnection *c, DBusMessage *m, void *data) {
    (void)data;
    if (dbus_message_get_type(m) != DBUS_MESSAGE_TYPE_METHOD_CALL)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    const char *iface = dbus_message_get_interface(m), *member = dbus_message_get_member(m), *pi = NULL, *name = NULL;
    if (!member)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    if (verbose)
        logmsg("%s %s.%s from %s", LOCALE_PATH, iface ? iface : "?", member, dbus_message_get_sender(m));
    load_locale();
    DBusMessage *r;
    DBusMessageIter it, dict, entry;
    if (iface && !strcmp(iface, DBUS_INTERFACE_INTROSPECTABLE)) {
        r = reply_string(m, introspect_xml);
    } else if (iface && !strcmp(iface, PROPS_IFACE) && !strcmp(member, "Get")) {
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &pi, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)) {
            r = error(m, DBUS_ERROR_INVALID_ARGS, "Get(ss)");
        } else {
            r = dbus_message_new_method_return(m);
            dbus_message_iter_init_append(r, &it);
            if ((*pi && strcmp(pi, LOCALE_NAME)) || !append_locale_property(&it, name)) {
                dbus_message_unref(r);
                r = error(m, DBUS_ERROR_UNKNOWN_PROPERTY, name);
            }
        }
    } else if (iface && !strcmp(iface, PROPS_IFACE) && !strcmp(member, "GetAll")) {
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &pi, DBUS_TYPE_INVALID)) {
            r = error(m, DBUS_ERROR_INVALID_ARGS, "GetAll(s)");
        } else {
            r = dbus_message_new_method_return(m);
            dbus_message_iter_init_append(r, &it);
            dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "{sv}", &dict);
            for (int i = 0; (!*pi || !strcmp(pi, LOCALE_NAME)) && locale_props[i]; i++) {
                dict_entry_start(&dict, &entry, locale_props[i]);
                append_locale_property(&entry, locale_props[i]);
                dbus_message_iter_close_container(&dict, &entry);
            }
            dbus_message_iter_close_container(&it, &dict);
        }
    } else if (iface && !strcmp(iface, PROPS_IFACE) && !strcmp(member, "Set")) {
        r = error(m, DBUS_ERROR_PROPERTY_READ_ONLY, "read-only");
    } else if (!strncmp(member, "Set", 3)) {
        /* SetLocale, SetVConsoleKeyboard, SetX11Keyboard */
        r = error(m, DBUS_ERROR_NOT_SUPPORTED, "the system locale is set by editing /etc/default/locale and /etc/default/keyboard");
    } else {
        r = error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
    }
    dbus_connection_send(c, r, NULL);
    dbus_message_unref(r);
    return DBUS_HANDLER_RESULT_HANDLED;
}


int main(int argc, char **argv) {
    long initial_uid = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--uid") && i + 1 < argc)
            initial_uid = atol(argv[++i]);
        else if (!strcmp(argv[i], "-v"))
            verbose = 1;
    }
    signal(SIGPIPE, SIG_IGN);

    DBusError err;
    dbus_error_init(&err);
    bus = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!bus) {
        logmsg("cannot connect to the system bus: %s", err.message);
        return 1;
    }
    int r = dbus_bus_request_name(bus, BUS_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &err);
    if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        logmsg("cannot own %s: %s", BUS_NAME, dbus_error_is_set(&err) ? err.message : "name taken");
        return 1;
    }
    static const DBusObjectPathVTable vtable = {.message_function = on_message};
    dbus_connection_register_fallback(bus, ROOT_PATH, &vtable, NULL);
    dbus_bus_add_match(bus, "type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'", NULL);
    dbus_connection_add_filter(bus, on_signal, NULL, NULL);
    /* A missing locale service is not worth losing the login manager over */
    if (dbus_bus_request_name(bus, LOCALE_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, NULL) == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        static const DBusObjectPathVTable locale_vtable = {.message_function = on_locale_message};
        dbus_connection_register_object_path(bus, LOCALE_PATH, &locale_vtable, NULL);
    } else {
        logmsg("cannot own %s", LOCALE_NAME);
    }

    /* A desktop started without a display manager: session 1, for --uid, active */
    if (initial_uid >= 0) {
        int s = add_session((unsigned)initial_uid, 0, "hydra", "wayland", "user", "KDE", "seat0", 2, "tty2", "", 0, "", "");
        char runtime[64];
        if (s >= 0)
            make_runtime_dir(sessions[s].uid, sessions[s].gid, runtime, sizeof runtime);
    }
    logmsg("seat0 ready on %s", BUS_NAME);

    /* The bus, and the pipes whose closing ends sessions */
    int busfd = -1;
    dbus_connection_get_unix_fd(bus, &busfd);
    for (;;) {
        while (dbus_connection_dispatch(bus) == DBUS_DISPATCH_DATA_REMAINS)
            ;
        dbus_connection_flush(bus);
        struct pollfd p[1 + MAX_SESSIONS];
        int owner[1 + MAX_SESSIONS];
        int n = 0;
        p[n].fd = busfd;
        p[n].events = POLLIN;
        owner[n++] = -1;
        for (int i = 0; i < MAX_SESSIONS; i++)
            if (sessions[i].used && sessions[i].fifo >= 0) {
                p[n].fd = sessions[i].fifo;
                p[n].events = POLLIN;
                owner[n++] = i;
            }
        if (poll(p, n, -1) < 0 && errno != EINTR)
            break;
        for (int k = 1; k < n; k++) {
            if (!p[k].revents)
                continue;
            char c;
            if (read(p[k].fd, &c, 1) <= 0)
                remove_session(owner[k]);
        }
        if (p[0].revents & (POLLHUP | POLLERR))
            break;
        if (p[0].revents)
            dbus_connection_read_write(bus, 0);
    }
    return 0;
}
