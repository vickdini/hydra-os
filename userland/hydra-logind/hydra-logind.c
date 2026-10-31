/*
 * hydra-logind: the part of systemd-logind's D-Bus API that Wayland compositors use.
 *
 * KWin (and Plasma) find their session through org.freedesktop.login1 on the system bus,
 * become its controller (Session.TakeControl) and open the DRM and evdev devices through
 * Session.TakeDevice, which hands back a descriptor the compositor could not open itself.
 * Hydra has one seat (seat0) with one graphical session ("1") on VT 2, owned by the user
 * given with --uid (default 1000).
 *
 * Build: gcc -O2 -o hydra-logind hydra-logind.c -I/usr/include/dbus-1.0
 *            -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -ldbus-1
 */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
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
#define SESSION_PATH ROOT_PATH "/session/_31"
#define SEAT_PATH ROOT_PATH "/seat/seat0"
#define MANAGER_IFACE "org.freedesktop.login1.Manager"
#define SESSION_IFACE "org.freedesktop.login1.Session"
#define SEAT_IFACE "org.freedesktop.login1.Seat"
#define USER_IFACE "org.freedesktop.login1.User"
#define PROPS_IFACE "org.freedesktop.DBus.Properties"

#define DRM_IOCTL_DROP_MASTER 0x641f
#define DRM_IOCTL_SET_MASTER 0x641e

static unsigned session_uid = 1000;
static char user_path[64];
static char user_name[64] = "user";
static char controller[256];
static unsigned long long boot_usec;
static int verbose;

struct device {
    unsigned major, minor;
    int fd;
};
static struct device devices[32];
static int ndevices;

static void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "hydra-logind: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
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

static int take_device(unsigned major, unsigned minor, int *fd_out) {
    char path[160];
    if (device_path(major, minor, path, sizeof path) < 0)
        return -ENODEV;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
        return -errno;
    if (major == 226)
        ioctl(fd, DRM_IOCTL_SET_MASTER, 0);
    if (ndevices < (int)(sizeof devices / sizeof devices[0]))
        devices[ndevices++] = (struct device){major, minor, fd};
    *fd_out = fd;
    if (verbose)
        logmsg("TakeDevice %u:%u -> %s", major, minor, path);
    return 0;
}

static void release_device(unsigned major, unsigned minor) {
    for (int i = 0; i < ndevices; i++) {
        if (devices[i].major == major && devices[i].minor == minor) {
            if (major == 13)
                ioctl(devices[i].fd, EVIOCREVOKE, 0);
            else if (major == 226)
                ioctl(devices[i].fd, DRM_IOCTL_DROP_MASTER, 0);
            close(devices[i].fd);
            devices[i] = devices[--ndevices];
            return;
        }
    }
}

static void release_all(void) {
    while (ndevices > 0)
        release_device(devices[0].major, devices[0].minor);
}

/* ---------- message helpers ---------- */

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

/* Appends property `name` of object `iface` as a variant; returns 0 if unknown. */
static int append_property(DBusMessageIter *it, const char *iface, const char *name) {
    const char *s;
    dbus_bool_t b;
    dbus_uint32_t u;
    dbus_uint64_t t;
    const char *seat = "seat0", *sid = "1";
    if (strcmp(iface, SESSION_IFACE) == 0) {
        if (!strcmp(name, "Id")) { variant_basic(it, DBUS_TYPE_STRING, &sid); return 1; }
        if (!strcmp(name, "User")) { u = session_uid; struct_xo(it, DBUS_TYPE_UINT32, &u, user_path, 1); return 1; }
        if (!strcmp(name, "Name")) { s = user_name; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "Timestamp") || !strcmp(name, "TimestampMonotonic")) { t = boot_usec; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
        if (!strcmp(name, "VTNr")) { u = 2; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "Seat")) { struct_xo(it, DBUS_TYPE_STRING, &seat, SEAT_PATH, 1); return 1; }
        if (!strcmp(name, "TTY")) { s = "tty2"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "Display") || !strcmp(name, "RemoteHost") || !strcmp(name, "RemoteUser") || !strcmp(name, "Desktop")) {
            s = !strcmp(name, "Desktop") ? "KDE" : ""; variant_basic(it, DBUS_TYPE_STRING, &s); return 1;
        }
        if (!strcmp(name, "Service")) { s = "hydra"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "Scope")) { s = "session-1.scope"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "Type")) { s = "wayland"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "Class")) { s = "user"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "State")) { s = "active"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "Active")) { b = TRUE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "Remote") || !strcmp(name, "IdleHint") || !strcmp(name, "LockedHint")) { b = FALSE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "Leader") || !strcmp(name, "Audit")) { u = 0; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "IdleSinceHint") || !strcmp(name, "IdleSinceHintMonotonic")) { t = 0; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
    } else if (strcmp(iface, SEAT_IFACE) == 0) {
        if (!strcmp(name, "Id")) { variant_basic(it, DBUS_TYPE_STRING, &seat); return 1; }
        if (!strcmp(name, "ActiveSession")) { struct_xo(it, DBUS_TYPE_STRING, &sid, SESSION_PATH, 1); return 1; }
        if (!strcmp(name, "CanTTY") || !strcmp(name, "CanGraphical") || !strcmp(name, "CanMultiSession")) { b = TRUE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "IdleHint")) { b = FALSE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1; }
        if (!strcmp(name, "Sessions")) {
            DBusMessageIter v, a;
            dbus_message_iter_open_container(it, DBUS_TYPE_VARIANT, "a(so)", &v);
            dbus_message_iter_open_container(&v, DBUS_TYPE_ARRAY, "(so)", &a);
            struct_xo(&a, DBUS_TYPE_STRING, &sid, SESSION_PATH, 0);
            dbus_message_iter_close_container(&v, &a);
            dbus_message_iter_close_container(it, &v);
            return 1;
        }
    } else if (strcmp(iface, MANAGER_IFACE) == 0) {
        if (!strcmp(name, "NAutoVTs")) { u = 6; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "IdleHint") || !strcmp(name, "PreparingForSleep") || !strcmp(name, "PreparingForShutdown") || !strcmp(name, "Docked") || !strcmp(name, "LidClosed")) {
            b = FALSE; variant_basic(it, DBUS_TYPE_BOOLEAN, &b); return 1;
        }
        if (!strcmp(name, "BlockInhibited") || !strcmp(name, "DelayInhibited") || !strcmp(name, "HandleLidSwitch") || !strcmp(name, "HandlePowerKey")) {
            s = !strncmp(name, "Handle", 6) ? "ignore" : ""; variant_basic(it, DBUS_TYPE_STRING, &s); return 1;
        }
        if (!strcmp(name, "InhibitDelayMaxUSec")) { t = 5000000; variant_basic(it, DBUS_TYPE_UINT64, &t); return 1; }
    } else if (strcmp(iface, USER_IFACE) == 0) {
        if (!strcmp(name, "UID")) { u = session_uid; variant_basic(it, DBUS_TYPE_UINT32, &u); return 1; }
        if (!strcmp(name, "Name")) { s = user_name; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "State")) { s = "active"; variant_basic(it, DBUS_TYPE_STRING, &s); return 1; }
        if (!strcmp(name, "RuntimePath")) {
            static char rp[64];
            snprintf(rp, sizeof rp, "/run/user/%u", session_uid);
            s = rp; variant_basic(it, DBUS_TYPE_STRING, &s); return 1;
        }
        if (!strcmp(name, "Display")) { const char *id = "1"; struct_xo(it, DBUS_TYPE_STRING, &id, SESSION_PATH, 1); return 1; }
    }
    return 0;
}

static const char *const session_props[] = {"Id", "User", "Name", "Timestamp", "TimestampMonotonic", "VTNr", "Seat", "TTY", "Display", "Remote",
    "RemoteHost", "RemoteUser", "Service", "Desktop", "Scope", "Leader", "Audit", "Type", "Class", "Active", "State", "IdleHint",
    "IdleSinceHint", "IdleSinceHintMonotonic", "LockedHint", NULL};
static const char *const seat_props[] = {"Id", "ActiveSession", "CanTTY", "CanGraphical", "CanMultiSession", "Sessions", "IdleHint", NULL};
static const char *const manager_props[] = {"NAutoVTs", "IdleHint", "PreparingForSleep", "PreparingForShutdown", "Docked", "LidClosed",
    "BlockInhibited", "DelayInhibited", "HandleLidSwitch", "HandlePowerKey", "InhibitDelayMaxUSec", NULL};
static const char *const user_props[] = {"UID", "Name", "State", "RuntimePath", "Display", NULL};

static const char *iface_of_path(const char *path) {
    if (!strcmp(path, ROOT_PATH)) return MANAGER_IFACE;
    if (!strcmp(path, SESSION_PATH) || !strcmp(path, ROOT_PATH "/session/auto") || !strcmp(path, ROOT_PATH "/session/self")) return SESSION_IFACE;
    if (!strcmp(path, SEAT_PATH) || !strcmp(path, ROOT_PATH "/seat/auto") || !strcmp(path, ROOT_PATH "/seat/self")) return SEAT_IFACE;
    if (!strcmp(path, user_path) || !strcmp(path, ROOT_PATH "/user/self")) return USER_IFACE;
    return NULL;
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

static DBusMessage *handle_properties(DBusMessage *m, const char *path, const char *member) {
    const char *obj_iface = iface_of_path(path);
    const char *iface = NULL, *name = NULL;
    if (!obj_iface)
        return error(m, DBUS_ERROR_UNKNOWN_OBJECT, path);
    if (!strcmp(member, "Get")) {
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
            return error(m, DBUS_ERROR_INVALID_ARGS, "Get(ss)");
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it;
        dbus_message_iter_init_append(r, &it);
        if ((*iface && strcmp(iface, obj_iface)) || !append_property(&it, obj_iface, name)) {
            dbus_message_unref(r);
            return error(m, DBUS_ERROR_UNKNOWN_PROPERTY, name);
        }
        return r;
    }
    if (!strcmp(member, "GetAll")) {
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &iface, DBUS_TYPE_INVALID))
            return error(m, DBUS_ERROR_INVALID_ARGS, "GetAll(s)");
        const char *const *list = !strcmp(obj_iface, SESSION_IFACE) ? session_props
                                  : !strcmp(obj_iface, SEAT_IFACE) ? seat_props
                                  : !strcmp(obj_iface, USER_IFACE) ? user_props : manager_props;
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it, dict, entry;
        dbus_message_iter_init_append(r, &it);
        dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "{sv}", &dict);
        if (!*iface || !strcmp(iface, obj_iface)) {
            for (int i = 0; list[i]; i++) {
                dict_entry_start(&dict, &entry, list[i]);
                append_property(&entry, obj_iface, list[i]);
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

static DBusMessage *handle_manager(DBusMessage *m, const char *member) {
    if (!strcmp(member, "GetSession") || !strcmp(member, "GetSessionByPID")) {
        if (!strcmp(member, "GetSession")) {
            const char *id = NULL;
            dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
            if (id && strcmp(id, "1") && strcmp(id, "auto") && strcmp(id, "self") && *id)
                return error(m, "org.freedesktop.login1.NoSuchSession", "No such session");
        }
        return reply_path(m, SESSION_PATH);
    }
    if (!strcmp(member, "GetSeat"))
        return reply_path(m, SEAT_PATH);
    if (!strcmp(member, "GetUser") || !strcmp(member, "GetUserByPID"))
        return reply_path(m, user_path);
    if (!strcmp(member, "ListSessions")) {
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it, a, s;
        const char *id = "1", *seat = "seat0", *path = SESSION_PATH;
        dbus_uint32_t uid = session_uid;
        const char *name = user_name;
        dbus_message_iter_init_append(r, &it);
        dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "(susso)", &a);
        dbus_message_iter_open_container(&a, DBUS_TYPE_STRUCT, NULL, &s);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &id);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_UINT32, &uid);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &name);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_STRING, &seat);
        dbus_message_iter_append_basic(&s, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_close_container(&a, &s);
        dbus_message_iter_close_container(&it, &a);
        return r;
    }
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
    if (!strcmp(member, "ActivateSession") || !strcmp(member, "ActivateSessionOnSeat") || !strcmp(member, "LockSessions") || !strcmp(member, "UnlockSessions"))
        return dbus_message_new_method_return(m);
    return error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
}

static DBusMessage *handle_session(DBusMessage *m, const char *member) {
    const char *sender = dbus_message_get_sender(m);
    if (!strcmp(member, "TakeControl")) {
        dbus_bool_t force = FALSE;
        dbus_message_get_args(m, NULL, DBUS_TYPE_BOOLEAN, &force, DBUS_TYPE_INVALID);
        if (*controller && strcmp(controller, sender) && !force)
            return error(m, "org.freedesktop.login1.DeviceIsTaken", "Session already has a controller");
        if (*controller && strcmp(controller, sender))
            release_all();
        snprintf(controller, sizeof controller, "%s", sender);
        logmsg("session controller is %s", sender);
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "ReleaseControl")) {
        if (!strcmp(controller, sender)) {
            release_all();
            controller[0] = 0;
        }
        return dbus_message_new_method_return(m);
    }
    if (!strcmp(member, "TakeDevice") || !strcmp(member, "ReleaseDevice") || !strcmp(member, "PauseDeviceComplete")) {
        dbus_uint32_t major = 0, minor = 0;
        if (!dbus_message_get_args(m, NULL, DBUS_TYPE_UINT32, &major, DBUS_TYPE_UINT32, &minor, DBUS_TYPE_INVALID))
            return error(m, DBUS_ERROR_INVALID_ARGS, "(uu)");
        if (strcmp(controller, sender))
            return error(m, "org.freedesktop.login1.NotInControl", "You are not in control of this session");
        if (!strcmp(member, "ReleaseDevice")) {
            release_device(major, minor);
            return dbus_message_new_method_return(m);
        }
        if (!strcmp(member, "PauseDeviceComplete"))
            return dbus_message_new_method_return(m);
        int fd;
        int e = take_device(major, minor, &fd);
        if (e < 0)
            return error(m, "org.freedesktop.login1.DeviceNotFound", strerror(-e));
        dbus_bool_t inactive = FALSE;
        DBusMessage *r = dbus_message_new_method_return(m);
        dbus_message_append_args(r, DBUS_TYPE_UNIX_FD, &fd, DBUS_TYPE_BOOLEAN, &inactive, DBUS_TYPE_INVALID);
        return r;
    }
    if (!strcmp(member, "Activate") || !strcmp(member, "Lock") || !strcmp(member, "Unlock") || !strcmp(member, "SetIdleHint") ||
        !strcmp(member, "SetLockedHint") || !strcmp(member, "SetType") || !strcmp(member, "SetClass") || !strcmp(member, "SetDisplay") ||
        !strcmp(member, "SetBrightness") || !strcmp(member, "SetTTY"))
        return dbus_message_new_method_return(m);
    if (!strcmp(member, "Terminate") || !strcmp(member, "Kill"))
        return error(m, DBUS_ERROR_ACCESS_DENIED, "not supported");
    return error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
}

static DBusMessage *handle_seat(DBusMessage *m, const char *member) {
    if (!strcmp(member, "SwitchTo") || !strcmp(member, "SwitchToNext") || !strcmp(member, "SwitchToPrevious") || !strcmp(member, "ActivateSession"))
        return dbus_message_new_method_return(m); /* only one session to switch to */
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
    const char *obj = iface_of_path(path);
    if (iface && !strcmp(iface, DBUS_INTERFACE_INTROSPECTABLE))
        r = reply_string(m, introspect_xml);
    else if (iface && !strcmp(iface, PROPS_IFACE))
        r = handle_properties(m, path, member);
    else if (!obj)
        r = error(m, DBUS_ERROR_UNKNOWN_OBJECT, path);
    else if (!strcmp(obj, MANAGER_IFACE))
        r = handle_manager(m, member);
    else if (!strcmp(obj, SESSION_IFACE))
        r = handle_session(m, member);
    else if (!strcmp(obj, SEAT_IFACE))
        r = handle_seat(m, member);
    else
        r = error(m, DBUS_ERROR_UNKNOWN_METHOD, member);
    if (r) {
        dbus_connection_send(c, r, NULL);
        dbus_message_unref(r);
    }
    return DBUS_HANDLER_RESULT_HANDLED;
}

/* Forget the controller (and close its devices) when it leaves the bus. */
static DBusHandlerResult on_signal(DBusConnection *c, DBusMessage *m, void *data) {
    (void)c;
    (void)data;
    if (dbus_message_is_signal(m, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
        const char *name, *old, *new_owner;
        if (dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old, DBUS_TYPE_STRING, &new_owner, DBUS_TYPE_INVALID) &&
            *controller && !strcmp(name, controller) && !*new_owner) {
            logmsg("controller %s left", controller);
            release_all();
            controller[0] = 0;
        }
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--uid") && i + 1 < argc)
            session_uid = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-v"))
            verbose = 1;
    }
    struct passwd *pw = getpwuid(session_uid);
    if (pw)
        snprintf(user_name, sizeof user_name, "%s", pw->pw_name);
    snprintf(user_path, sizeof user_path, ROOT_PATH "/user/_%u", session_uid);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    boot_usec = (unsigned long long)ts.tv_sec * 1000000ull;
    signal(SIGPIPE, SIG_IGN);

    DBusError err;
    dbus_error_init(&err);
    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!c) {
        logmsg("cannot connect to the system bus: %s", err.message);
        return 1;
    }
    int r = dbus_bus_request_name(c, BUS_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &err);
    if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        logmsg("cannot own %s: %s", BUS_NAME, dbus_error_is_set(&err) ? err.message : "name taken");
        return 1;
    }
    static const DBusObjectPathVTable vtable = {.message_function = on_message};
    dbus_connection_register_fallback(c, ROOT_PATH, &vtable, NULL);
    dbus_bus_add_match(c, "type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'", NULL);
    dbus_connection_add_filter(c, on_signal, NULL, NULL);
    logmsg("seat0 session 1 for uid %u (%s) on %s", session_uid, user_name, BUS_NAME);
    while (dbus_connection_read_write_dispatch(c, -1))
        ;
    return 0;
}
