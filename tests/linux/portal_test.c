// xdg-document-portal through vfs-server's FUSE (wave 9, Group 6b-2): run as user hydra in a
// KDE session. Adds a file to the document portal (python3-gi: Add with an O_PATH descriptor),
// then stats, reads and appends to it through /run/user/1000/doc; prints PORTAL PASS.
// Build: gcc -O1 -w -o portaltest portal_test.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char *py[] = {
    "import os, sys",
    "try:",
    "    from gi.repository import Gio, GLib",
    "except Exception as e:",
    "    print('NO GI:', e); sys.exit(0)",
    "bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)",
    "open('/tmp/portal_src.txt', 'w').write('portal test file\\n')",
    "fd = os.open('/tmp/portal_src.txt', os.O_RDONLY | os.O_PATH)",
    "fdl = Gio.UnixFDList.new()",
    "i = fdl.append(fd)",
    "r, _ = bus.call_with_unix_fd_list_sync('org.freedesktop.portal.Documents', '/org/freedesktop/portal/documents',",
    "    'org.freedesktop.portal.Documents', 'Add', GLib.Variant('(hbb)', (i, True, False)), None, 0, 20000, fdl, None)",
    "doc = r.unpack()[0]",
    "p = '/run/user/1000/doc/%s/portal_src.txt' % doc",
    "print('DOC', doc)",
    "st = os.stat(p)",
    "print('stat ok size', st.st_size, 'mode %o' % st.st_mode)",
    "print('READ:', open(p).read().strip())",
    "with open(p, 'a') as f:",
    "    f.write('appended through the portal\\n')",
    "print('SRC NOW:', open('/tmp/portal_src.txt').read().replace('\\n', ' | '))",
    "print('PORTAL PASS')",
    0,
};

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
    setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus", 1);
    system("echo id: $(id -u); grep -a ' /run/user/1000/doc ' /proc/mounts || echo NO DOC MOUNT");
    FILE *f = fopen("/tmp/portal_test.py", "w");
    if (!f) { perror("/tmp/portal_test.py"); return 1; }
    for (int i = 0; py[i]; i++) fprintf(f, "%s\n", py[i]);
    fclose(f);
    int r = system("python3 /tmp/portal_test.py 2>&1");
    printf("PORTAL_DONE rc=%d\n", r);
    return 0;
}
