/* hydra-access-check: asks the kernel's access policy (src/compat/linux/abac.rs) about
 * things that are not files.
 *
 *   hydra-access-check polkit <action-id> <user>
 *       Prints "no" when the policy refuses <user> the administrative action (polkit
 *       then refuses it without asking for a password), nothing otherwise. Called by
 *       /etc/polkit-1/rules.d/60-hydra-access.rules.
 *   hydra-access-check login [<user>]
 *       Exit status 0 if <user> (default: $PAM_USER, for pam_exec) may sign in now
 *       (Family screen time, sign-in hours), 1 if not.
 *
 * The question is a "what if" query (PR_HYDRA_ACCESS EVALUATE) with the user's
 * attributes (/etc/hydra/access/subjects/<user> plus name, uid and groups, as
 * hydra-logind gives a session) and a resource described by labels: action=<id> and
 * category=<software|network|time|users|power|devices|system|other>, or
 * action=session. The policy allows it when the answer's enforced actions include x. */
#define _GNU_SOURCE
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define PR_HYDRA_ACCESS 0x48594401
#define EVALUATE 5

static int user_attrs(const char *user, char *buf, size_t len) {
    struct passwd *pw = getpwnam(user);
    int n = snprintf(buf, len, "name=%s\n", user);
    if (pw) {
        n += snprintf(buf + n, len - n, "uid=%u\n", (unsigned)pw->pw_uid);
        gid_t groups[64];
        int ng = 64;
        if (getgrouplist(user, pw->pw_gid, groups, &ng) > 0 && ng > 0) {
            n += snprintf(buf + n, len - n, "groups=");
            for (int i = 0; i < ng && n < (int)len - 64; i++) {
                struct group *g = getgrgid(groups[i]);
                if (g) n += snprintf(buf + n, len - n, "%s%s", i ? "," : "", g->gr_name);
            }
            n += snprintf(buf + n, len - n, "\n");
        }
    }
    char path[512];
    snprintf(path, sizeof path, "/etc/hydra/access/subjects/%s", user);
    FILE *f = fopen(path, "r");
    if (f) {
        n += (int)fread(buf + n, 1, len - n - 1, f);
        fclose(f);
    }
    buf[n] = 0;
    return n;
}

/* 1 allowed (or no policy / not covered), 0 refused. */
static int allowed(const char *user, const char *labels) {
    char q[12000], out[1024];
    int n = user_attrs(user, q, sizeof q - 2048);
    n += snprintf(q + n, sizeof q - n, "\n--\n%s", labels);
    long r = prctl(PR_HYDRA_ACCESS, EVALUATE, (unsigned long)q, (unsigned long)n | (unsigned long)(sizeof out - 1) << 32, (unsigned long)out);
    if (r <= 0) return 1;
    out[r] = 0;
    if (getenv("HYDRA_ACCESS_DEBUG")) fprintf(stderr, "%s", out);
    const char *e = strstr(out, "enforced=");
    if (!e) return 1;
    const char *sp = strchr(e, ' ');
    for (const char *c = e + 9; c && *c && c < sp; c++)
        if (*c == 'x') return 1;
    return 0;
}

static const char *category(const char *id) {
    static const struct { const char *prefix, *cat; } map[] = {
        {"org.freedesktop.packagekit.", "software"}, {"org.debian.apt.", "software"}, {"org.kde.discover", "software"},
        {"org.hydra.apps.", "software"}, {"io.snapcraft.", "software"}, {"org.freedesktop.Flatpak.", "software"},
        {"org.freedesktop.NetworkManager.", "network"}, {"org.freedesktop.network1.", "network"}, {"org.freedesktop.resolve1.", "network"},
        {"org.freedesktop.timedate1.", "time"}, {"org.kde.kcontrol.kcmclock.", "time"},
        {"org.freedesktop.accounts.", "users"}, {"org.kde.kcontrol.kcmsddm.", "users"}, {"org.hydra.access.", "users"},
        {"org.freedesktop.login1.power-off", "power"}, {"org.freedesktop.login1.reboot", "power"},
        {"org.freedesktop.login1.halt", "power"}, {"org.freedesktop.login1.suspend", "power"}, {"org.freedesktop.login1.hibernate", "power"},
        {"org.freedesktop.udisks2.", "devices"}, {"org.freedesktop.UDisks2.", "devices"}, {"org.freedesktop.bolt.", "devices"},
        {"org.freedesktop.fwupd.", "system"}, {"org.freedesktop.systemd1.", "system"}, {"org.freedesktop.policykit.exec", "system"},
        {"org.freedesktop.locale1.", "system"}, {"org.freedesktop.hostname1.", "system"},
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
        if (!strncmp(id, map[i].prefix, strlen(map[i].prefix))) return map[i].cat;
    return "other";
}

int main(int argc, char **argv) {
    char labels[1024];
    if (argc >= 4 && !strcmp(argv[1], "polkit")) {
        const char *id = argv[2];
        for (const char *c = id; *c; c++)
            if (*c == '\n' || *c == '=' || *c == ',') return 0;
        snprintf(labels, sizeof labels, "action=%s\ncategory=%s\n", id, category(id));
        if (!allowed(argv[3], labels)) puts("no");
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "login")) {
        const char *user = argc >= 3 ? argv[2] : getenv("PAM_USER");
        if (!user) return 0;
        snprintf(labels, sizeof labels, "action=session\ncategory=session\n");
        if (!allowed(user, labels)) {
            fprintf(stderr, "%s may not sign in at this time\n", user);
            return 1;
        }
        return 0;
    }
    fprintf(stderr, "usage: hydra-access-check polkit <action-id> <user> | login [<user>]\n");
    return 2;
}
