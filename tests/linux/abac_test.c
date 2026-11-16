// Attribute-based access control (src/compat/linux/abac.rs), run as root:
// - a policy loaded with prctl(PR_HYDRA_ACCESS, LOAD) restricts what the mode bits allow,
//   by the subject's attributes (set by root, inherited across fork and exec) against the
//   file's labels (security.hydra.labels): department match and clearance >= classification;
// - unlabelled files and processes without attributes are not affected; root is not;
// - new files and folders inherit their folder's labels; users cannot change labels;
// - only root loads policies and sets attributes;
// - delete needs the delete right; staged rules only log ("staged-would-deny");
// - decisions follow label and policy changes (caches), time conditions, app control
//   (deny by path, allow-list of administrator-installed programs) and the unprivileged
//   EVALUATE query.
// Hydra-specific (Linux has no PR_HYDRA_ACCESS: prctl fails with EINVAL there).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define PR_HYDRA_ACCESS 0x48594401
#define LOAD 1
#define SET_SUBJECT 2
#define GET_SUBJECT 3
#define READ_AUDIT 4
#define EVALUATE 5
#define STATUS 6
#define LABELS "security.hydra.labels"
#define DIR "/tmp/abac_t"
#define USER 1000

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

static long acc(long cmd, long a2, long a3, long a4, long a5) { return prctl(PR_HYDRA_ACCESS, cmd, a2, a3, a4, a5); }
static long load(const char *p) { return acc(LOAD, (long)p, (long)strlen(p), 0, 0); }
static long set_subject(pid_t pid, const char *s) { return acc(SET_SUBJECT, pid, (long)s, (long)strlen(s), 0); }

static void label(const char *path, const char *labels) {
    if (setxattr(path, LABELS, labels, strlen(labels), 0) != 0) printf("     setxattr %s: %s\n", path, strerror(errno));
}
static void mkfile(const char *path, const char *labels) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd >= 0) { if (write(fd, "data\n", 5) < 0) {} close(fd); }
    chmod(path, 0666);
    if (labels) label(path, labels);
}

// Runs `fn` in a child with subject `subject` (NULL: none) as uid USER; its exit status.
static int as_user(const char *subject, int (*fn)(void)) {
    pid_t p = fork();
    if (p == 0) {
        if (subject && set_subject(0, subject) != 0) _exit(90);
        if (setresgid(USER, USER, USER) || setresuid(USER, USER, USER)) _exit(91);
        _exit(fn());
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

static int can_open(const char *path, int flags) {
    int fd = open(path, flags);
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

static int t_fin(void) {
    // department Finance, clearance Confidential
    int r = 0;
    if (!can_open(DIR "/fin_conf", O_RDONLY)) r |= 1;          // allowed
    if (can_open(DIR "/fin_secret", O_RDONLY) || errno != EACCES) r |= 2;  // clearance too low
    if (can_open(DIR "/hr_conf", O_RDONLY)) r |= 4;            // other department
    if (!can_open(DIR "/plain", O_RDWR)) r |= 8;               // no labels: mode bits only
    if (!can_open(DIR "/fin_conf", O_RDWR)) r |= 16;           // write allowed too
    return r;
}
static int t_open_secret(void) { return can_open(DIR "/fin_secret", O_RDONLY) ? 0 : 1; }
static int t_write_secret(void) { return can_open(DIR "/fin_secret", O_WRONLY) ? 0 : 1; }
static int t_labels_protected(void) {
    int r = 0;
    if (setxattr(DIR "/fin_conf", LABELS, "department=HR", 13, 0) == 0 || errno != EPERM) r |= 1;
    if (removexattr(DIR "/fin_conf", LABELS) == 0 || errno != EPERM) r |= 2;
    char b[256];
    ssize_t n = getxattr(DIR "/fin_conf", LABELS, b, sizeof b);  // anyone may read them
    if (n <= 0) r |= 4;
    if (set_subject(0, "clearance=Secret") != -1 || errno != EPERM) r |= 8;
    if (load("hydra-access 1\n") != -1 || errno != EPERM) r |= 16;
    if (acc(READ_AUDIT, 0, (long)b, sizeof b, 0) != -1 || errno != EPERM) r |= 32;
    return r;
}
static int t_inherit(void) {
    // Creates in the labelled folder; the new file must carry the folder's labels
    int r = 0;
    int fd = open(DIR "/findir/new", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) return 1;
    close(fd);
    char b[256] = {0};
    ssize_t n = getxattr(DIR "/findir/new", LABELS, b, sizeof b - 1);
    if (n <= 0 || !strstr(b, "department=Finance") || !strstr(b, "classification=Internal")) r |= 2;
    if (mkdir(DIR "/findir/sub", 0755) != 0) r |= 4;
    memset(b, 0, sizeof b);
    n = getxattr(DIR "/findir/sub", LABELS, b, sizeof b - 1);
    if (n <= 0 || !strstr(b, "department=Finance")) r |= 8;
    return r;
}
static int t_exec_child(void) {
    // The subject survives exec: run ourselves with "--probe"
    pid_t p = fork();
    if (p == 0) {
        execl("/proc/self/exe", "abac", "--probe", (char *)NULL);
        _exit(97);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 98;
}
static int probe(void) {
    char b[512] = {0};
    long n = acc(GET_SUBJECT, 0, (long)b, sizeof b - 1, 0);
    int r = 0;
    if (n <= 0 || !strstr(b, "department=Finance")) r |= 1;
    if (can_open(DIR "/fin_secret", O_RDONLY)) r |= 2;
    if (!can_open(DIR "/fin_conf", O_RDONLY)) r |= 4;
    return r;
}
static int t_delete(void) {
    int r = 0;
    if (unlink(DIR "/fin_del") == 0 || errno != EACCES) r |= 1;   // rule grants rw only
    if (rename(DIR "/fin_del", "/tmp/abac_moved") == 0 || errno != EACCES) r |= 2;
    if (unlink(DIR "/plain_del") != 0) r |= 4;
    return r;
}
static int t_staged(void) { return can_open(DIR "/fin_conf", O_RDONLY) ? 0 : 1; }
static int t_hr(void) { return can_open(DIR "/hr_conf", O_RDONLY) ? 0 : 1; }
static int t_run(const char *prog) {
    pid_t p = fork();
    if (p == 0) {
        execl(prog, prog, (char *)NULL);
        _exit(errno == EACCES ? 77 : 78);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}
static int t_app_deny(void) {
    int r = 0;
    if (t_run(DIR "/prog") != 77) r |= 1;   // denied by path
    if (t_run("/bin/true") != 0) r |= 2;    // allowed
    return r;
}
static int t_app_list(void) {
    int r = 0;
    if (t_run(DIR "/prog") != 77) r |= 1;   // not installed by the administrator
    if (t_run("/bin/true") != 0) r |= 2;    // root's, in a root folder
    return r;
}
static int t_evaluate(void) {
    const char *q = "department=Finance\nclearance=Confidential\n--\ndepartment=Finance\nclassification=Secret\npolicy=Fin\n";
    char out[512] = {0};
    long n = acc(EVALUATE, (long)q, (long)strlen(q) | (long)(sizeof out - 1) << 32, (long)out, 0);
    if (n <= 0) return 1;
    printf("     evaluate: %s", out);
    return strstr(out, "enforced=- ") && strstr(out, "covered=1") && strstr(out, "rule=fin-dept") ? 0 : 2;
}

static const char *POLICY =
    "hydra-access 1\n"
    "type level Public Internal Confidential Secret\n"
    "attrtype clearance level\n"
    "attrtype classification level\n"
    "policy Fin\n"
    "rule fin-dept\n"
    "allow rw user.department res.department == user.clearance res.classification >= and\n"
    "allow r user.role 'auditor ==\n";

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--probe")) return probe();
    if (argc > 2 && !strcmp(argv[1], "--load")) {
        // Loads a policy file (perf runs): abac --load FILE
        static char text[65536];
        FILE *f = fopen(argv[2], "r");
        size_t n = f ? fread(text, 1, sizeof text - 1, f) : 0;
        if (f) fclose(f);
        text[n] = 0;
        long r = load(text);
        printf("load: %ld\n", r);
        return r != 0;
    }
    char st[512] = {0};
    if (acc(STATUS, 0, (long)st, sizeof st - 1, 0) < 0) {
        printf("FAIL PR_HYDRA_ACCESS not supported (%s)\n", strerror(errno));
        return 1;
    }
    printf("     status: %s", st);
    if (geteuid() != 0) { printf("FAIL run as root\n"); return 1; }
    // A clean slate: no policy, our own subject none
    load("");
    system("rm -rf " DIR " /tmp/abac_moved");
    mkdir(DIR, 0777);
    chmod(DIR, 0777);
    mkfile(DIR "/fin_conf", "department=Finance\nclassification=Confidential\npolicy=Fin\n");
    mkfile(DIR "/fin_secret", "department=Finance\nclassification=Secret\npolicy=Fin\n");
    mkfile(DIR "/hr_conf", "department=HR\nclassification=Confidential\npolicy=Fin\n");
    mkfile(DIR "/fin_del", "department=Finance\nclassification=Public\npolicy=Fin\n");
    mkfile(DIR "/plain", NULL);
    mkfile(DIR "/plain_del", NULL);
    mkdir(DIR "/findir", 0777);
    chmod(DIR "/findir", 0777);
    label(DIR "/findir", "department=Finance\nclassification=Internal\npolicy=Fin\n");

    const char *fin = "department=Finance\nclearance=Confidential\n";
    check(as_user(fin, t_open_secret) == 0, "no policy loaded: labels alone restrict nothing");
    check(load("hydra-access 1\nbogus line\n") == -1 && errno == EINVAL, "a malformed policy is refused");
    check(load(POLICY) == 0, "root loads a policy");
    int r = as_user(fin, t_fin);
    check(r == 0, "Finance/Confidential: reads its department's Confidential file, not Secret nor HR; unlabelled file unaffected");
    if (r) printf("     t_fin=%d\n", r);
    check(as_user(NULL, t_open_secret) == 0, "a process without attributes is not restricted");
    check(as_user("role=auditor\n", t_open_secret) == 0, "auditor role: may read any file of the policy");
    check(as_user("role=auditor\n", t_write_secret) == 1, "auditor role: may not write");
    check(can_open(DIR "/fin_secret", O_RDWR), "root is not restricted");
    r = as_user(fin, t_labels_protected);
    check(r == 0, "users cannot set or remove labels, set attributes, load policies or read the audit; they can read labels");
    if (r) printf("     t_labels_protected=%d\n", r);
    r = as_user("department=Finance\nclearance=Internal\n", t_inherit);
    check(r == 0, "new files and folders inherit their folder's labels");
    if (r) printf("     t_inherit=%d\n", r);
    r = as_user(fin, t_exec_child);
    check(r == 0, "attributes are inherited across fork and exec and still enforced");
    if (r) printf("     t_exec_child=%d\n", r);
    r = as_user(fin, t_delete);
    check(r == 0, "delete and move-away need the delete right (unlabelled files: mode bits only)");
    if (r) printf("     t_delete=%d\n", r);

    // Audit: the denials above, with paths
    char *au = calloc(1, 65536);
    long n = acc(READ_AUDIT, 0, (long)au, 65535, 0);
    check(n > 0 && strstr(au, " deny ") && strstr(au, "rule=fin-dept") && strstr(au, "path=" DIR "/fin_secret"), "denials are audited (rule, policy, path)");
    if (n > 0) { char *nl = strchr(au, '\n'); if (nl) *nl = 0; printf("     audit: %s\n", au); }

    // Cache invalidation: relabelling and reloading change decisions at once
    check(as_user(fin, t_hr) == 1, "HR file denied (cached decision)");
    label(DIR "/hr_conf", "department=Finance\nclassification=Confidential\npolicy=Fin\n");
    check(as_user(fin, t_hr) == 0, "relabelled file: allowed at once");
    label(DIR "/hr_conf", "department=HR\nclassification=Confidential\npolicy=Fin\n");
    check(as_user(fin, t_hr) == 1, "labelled back: denied again");
    char pol2[1024];
    snprintf(pol2, sizeof pol2, "%sallow r user.department 'Finance ==\n", POLICY);
    check(load(pol2) == 0 && as_user(fin, t_hr) == 0, "policy change: a new allow entry applies at once");

    // Staging: a proposed rule only logs
    snprintf(pol2, sizeof pol2, "%srule fin-strict staged\nallow r user.clearance 'Secret ==\n", POLICY);
    check(load(pol2) == 0, "policy with a staged rule loads");
    acc(READ_AUDIT, 0, (long)au, 65535, 0); // drain
    check(as_user(fin, t_staged) == 0, "staged rule does not restrict");
    memset(au, 0, 65536);
    n = acc(READ_AUDIT, 0, (long)au, 65535, 0);
    check(n > 0 && strstr(au, "staged-would-deny") && strstr(au, "rule=fin-strict"), "staged rule logs what it would deny");

    // Time conditions
    snprintf(pol2, sizeof pol2, "%srule never\nallow rwxd env.weekday #8 ==\n", POLICY);
    check(load(pol2) == 0 && as_user("role=auditor\n", t_open_secret) == 1, "time condition false (weekday 8): denied");
    snprintf(pol2, sizeof pol2, "%srule always\nallow rwxd env.hour #0 >= env.weekday #1 >= and\n", POLICY);
    check(load(pol2) == 0 && as_user("role=auditor\n", t_open_secret) == 0, "time condition true: allowed");

    // Global policy (no policy label needed) and target conditions
    load("hydra-access 1\npolicy G global\nrule secret-only\ntarget res.classification 'Secret ==\nallow r user.vip 'yes ==\n");
    mkfile(DIR "/g_secret", "classification=Secret\n");
    mkfile(DIR "/g_public", "classification=Public\n");
    check(as_user("vip=no\n", t_open_secret) == 1, "global policy: covers labelled files without a policy label");
    {
        int ok = as_user("vip=no\n", t_hr) == 0; // hr_conf: Confidential, rule target does not match
        check(ok, "a rule whose target does not match does not restrict");
    }

    // App control
    {
        int fd = open(DIR "/prog", O_CREAT | O_TRUNC | O_WRONLY, 0755);
        const char *sh = "#!/bin/sh\nexit 0\n";
        if (fd >= 0) { if (write(fd, sh, strlen(sh)) < 0) {} close(fd); }
        chmod(DIR "/prog", 0755);
    }
    load("hydra-access 1\napp no-prog deny path " DIR "/prog user.department 'Finance ==\n");
    r = as_user(fin, t_app_deny);
    check(r == 0, "app control: a program denied by path does not run; others do");
    if (r) printf("     t_app_deny=%d\n", r);
    check(as_user("department=HR\n", t_app_deny) == 1, "app control: the rule applies only to its subjects");
    load("hydra-access 1\napp installed allow trusted - user.role 'kiosk ==\n");
    r = as_user("role=kiosk\n", t_app_list);
    check(r == 0, "app control allow-list: only administrator-installed programs run");
    if (r) printf("     t_app_list=%d\n", r);
    memset(au, 0, 65536);
    n = acc(READ_AUDIT, 0, (long)au, 65535, 0);
    check(n > 0 && strstr(au, "app-deny") && strstr(au, "path=" DIR "/prog"), "app denials are audited");

    // EVALUATE (any user)
    load(POLICY);
    check(as_user(NULL, t_evaluate) == 0, "EVALUATE: unprivileged what-if query names the deciding rule");

    // Unload: nothing restricted
    check(load("") == 0 && as_user(fin, t_open_secret) == 0, "unloading the policy lifts the restrictions");
    memset(st, 0, sizeof st);
    acc(STATUS, 0, (long)st, sizeof st - 1, 0);
    printf("     status: %s", st);
    system("rm -rf " DIR " /tmp/abac_moved");
    printf("%s: %d failure(s)\n", fails ? "FAILED" : "PASSED", fails);
    return fails != 0;
}
