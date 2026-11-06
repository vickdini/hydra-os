// System V IPC: shared memory (fork inheritance, removal while attached, read-only),
// semaphores (atomic operations, blocking, timeouts, SEM_UNDO, removal while waiting),
// message queues (type selection, truncation, blocking, full queue), IPC namespaces.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

union semun { int val; struct semid_ds *buf; unsigned short *array; };

static void msleep(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&ts, 0);
}

static int child_status(pid_t c) {
    int st;
    waitpid(c, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

int main(void) {
    key_t key = 0x4859 + getpid() % 1000;

    // ---- shared memory
    int shm = shmget(IPC_PRIVATE, 65536, 0600);
    char *p = shmat(shm, 0, 0);
    CHECK(shm >= 0 && p != (void *)-1, "shmget + shmat");
    strcpy(p, "parent");
    pid_t c = fork();
    if (c == 0) {
        struct shmid_ds ds;
        int ok = !strcmp(p, "parent") && shmctl(shm, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2;
        strcpy(p, "child");
        _exit(ok ? 0 : 1);
    }
    CHECK(child_status(c) == 0 && !strcmp(p, "child"), "child shares the segment and its attachment counts");
    struct shmid_ds ds;
    CHECK(shmctl(shm, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1 && ds.shm_segsz == 65536 && ds.shm_cpid == getpid(), "nattch back to 1 after the child exits");
    char *q = shmat(shm, 0, SHM_RDONLY);
    CHECK(q != (void *)-1 && !strcmp(q, "child") && q != p, "second, read-only attachment");
    c = fork();
    if (c == 0) {
        q[0] = 'X'; // SIGSEGV
        _exit(0);
    }
    CHECK(child_status(c) == 128 + SIGSEGV, "writing a read-only attachment faults");
    int k = shmget(key, 4096, IPC_CREAT | 0600);
    errno = 0;
    CHECK(k >= 0 && shmget(key, 4096, IPC_CREAT | IPC_EXCL | 0600) == -1 && errno == EEXIST, "IPC_EXCL on an existing key");
    errno = 0;
    CHECK(shmget(key, 8192, 0) == -1 && errno == EINVAL, "asking for more than the segment's size");
    CHECK(shmget(key, 0, 0) == k, "shmget by key finds it");
    char *kp = shmat(k, 0, 0);
    CHECK(shmctl(k, IPC_RMID, 0) == 0, "IPC_RMID while attached");
    errno = 0;
    CHECK(shmget(key, 0, 0) == -1 && errno == ENOENT, "removed segment no longer found by key");
    kp[0] = 1;
    CHECK(kp[0] == 1 && shmdt(kp) == 0, "still usable until detached");
    errno = 0;
    CHECK(shmctl(k, IPC_STAT, &ds) == -1 && errno == EINVAL, "gone after the last detach");
    errno = 0;
    CHECK(shmdt(p + 4096) == -1 && errno == EINVAL, "shmdt of an address that is not an attachment");
    shmdt(p);
    shmdt(q);
    shmctl(shm, IPC_RMID, 0);

    // ---- semaphores
    int sem = semget(IPC_PRIVATE, 3, 0600);
    unsigned short init[3] = {1, 0, 5}, out[3];
    union semun arg = {.array = init};
    CHECK(sem >= 0 && semctl(sem, 0, SETALL, arg) == 0, "semget + SETALL");
    arg.array = out;
    CHECK(semctl(sem, 0, GETALL, arg) == 0 && out[0] == 1 && out[1] == 0 && out[2] == 5, "GETALL");
    struct sembuf dec0 = {0, -1, 0};
    CHECK(semop(sem, &dec0, 1) == 0 && semctl(sem, 0, GETVAL) == 0 && semctl(sem, 0, GETPID) == getpid(), "semop -1, GETPID");
    struct sembuf both[2] = {{2, -1, IPC_NOWAIT}, {0, -1, IPC_NOWAIT}};
    errno = 0;
    CHECK(semop(sem, both, 2) == -1 && errno == EAGAIN && semctl(sem, 2, GETVAL) == 5, "all-or-nothing: nothing applied when one op would block");
    struct sembuf zero1 = {1, 0, 0};
    CHECK(semop(sem, &zero1, 1) == 0, "wait-for-zero on a zero semaphore");
    struct timespec t100 = {0, 100000000};
    errno = 0;
    CHECK(semtimedop(sem, &dec0, 1, &t100) == -1 && errno == EAGAIN, "semtimedop times out");
    c = fork();
    if (c == 0) {
        struct sembuf d1 = {1, -1, 0};
        _exit(semop(sem, &d1, 1) == 0 ? 0 : 1);
    }
    msleep(100);
    CHECK(semctl(sem, 1, GETNCNT) == 1, "a waiter counts in GETNCNT");
    struct sembuf inc1 = {1, 1, 0};
    semop(sem, &inc1, 1);
    CHECK(child_status(c) == 0 && semctl(sem, 1, GETVAL) == 0, "waiter woken and done");
    c = fork();
    if (c == 0) {
        struct sembuf undo = {2, -2, SEM_UNDO};
        semop(sem, &undo, 1);
        _exit(semctl(sem, 2, GETVAL) == 3 ? 0 : 1);
    }
    CHECK(child_status(c) == 0 && semctl(sem, 2, GETVAL) == 5, "SEM_UNDO reverts at exit");
    c = fork();
    if (c == 0) {
        struct sembuf d1 = {1, -1, 0};
        _exit(semop(sem, &d1, 1) == -1 && errno == EIDRM ? 0 : 1);
    }
    msleep(100);
    CHECK(semctl(sem, 0, IPC_RMID) == 0 && child_status(c) == 0, "removal wakes a waiter with EIDRM");

    // ---- message queues
    struct { long type; char text[64]; } m;
    int mq = msgget(IPC_PRIVATE, 0600);
    CHECK(mq >= 0, "msgget");
    long types[4] = {3, 1, 2, 1};
    for (int i = 0; i < 4; i++) {
        m.type = types[i];
        sprintf(m.text, "m%d", i);
        msgsnd(mq, &m, strlen(m.text) + 1, 0);
    }
    struct msqid_ds mds;
    CHECK(msgctl(mq, IPC_STAT, &mds) == 0 && mds.msg_qnum == 4 && mds.msg_lspid == getpid(), "4 messages queued");
    CHECK(msgrcv(mq, &m, 64, -2, 0) == 3 && m.type == 1 && !strcmp(m.text, "m1"), "type -2: the oldest of the lowest type");
    CHECK(msgrcv(mq, &m, 64, 1, MSG_EXCEPT) == 3 && m.type == 3, "MSG_EXCEPT 1: the first other type");
    errno = 0;
    CHECK(msgrcv(mq, &m, 1, 2, 0) == -1 && errno == E2BIG, "too small a buffer: E2BIG, message kept");
    CHECK(msgrcv(mq, &m, 1, 2, MSG_NOERROR) == 1 && m.text[0] == 'm', "MSG_NOERROR truncates");
    CHECK(msgrcv(mq, &m, 64, 0, 0) == 3 && !strcmp(m.text, "m3"), "type 0: the first message");
    errno = 0;
    CHECK(msgrcv(mq, &m, 64, 0, IPC_NOWAIT) == -1 && errno == ENOMSG, "empty queue: ENOMSG");
    c = fork();
    if (c == 0) {
        int n = msgrcv(mq, &m, 64, 7, 0);
        _exit(n == 6 && !strcmp(m.text, "late!") ? 0 : 1);
    }
    msleep(100);
    m.type = 7;
    strcpy(m.text, "late!");
    msgsnd(mq, &m, 6, 0);
    CHECK(child_status(c) == 0, "blocked receiver gets a later message");
    msgctl(mq, IPC_STAT, &mds);
    mds.msg_qbytes = 10;
    CHECK(msgctl(mq, IPC_SET, &mds) == 0, "lower the queue's byte limit");
    m.type = 1;
    msgsnd(mq, &m, 8, 0);
    errno = 0;
    CHECK(msgsnd(mq, &m, 8, IPC_NOWAIT) == -1 && errno == EAGAIN, "full queue: EAGAIN");
    errno = 0;
    m.type = 0;
    CHECK(msgsnd(mq, &m, 1, 0) == -1 && errno == EINVAL, "type 0: EINVAL");
    CHECK(msgctl(mq, IPC_RMID, 0) == 0, "msgctl IPC_RMID");

    // ---- limits and namespaces
    char buf[64] = {0};
    int fd = open("/proc/sys/kernel/msgmax", O_RDONLY);
    CHECK(fd >= 0 && read(fd, buf, 63) > 0 && atoi(buf) >= 8192, "/proc/sys/kernel/msgmax = %d", atoi(buf));
    int pub = msgget(key, IPC_CREAT | 0600);
    c = fork();
    if (c == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWIPC)) _exit(2);
        _exit(msgget(key, 0) == -1 && errno == ENOENT ? 0 : 1);
    }
    CHECK(child_status(c) == 0, "a new IPC namespace does not see the queue");
    msgctl(pub, IPC_RMID, 0);

    printf(fails ? "SYSV TEST FAILED (%d)\n" : "SYSV TEST PASSED\n", fails);
    return fails != 0;
}
