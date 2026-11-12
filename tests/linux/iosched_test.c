// Programs keep running while another process waits on the file server: a thread
// computing for 0.4 s gets (nearly) all of it even while another process reads a file in a
// loop (each read a request to the file server). With one CPU it only reports.
// Build: gcc -O1 -w -pthread -o iosched iosched_test.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static volatile unsigned long sink;
static double ran, took;
// Computes for 0.4 s of wall time from its start; notes the CPU time it got
static void *spin(void *x) {
    double t0 = now(), end = t0 + 0.4;
    unsigned long v = 1;
    while (now() < end)
        for (int i = 0; i < 100000; i++) v = v * 6364136223846793005UL + 1;
    sink = v;
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    ran = t.tv_sec + t.tv_nsec / 1e9;
    took = now() - t0;
    return NULL;
}

static double spin_once(void) {
    pthread_t t;
    pthread_create(&t, NULL, spin, NULL);
    pthread_join(t, NULL);
    return ran / took;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    double quiet = spin_once();
    pid_t io = fork();
    if (io == 0) {
        char b[4096];
        int fd = open("/etc/passwd", O_RDONLY);
        for (;;) pread(fd, b, sizeof b, 0);
    }
    usleep(100000);
    double busy = spin_once();
    kill(io, SIGKILL);
    waitpid(io, NULL, 0);
    printf("     %ld CPUs: a computing thread got %.0f%% of its time alone, %.0f%% while another process reads a file\n", n,
           quiet * 100, busy * 100);
    // With one CPU it shares that CPU with the file server and whatever else runs: reported
    if (n > 1) {
        check(quiet > 0.8, "a computing thread runs alone");
        check(busy > 0.7, "it keeps running while another process waits on the file server");
    }
    printf(fails ? "IOSCHED TEST FAILED (%d)\n" : "IOSCHED TEST PASSED\n", fails);
    return fails != 0;
}
