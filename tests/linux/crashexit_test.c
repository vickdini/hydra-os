// Kernel robustness when processes die abruptly while holding pool files:
//  1. children that die from their own CPU fault (SIGSEGV);
//  2. children killed with SIGKILL while spinning in user mode (the signal is delivered
//     on return from the timer interrupt);
//  3. the same for the init of a PID namespace, whose namespace dies with it.
// Prints CRASHEXIT DONE if the kernel survives.
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void hold_files(void) {
    open("/bin/crashexit.elf", O_RDONLY);
    open("/bin", O_RDONLY | O_DIRECTORY);
    open("/", O_RDONLY | O_DIRECTORY);
}

static void spin(void) {
    for (volatile unsigned long n = 0;; n++) {
    }
}

static void pause_ms(long ms) {
    struct timespec ts = {0, ms * 1000000};
    nanosleep(&ts, 0);
}

int main(void) {
    int gone = 0, st;
    for (int i = 0; i < 40; i++) {
        pid_t c = fork();
        if (c == 0) {
            hold_files();
            *(volatile int *)8 = 1;
        }
        waitpid(c, &st, 0);
        gone += WIFSIGNALED(st);
    }
    for (int i = 0; i < 40; i++) {
        pid_t c = fork();
        if (c == 0) {
            hold_files();
            spin();
        }
        pause_ms(20);
        kill(c, SIGKILL);
        waitpid(c, &st, 0);
        gone += WIFSIGNALED(st);
    }
    for (int i = 0; i < 40; i++) {
        pid_t c = syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
        if (c == 0) {
            hold_files();
            if (fork() == 0) {
                hold_files();
                spin();
            }
            spin();
        }
        pause_ms(20);
        kill(c, SIGKILL);
        waitpid(c, &st, 0);
        gone += WIFSIGNALED(st);
    }
    printf("CRASHEXIT DONE: %d/120 died\n", gone);
    return 0;
}
