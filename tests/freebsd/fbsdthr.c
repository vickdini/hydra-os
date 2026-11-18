/*
 * fbsdthr: threads and signals through FreeBSD's libthr (Group 11, step 0): thr_new,
 * _umtx_op (mutexes, condition variables, semaphores, thr_exit wake), thread-local storage
 * (sysarch AMD64_SET_FSBASE), signal handlers with siginfo and the FreeBSD ucontext,
 * sigaltstack, and SIGTHR-based pthread_cancel. Prints "ok NAME" / "FAIL NAME ...";
 * last line FBSDTHR-DONE <failures>.
 *
 * Build: clang-15 --target=x86_64-unknown-freebsd15.1 --sysroot=$SYSROOT -fuse-ld=lld -O1 -pthread -o fbsdthr fbsdthr.c
 */
#include <sys/types.h>
#include <sys/ucontext.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(name, cond, ...) do { if (cond) printf("ok %s\n", name); \
    else { fails++; printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); } } while (0)

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static long counter;
static int ready;
static __thread int tls_value;
static sem_t sem;

static void *adder(void *arg)
{
    tls_value = (int)(long)arg;
    for (int i = 0; i < 100000; i++) {
        pthread_mutex_lock(&mu);
        counter++;
        pthread_mutex_unlock(&mu);
    }
    return (void *)(long)(tls_value * 2);
}

static void *waiter(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&mu);
    while (!ready)
        pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    sem_post(&sem);
    return NULL;
}

static void *sleeper(void *arg)
{
    (void)arg;
    for (;;)
        pause();
    return NULL;
}

static volatile sig_atomic_t got_sig, got_code;
static volatile long got_rip;
static void handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = ucv;
    got_sig = sig;
    got_code = si->si_code;
    got_rip = uc->uc_mcontext.mc_rip;
}

int main(void)
{
    pthread_t t[4];
    void *ret;
    for (long i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, adder, (void *)(i + 1));
    long sum = 0;
    for (int i = 0; i < 4; i++) { pthread_join(t[i], &ret); sum += (long)ret; }
    CHECK("4 threads, mutex counter", counter == 400000, "counter %ld", counter);
    CHECK("TLS per thread + join values", sum == 2 + 4 + 6 + 8, "sum %ld", sum);

    sem_init(&sem, 0, 0);
    pthread_t w;
    pthread_create(&w, NULL, waiter, NULL);
    usleep(20000);
    pthread_mutex_lock(&mu); ready = 1; pthread_cond_signal(&cv); pthread_mutex_unlock(&mu);
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 2;
    CHECK("condvar + semaphore", sem_timedwait(&sem, &ts) == 0, "errno %d", errno);
    pthread_join(w, NULL);
    pthread_set_name_np(pthread_self(), "fbsdthr-main");

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    raise(SIGUSR2);
    CHECK("SIGUSR2 (31) handler with siginfo/ucontext", got_sig == SIGUSR2 && SIGUSR2 == 31 && got_code == SI_USER && got_rip != 0,
          "sig %d code %d rip %#lx", (int)got_sig, (int)got_code, got_rip);

    stack_t ss = { .ss_sp = malloc(65536), .ss_size = 65536, .ss_flags = 0 };
    CHECK("sigaltstack", sigaltstack(&ss, NULL) == 0, "errno %d", errno);

    pthread_t s;
    pthread_create(&s, NULL, sleeper, NULL);
    usleep(10000);
    CHECK("pthread_cancel (SIGTHR)", pthread_cancel(s) == 0 && pthread_join(s, &ret) == 0 && ret == PTHREAD_CANCELED,
          "ret %p", ret);

    printf("FBSDTHR-DONE %d\n", fails);
    return fails != 0;
}
