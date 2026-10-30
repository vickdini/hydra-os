#include <sys/epoll.h>
#include <stdio.h>
int main() {
    printf("sizeof: %zu\n", sizeof(struct epoll_event));
    return 0;
}
