#include <sys/socket.h>
#include <stdio.h>
int main() {
    printf("sizeof msghdr: %zu\n", sizeof(struct msghdr));
    printf("sizeof cmsghdr: %zu\n", sizeof(struct cmsghdr));
    printf("CMSG_FIRSTHDR: %zu\n", CMSG_LEN(sizeof(int)));
    return 0;
}
