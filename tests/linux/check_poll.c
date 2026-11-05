#include <poll.h>
#include <stdio.h>
int main() {
    printf("sizeof pollfd: %zu\n", sizeof(struct pollfd));
    return 0;
}
