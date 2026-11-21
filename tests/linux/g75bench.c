// Group 7-5 budget runner: writes its bench script to /tmp/g75bench.sh and runs it (fork+exec
// loops, lxbench fork_exec_wait, make -j with the FIFO jobserver). Build: gcc -O1 -w
#include <stdio.h>
#include <unistd.h>
static const char S[] = "#!/bin/bash\n"
"# Group 7-5 budget and make -j check (runs in the Ubuntu chroot, from /tmp)\n"
"cd /tmp\n"
"cat lxbench.elf > lxbench; chmod 755 lxbench\n"
"for i in 1 2 3; do ./lxbench fork_exec_wait | grep BENCH; done\n"
"ns() { date +%s%N; }\n"
"s=$(ns); for i in $(seq 300); do /bin/true; done; e=$(ns); echo \"G75 LOOP_TRUE $(( (e-s)/300000 )) us/fork+exec\"\n"
"printf '#!/bin/sh\\nexit 0\\n' > g75t.sh; chmod 755 g75t.sh\n"
"s=$(ns); for i in $(seq 200); do ./g75t.sh; done; e=$(ns); echo \"G75 LOOP_SCRIPT $(( (e-s)/200000 )) us/script\"\n"
"make --version | head -1\n"
"rm -rf mj; mkdir -p mj/sub\n"
"for i in $(seq 16); do printf 'int f%d(void){return %d;}\\n' $i $i > mj/sub/f$i.c; done\n"
"printf 'OBJS=$(patsubst %%.c,%%.o,$(wildcard *.c))\\nall: $(OBJS)\\n%%.o: %%.c\\n\\tgcc -O1 -c $< -o $@\\n' > mj/sub/Makefile\n"
"printf 'all:\\n\\t+$(MAKE) -C sub\\n' > mj/Makefile\n"
"s=$(ns); timeout 300 make -j4 -C mj > mj.out 2>&1; rc=$?; e=$(ns)\n"
"echo \"G75 MAKEJ rc=$rc $(( (e-s)/1000000 )) ms objs=$(ls mj/sub/*.o 2>/dev/null | wc -l) jobserver=$(grep -o 'jobserver-auth=[^ ]*' -m1 mj.out)\"\n"
"s=$(ns); make -C mj/sub clean >/dev/null 2>&1; rm -f mj/sub/*.o; timeout 300 make -j4 --debug=j -C mj 2>&1 | grep -o 'jobserver[^ ]*' | sort | uniq -c | head -3; e=$(ns)\n"
"echo G75BENCH-DONE\n"
"";
int main(void) {
    FILE *f = fopen("/tmp/g75bench.sh", "w");
    if (!f) return 1;
    fputs(S, f);
    fclose(f);
    execl("/bin/bash", "bash", "/tmp/g75bench.sh", (char *)0);
    return 127;
}
