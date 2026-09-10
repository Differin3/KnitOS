// M1 smoke test: user-space app using libk + main(argc, argv).
#include "lib/libk.h"

int main(int argc, char** argv) {
    printf("argtest: argc=%d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("  argv[%d] = %s\n", i, argv[i] ? argv[i] : "(null)");
    }
    printf("uid=%d pid=%d cwd=", (int)sys_getuid(), (int)sys_getpid());
    char cwd[128];
    if (sys_getcwd(cwd, sizeof(cwd)) >= 0) printf("%s", cwd);
    printf("\n");

    char* p = (char*)malloc(64);
    if (p) {
        strcpy(p, "heap allocation OK");
        printf("malloc: %s\n", p);
        free(p);
    } else {
        printf("malloc: FAILED\n");
    }

    int pfd[2];
    if (sys_pipe(pfd) == 0) {
        const char* msg = "pipe roundtrip OK";
        sys_write(pfd[1], msg, strlen(msg));
        sys_close(pfd[1]);
        char rbuf[64];
        int n = (int)sys_read(pfd[0], rbuf, sizeof(rbuf) - 1);
        if (n > 0) {
            rbuf[n] = 0;
            printf("pipe: %s\n", rbuf);
        } else {
            printf("pipe: read failed (%d)\n", n);
        }
        sys_close(pfd[0]);
    } else {
        printf("pipe: create failed\n");
    }

    volatile int shared = 111;
    long pid = sys_fork();
    if (pid == 0) {
        shared = 222;
        printf("child: pid=%d ppid=%d shared=%d\n",
               (int)sys_getpid(), (int)sys_getppid(), shared);
        sys_exit(0);
    } else if (pid > 0) {
        int status = 0;
        long reaped = sys_wait(&status);
        printf("parent: fork=%d reaped=%d shared=%d\n", (int)pid, (int)reaped, shared);
    } else {
        printf("fork: failed (%d)\n", (int)pid);
    }
    printf("argtest done\n");
    return 0;
}
