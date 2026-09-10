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
    printf("argtest done\n");
    return 0;
}
