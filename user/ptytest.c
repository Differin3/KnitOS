// M2 smoke test: interactive program over a PTY (stdin/stdout on a pty slave).
#include "lib/libk.h"

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    printf("ptytest: isatty(0)=%d\n", (int)sys_isatty(0));
    printf("ptytest: type a line (q to quit)\n");
    char buf[128];
    for (;;) {
        printf("> ");
        long n = sys_read(0, buf, sizeof(buf) - 1);
        if (n <= 0) {
            printf("ptytest: EOF\n");
            break;
        }
        buf[n] = 0;
        printf("got: %s", buf);
        if (buf[0] == 'q') {
            printf("ptytest: bye\n");
            break;
        }
    }
    return 0;
}
