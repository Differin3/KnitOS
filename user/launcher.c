#include "syscall.h"

static const char m1[] = "launcher: exec /tmp/hello.elf\n";
static const char m2[] = "launcher: exec failed\n";

void _start(void) {
    sys_write(1, m1, (sizeof(m1) - 1));
    long r = sys_exec("/tmp/hello.elf");
    if (r != 0) {
        sys_write(1, m2, (sizeof(m2) - 1));
        syscall4(SYS_EXIT, 0, 0, 0);
    }
    for (;;) __asm__ volatile("hlt");
}