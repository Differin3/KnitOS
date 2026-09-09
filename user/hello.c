#include "syscall.h"

static const char hello[] = "Hello from user mode!\n";
static const char bye[] = "user task exit\n";

static void halt_forever(void) __attribute__((noreturn));

void _start(void) {
    sys_write(1, hello, (sizeof(hello) - 1));
    syscall4(SYS_YIELD, 0, 0, 0);
    syscall4(SYS_YIELD, 0, 0, 0);
    sys_write(1, bye, (sizeof(bye) - 1));
    syscall4(SYS_EXIT, 0, 0, 0);
    halt_forever();
}

static void halt_forever(void) {
    for (;;) __asm__ volatile("hlt");
}