#include "syscall.h"

static const char m_warn[] = "user demo3 crash attempt\n";

void _start(void) {
    sys_write(1, m_warn, (sizeof(m_warn) - 1));
    /* Чтение supervisor-страницы ядра (PDE 0) из ring3 -> #PF (protection),
       ядро убивает задачу вместо паники. Дальше выполняться не должны. */
    volatile unsigned int* p = (volatile unsigned int*)0x1000;
    (void)*p;
    sys_write(1, "user demo3 SURVIVED (BAD)\n", 26);
    syscall4(SYS_EXIT, 0, 0, 0);
    for (;;) __asm__ volatile("hlt");
}