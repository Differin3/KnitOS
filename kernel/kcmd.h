#ifndef KERNEL_KCMD_H
#define KERNEL_KCMD_H

#include <stddef.h>

/* Выполняет команду ядра, форматируя вывод в out (NUL-terminated).
   Возвращает длину вывода. */
int kernel_run_command(const char* cmd, char* out, size_t cap);

#endif
