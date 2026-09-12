#ifndef KERNEL_KCMD_H
#define KERNEL_KCMD_H

#include <stddef.h>

/* Выполняет команду ядра, форматируя вывод в out (NUL-terminated).
   Возвращает длину вывода. Вызывается из SYS_KCMD. */
int kernel_run_command(const char* cmd, char* out, size_t cap);

/* Мост к консольному shell (вызывается из главного цикла ядра):
   - kernel_kcmd_take(): есть ли отложенная команда (копирует её в cmd);
   - kernel_kcmd_resp()/cap(): буфер для захвата вывода;
   - kernel_kcmd_reply(): ответ готов. */
int    kernel_kcmd_take(char* cmd, size_t cap);
char*  kernel_kcmd_resp(void);
size_t kernel_kcmd_resp_cap(void);
void   kernel_kcmd_reply(size_t len);
/* Команда не распознана ядром — user-space должен попробовать exec. */
void   kernel_kcmd_reply_notfound(void);

#endif
