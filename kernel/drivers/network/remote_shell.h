#ifndef REMOTE_SHELL_H
#define REMOTE_SHELL_H

#include <stdint.h>

/* Запустить удалённую оболочку (raw, аналог telnet) на TCP-порту.
   Возвращает tid kthread-сервера или -1. */
int rsh_server_start(uint16_t port, int max_sessions, int accept_timeout_ms);

/* Остановить сервер (если запущен). */
void rsh_server_stop(void);

int rsh_server_running(void);

#endif
