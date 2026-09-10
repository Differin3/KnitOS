#ifndef KNITOS_PTY_H
#define KNITOS_PTY_H

#include <stdint.h>
#include <stddef.h>

#define KPTY_MAX 8
#define KPTY_BUF 4096

/* Создаёт PTY (обе стороны закрыты, refs=0). Возвращает индекс или -1. */
int pty_create(void);

/* Учёт ссылок на концы (по одной на fd). */
void pty_ref(int idx, int master);
void pty_unref(int idx, int master);

/* Сторона мастера (управляющий процесс: шелл, sshd). */
int pty_master_write(int idx, const void* buf, uint32_t n); /* ввод для slave + echo */
int pty_master_read(int idx, void* buf, uint32_t n);        /* вывод slave (блок) */
int pty_master_read_nb(int idx, void* buf, uint32_t n);     /* вывод slave (неблок) */

/* Сторона slave (программа: stdin/stdout). */
int pty_slave_read(int idx, void* buf, uint32_t n);         /* канонический ввод */
int pty_slave_write(int idx, const void* buf, uint32_t n);  /* вывод -> мастер */

/* Забрать отложенный Ctrl+C (1 = был, 0 = нет). */
int pty_take_signal(int idx);

#endif
