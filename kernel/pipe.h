#ifndef KNITOS_PIPE_H
#define KNITOS_PIPE_H

#include <stdint.h>
#include <stddef.h>

#define KPIPE_MAX 8
#define KPIPE_BUF 4096

/* Создаёт новый канал. Возвращает индекс или -1. */
int pipe_create(void);

/* Читает до n байт. Блокируется, пока нет данных и есть писатели.
   Возвращает число прочитанных байт (0 = все писатели закрыты), -1 = ошибка. */
int pipe_read(int idx, void* buf, uint32_t n);

/* Пишет до n байт. Блокируется, пока буфер полон и есть читатели.
   Возвращает число записанных байт, -1 если читателей нет. */
int pipe_write(int idx, const void* buf, uint32_t n);

/* Закрывает один конец канала (write_end != 0 для пишущего конца). */
void pipe_close(int idx, int write_end);

/* Добавляет ссылку на конец канала (для dup2). */
void pipe_ref(int idx, int write_end);

#endif
