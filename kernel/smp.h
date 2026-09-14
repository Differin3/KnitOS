#ifndef SMP_H
#define SMP_H

#include <stdint.h>

/* Инициализация SMP: копирует трамполин, рассылает INIT-SIPI и поднимает AP. */
void smp_init(void);

/* Число ядер, запущенных (включая BSP). */
int smp_cpu_count(void);

#endif
