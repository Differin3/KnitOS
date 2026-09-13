#ifndef KERNEL_HEAP_H
#define KERNEL_HEAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void* malloc(size_t size);
void free(void* ptr);
void* realloc(void* ptr, size_t size);
void* calloc(size_t nmemb, size_t size);

/* Статистика кучи (для мониторинга). Любой указатель может быть NULL. */
void heap_get_stats(uint32_t* total, uint32_t* used, uint32_t* free_bytes);

#ifdef __cplusplus
}
#endif

#endif
