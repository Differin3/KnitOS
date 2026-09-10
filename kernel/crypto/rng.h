#ifndef CRYPTO_RNG_H
#define CRYPTO_RNG_H

#include <stdint.h>
#include <stddef.h>

/* Инициализация (идемпотентна). Вызывается лениво. */
void rng_init(void);

/* Заполняет буфер случайными байтами (ChaCha20-based CSPRNG). */
void rng_bytes(void* out, size_t n);

/* 32-битное случайное число. */
uint32_t rng_u32(void);

#endif
