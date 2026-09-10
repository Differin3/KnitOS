#ifndef CRYPTO_ED25519_H
#define CRYPTO_ED25519_H

#include <stdint.h>
#include <stddef.h>

#define ED25519_PK_SIZE 32
#define ED25519_SK_SIZE 64
#define ED25519_SIG_SIZE 64

/* Генерирует пару ключей из seed: sk = seed(32) || pk(32). */
void ed25519_keypair_from_seed(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

/* Подписывает сообщение. sig = 64 байта. */
void ed25519_sign(uint8_t sig[64], const void* msg, size_t len, const uint8_t sk[64]);

/* Проверяет подпись. Возвращает 1 если верна, 0 иначе. */
int ed25519_verify(const uint8_t sig[64], const void* msg, size_t len, const uint8_t pk[32]);

/* Экспорт публичного ключа из приватного (sk = seed||pk). */
void ed25519_public_key(uint8_t pk[32], const uint8_t sk[64]);

#endif
