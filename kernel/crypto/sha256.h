#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[SHA256_BLOCK_SIZE];
    size_t   datalen;
};

void sha256_init(struct sha256_ctx* ctx);
void sha256_update(struct sha256_ctx* ctx, const void* data, size_t len);
void sha256_final(struct sha256_ctx* ctx, uint8_t out[SHA256_DIGEST_SIZE]);
void sha256(const void* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/* HMAC-SHA256 */
void hmac_sha256(const void* key, size_t key_len,
                 const void* msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_SIZE]);

#endif
