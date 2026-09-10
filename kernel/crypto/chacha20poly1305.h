#ifndef CRYPTO_CHACHA20POLY1305_H
#define CRYPTO_CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE   32
#define CHACHA20_NONCE_SIZE 12
#define POLY1305_TAG_SIZE   16

/* ChaCha20 stream cipher (RFC 8439 §2.4). */
void chacha20_xor(uint8_t* out, const uint8_t* in, size_t len,
                  const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

/* Poly1305 one-time MAC (RFC 8439 §2.5). */
void poly1305(uint8_t tag[16], const uint8_t* msg, size_t len,
              const uint8_t key[32]);

/* AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8). Encrypts `len` bytes.
   out must have room for len + 16 (ciphertext || tag). */
void chacha20poly1305_encrypt(uint8_t* out,
                              const uint8_t* plain, size_t len,
                              const uint8_t* aad, size_t aad_len,
                              const uint8_t nonce[12],
                              const uint8_t key[32]);

/* Returns 1 if the tag is valid, 0 otherwise. Decrypts in place into `out`. */
int chacha20poly1305_decrypt(uint8_t* out,
                             const uint8_t* cipher, size_t len,
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t nonce[12],
                             const uint8_t key[32]);

#endif
