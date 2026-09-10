#ifndef CRYPTO_X25519_H
#define CRYPTO_X25519_H

#include <stdint.h>
#include <stddef.h>

#define X25519_KEY_SIZE 32

/* Curve25519 scalar multiplication (RFC 7748): q = n * p.
   All buffers are 32 bytes. Returns 0. */
int x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/* Derive a public key from a private scalar (base point 9). */
int x25519_public_key(uint8_t pub[32], const uint8_t priv[32]);

#endif
