#ifndef LIBK_H
#define LIBK_H

#include "syscall.h"

typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;

#ifndef NULL
#define NULL ((void*)0)
#endif

/* string */
void* memcpy(void* d, const void* s, size_t n);
void* memmove(void* d, const void* s, size_t n);
void* memset(void* d, int c, size_t n);
int   memcmp(const void* a, const void* b, size_t n);
size_t strlen(const char* s);
int   strcmp(const char* a, const char* b);
int   strncmp(const char* a, const char* b, size_t n);
char* strcpy(char* d, const char* s);
char* strncpy(char* d, const char* s, size_t n);
char* strcat(char* d, const char* s);
char* strchr(const char* s, int c);
char* strrchr(const char* s, int c);
char* strstr(const char* h, const char* n);

/* stdlib */
void* malloc(size_t n);
void  free(void* p);
void* calloc(size_t n, size_t sz);
void* realloc(void* p, size_t n);
int   atoi(const char* s);
long  atol(const char* s);
void  exit(int code) __attribute__((noreturn));

/* stdio (subset) */
int   printf(const char* fmt, ...);
int   snprintf(char* buf, size_t cap, const char* fmt, ...);
int   puts(const char* s);
int   putchar(int c);

/* helpers */
int   htons_i(int v);
uint32_t htonl_u(uint32_t v);

/* crypto (через SYS_CRYPTO) */
int kc_sha256(const void* data, size_t len, unsigned char out[32]);
int kc_hmac_sha256(const void* key, size_t klen, const void* msg, size_t mlen,
                   unsigned char out[32]);
int kc_x25519(const unsigned char scalar[32], const unsigned char point[32],
              unsigned char out[32]);
int kc_random(void* out, size_t n);
/* out: plain_len + 16 байт */
int kc_aead_encrypt(const unsigned char key[32], const unsigned char nonce[12],
                    const void* aad, size_t aad_len,
                    const void* plain, size_t plain_len, unsigned char* out);
/* cipher_len = plain_len + 16; out: plain_len байт. <0 при неверном теге. */
int kc_aead_decrypt(const unsigned char key[32], const unsigned char nonce[12],
                    const void* aad, size_t aad_len,
                    const void* cipher, size_t cipher_len, unsigned char* out);

#endif
