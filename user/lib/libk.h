#ifndef LIBK_H
#define LIBK_H

#include "syscall.h"

typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

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

#endif
