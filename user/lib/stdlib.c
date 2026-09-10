// libk: minimal malloc (first-fit free list over a static arena) + misc.
#include "libk.h"

#define ARENA_SIZE (256 * 1024)
static uint8_t g_arena[ARENA_SIZE] __attribute__((aligned(16)));
static int g_arena_init = 0;

struct blk {
    size_t size;        /* payload size */
    int free;
    struct blk* next;
};

static struct blk* g_head;

static void arena_init(void) {
    g_head = (struct blk*)g_arena;
    g_head->size = ARENA_SIZE - sizeof(struct blk);
    g_head->free = 1;
    g_head->next = 0;
    g_arena_init = 1;
}

void* malloc(size_t n) {
    if (!g_arena_init) arena_init();
    if (n == 0) return 0;
    n = (n + 15u) & ~(size_t)15u;
    struct blk* b = g_head;
    while (b) {
        if (b->free && b->size >= n) {
            if (b->size >= n + sizeof(struct blk) + 16) {
                struct blk* nb = (struct blk*)((uint8_t*)b + sizeof(struct blk) + n);
                nb->size = b->size - n - sizeof(struct blk);
                nb->free = 1;
                nb->next = b->next;
                b->size = n;
                b->next = nb;
            }
            b->free = 0;
            return (void*)((uint8_t*)b + sizeof(struct blk));
        }
        b = b->next;
    }
    return 0;
}

void free(void* p) {
    if (!p) return;
    struct blk* b = (struct blk*)((uint8_t*)p - sizeof(struct blk));
    b->free = 1;
    /* coalesce forward */
    if (b->next && b->next->free) {
        b->size += sizeof(struct blk) + b->next->size;
        b->next = b->next->next;
    }
    /* coalesce backward */
    struct blk* c = g_head;
    while (c && c->next != b) c = c->next;
    if (c && c->free) {
        c->size += sizeof(struct blk) + b->size;
        c->next = b->next;
    }
}

void* calloc(size_t n, size_t sz) {
    size_t t = n * sz;
    void* p = malloc(t);
    if (p) memset(p, 0, t);
    return p;
}

void* realloc(void* p, size_t n) {
    if (!p) return malloc(n);
    struct blk* b = (struct blk*)((uint8_t*)p - sizeof(struct blk));
    if (b->size >= n) return p;
    void* np = malloc(n);
    if (!np) return 0;
    memcpy(np, p, b->size);
    free(p);
    return np;
}

int atoi(const char* s) {
    int sign = 1, v = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { sign = -1; s++; } else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return sign * v;
}
long atol(const char* s) {
    long sign = 1, v = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { sign = -1; s++; } else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return sign * v;
}

void exit(int code) {
    sys_exit(code);
    for (;;) sys_yield();
}
