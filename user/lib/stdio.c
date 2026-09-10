// libk: printf subset (write to fd 1) + helpers.
#include "libk.h"

int putchar(int c) {
    char ch = (char)c;
    sys_write(1, &ch, 1);
    return c;
}
int puts(const char* s) {
    size_t n = strlen(s);
    sys_write(1, s, n);
    sys_write(1, "\n", 1);
    return (int)n + 1;
}

struct sink {
    char* buf;
    size_t cap;
    size_t len;   /* total would-be length */
};

static void emit(struct sink* s, char c) {
    if (s->buf) {
        if (s->len + 1 < s->cap) s->buf[s->len] = c;
    } else {
        sys_write(1, &c, 1);
    }
    s->len++;
}

static void emit_str(struct sink* s, const char* str) {
    while (*str) emit(s, *str++);
}

static void emit_uint(struct sink* s, unsigned long v, int base, int upper) {
    char tmp[24];
    int t = 0;
    const char* dg = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (v == 0) tmp[t++] = '0';
    while (v > 0 && t < 24) { tmp[t++] = dg[v % (unsigned)base]; v /= (unsigned)base; }
    while (t > 0) emit(s, tmp[--t]);
}

static void emit_int(struct sink* s, long v) {
    if (v < 0) { emit(s, '-'); emit_uint(s, (unsigned long)(-v), 10, 0); }
    else emit_uint(s, (unsigned long)v, 10, 0);
}

static int vfmt(struct sink* s, const char* fmt, __builtin_va_list ap) {
    for (; *fmt; fmt++) {
        if (*fmt != '%') { emit(s, *fmt); continue; }
        fmt++;
        int is_long = 0;
        while (*fmt == 'l') { is_long = 1; fmt++; }
        switch (*fmt) {
            case 'd': case 'i':
                if (is_long) emit_int(s, __builtin_va_arg(ap, long));
                else emit_int(s, __builtin_va_arg(ap, int));
                break;
            case 'u':
                if (is_long) emit_uint(s, __builtin_va_arg(ap, unsigned long), 10, 0);
                else emit_uint(s, __builtin_va_arg(ap, unsigned int), 10, 0);
                break;
            case 'x':
                if (is_long) emit_uint(s, __builtin_va_arg(ap, unsigned long), 16, 0);
                else emit_uint(s, __builtin_va_arg(ap, unsigned int), 16, 0);
                break;
            case 'X':
                if (is_long) emit_uint(s, __builtin_va_arg(ap, unsigned long), 16, 1);
                else emit_uint(s, __builtin_va_arg(ap, unsigned int), 16, 1);
                break;
            case 'p':
                emit(s, '0'); emit(s, 'x');
                emit_uint(s, (unsigned long)__builtin_va_arg(ap, void*), 16, 0);
                break;
            case 'c': emit(s, (char)__builtin_va_arg(ap, int)); break;
            case 's': emit_str(s, __builtin_va_arg(ap, const char*)); break;
            case '%': emit(s, '%'); break;
            case 0: return (int)s->len;
            default: emit(s, '%'); emit(s, *fmt); break;
        }
    }
    return (int)s->len;
}

int printf(const char* fmt, ...) {
    struct sink s = { 0, 0, 0 };
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int n = vfmt(&s, fmt, ap);
    __builtin_va_end(ap);
    return n;
}

int snprintf(char* buf, size_t cap, const char* fmt, ...) {
    struct sink s = { buf, cap, 0 };
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int n = vfmt(&s, fmt, ap);
    __builtin_va_end(ap);
    if (cap > 0) {
        size_t term = s.len < cap ? s.len : cap - 1;
        buf[term] = 0;
    }
    return n;
}

int htons_i(int v) { return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF); }
uint32_t htonl_u(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}
