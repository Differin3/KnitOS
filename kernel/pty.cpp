#include "pty.h"
#include "sched/task.h"

struct kpty {
    bool used;
    /* Ввод для slave (от мастера), уже прошедший line discipline. */
    uint8_t in_buf[KPTY_BUF];
    uint32_t in_head;
    uint32_t in_tail;
    uint32_t in_count;
    /* Вывод slave (для мастера). */
    uint8_t out_buf[KPTY_BUF];
    uint32_t out_head;
    uint32_t out_tail;
    uint32_t out_count;
    /* Текущая набираемая строка (канонический режим). */
    uint8_t line[KPTY_BUF];
    uint32_t line_len;
    int master_refs;
    int slave_refs;
    int sigint;
    int eof;
    int raw;
};

static struct kpty g_ptys[KPTY_MAX];

static void ring_push(uint8_t* buf, uint32_t* head, uint32_t* count, uint8_t c) {
    if (*count >= KPTY_BUF) return;
    buf[*head] = c;
    *head = (*head + 1) % KPTY_BUF;
    (*count)++;
}

static int ring_pop(uint8_t* buf, uint32_t* tail, uint32_t* count, uint8_t* out) {
    if (*count == 0) return 0;
    *out = buf[*tail];
    *tail = (*tail + 1) % KPTY_BUF;
    (*count)--;
    return 1;
}

int pty_create(void) {
    for (int i = 0; i < KPTY_MAX; i++) {
        if (g_ptys[i].used) continue;
        struct kpty* p = &g_ptys[i];
        p->used = true;
        p->in_head = p->in_tail = p->in_count = 0;
        p->out_head = p->out_tail = p->out_count = 0;
        p->line_len = 0;
        p->master_refs = 0;
        p->slave_refs = 0;
        p->sigint = 0;
        p->eof = 0;
        p->raw = 0;
        return i;
    }
    return -1;
}

void pty_ref(int idx, int master) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return;
    if (master) g_ptys[idx].master_refs++;
    else g_ptys[idx].slave_refs++;
}

void pty_unref(int idx, int master) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return;
    struct kpty* p = &g_ptys[idx];
    if (master) {
        if (p->master_refs > 0) p->master_refs--;
    } else {
        if (p->slave_refs > 0) p->slave_refs--;
    }
    if (p->master_refs == 0 && p->slave_refs == 0) p->used = false;
}

/* Эхо в сторону мастера (то, что видит пользователь). */
static void pty_echo(struct kpty* p, const char* s) {
    while (*s) ring_push(p->out_buf, &p->out_head, &p->out_count, (uint8_t)*s++);
}

int pty_master_write(int idx, const void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return -1;
    struct kpty* p = &g_ptys[idx];
    const uint8_t* in = (const uint8_t*)buf;
    if (p->raw) {
        /* Raw: байты идут как есть, без line discipline и эха. */
        for (uint32_t i = 0; i < n; i++)
            ring_push(p->in_buf, &p->in_head, &p->in_count, in[i]);
        return (int)n;
    }
    for (uint32_t i = 0; i < n; i++) {
        uint8_t c = in[i];
        if (c == '\r' || c == '\n') {
            pty_echo(p, "\r\n");
            for (uint32_t k = 0; k < p->line_len; k++) {
                ring_push(p->in_buf, &p->in_head, &p->in_count, p->line[k]);
            }
            ring_push(p->in_buf, &p->in_head, &p->in_count, '\n');
            p->line_len = 0;
        } else if (c == 0x7f || c == 0x08) {
            if (p->line_len > 0) {
                p->line_len--;
                pty_echo(p, "\b \b");
            }
        } else if (c == 0x03) {
            p->sigint = 1;
            pty_echo(p, "^C\r\n");
            p->line_len = 0;
        } else if (c == 0x04) {
            /* Ctrl+D: отдать накопленную строку и выставить EOF (без эха). */
            for (uint32_t k = 0; k < p->line_len; k++)
                ring_push(p->in_buf, &p->in_head, &p->in_count, p->line[k]);
            p->line_len = 0;
            p->eof = 1;
        } else {
            if (p->line_len < KPTY_BUF) p->line[p->line_len++] = c;
            ring_push(p->out_buf, &p->out_head, &p->out_count, c);
        }
    }
    return (int)n;
}

int pty_master_read(int idx, void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return -1;
    struct kpty* p = &g_ptys[idx];
    uint8_t* out = (uint8_t*)buf;
    uint32_t i = 0;
    while (i < n) {
        if (ring_pop(p->out_buf, &p->out_tail, &p->out_count, &out[i])) {
            i++;
            continue;
        }
        if (i > 0) break;
        if (p->slave_refs == 0) break; /* EOF: программа закрыла slave */
        sched_yield();
    }
    return (int)i;
}

int pty_master_read_nb(int idx, void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return -1;
    struct kpty* p = &g_ptys[idx];
    uint8_t* out = (uint8_t*)buf;
    uint32_t i = 0;
    while (i < n && ring_pop(p->out_buf, &p->out_tail, &p->out_count, &out[i])) i++;
    return (int)i;
}

int pty_slave_read(int idx, void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return -1;
    struct kpty* p = &g_ptys[idx];
    uint8_t* out = (uint8_t*)buf;
    uint32_t i = 0;
    while (i < n) {
        if (ring_pop(p->in_buf, &p->in_tail, &p->in_count, &out[i])) {
            i++;
            continue;
        }
        if (i > 0) break;
        if (p->in_count == 0 && p->eof) { p->eof = 0; break; } /* Ctrl+D EOF */
        if (p->master_refs == 0) break; /* EOF: мастер закрыт */
        sched_yield();
    }
    return (int)i;
}

int pty_slave_write(int idx, const void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return -1;
    struct kpty* p = &g_ptys[idx];
    const uint8_t* in = (const uint8_t*)buf;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t c = in[i];
        if (c == '\n') ring_push(p->out_buf, &p->out_head, &p->out_count, '\r');
        ring_push(p->out_buf, &p->out_head, &p->out_count, c);
    }
    return (int)n;
}

int pty_take_signal(int idx) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return 0;
    int s = g_ptys[idx].sigint;
    g_ptys[idx].sigint = 0;
    return s;
}

void pty_set_raw(int idx, int raw) {
    if (idx < 0 || idx >= KPTY_MAX || !g_ptys[idx].used) return;
    g_ptys[idx].raw = raw ? 1 : 0;
}
