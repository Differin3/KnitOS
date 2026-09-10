#include "pipe.h"
#include "sched/task.h"

struct kpipe {
    bool used;
    uint8_t buf[KPIPE_BUF];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    int readers;
    int writers;
};

static struct kpipe g_pipes[KPIPE_MAX];

int pipe_create(void) {
    for (int i = 0; i < KPIPE_MAX; i++) {
        if (g_pipes[i].used) continue;
        g_pipes[i].used = true;
        g_pipes[i].head = 0;
        g_pipes[i].tail = 0;
        g_pipes[i].count = 0;
        g_pipes[i].readers = 1;
        g_pipes[i].writers = 1;
        return i;
    }
    return -1;
}

int pipe_read(int idx, void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPIPE_MAX || !g_pipes[idx].used) return -1;
    struct kpipe* p = &g_pipes[idx];
    uint8_t* out = (uint8_t*)buf;
    uint32_t i = 0;
    while (i < n) {
        if (p->count == 0) {
            if (i > 0) break;
            if (p->writers == 0) break;
            sched_yield();
            continue;
        }
        out[i++] = p->buf[p->tail];
        p->tail = (p->tail + 1) % KPIPE_BUF;
        p->count--;
    }
    return (int)i;
}

int pipe_write(int idx, const void* buf, uint32_t n) {
    if (idx < 0 || idx >= KPIPE_MAX || !g_pipes[idx].used) return -1;
    struct kpipe* p = &g_pipes[idx];
    const uint8_t* in = (const uint8_t*)buf;
    uint32_t i = 0;
    while (i < n) {
        if (p->readers == 0) return -1;
        if (p->count == KPIPE_BUF) {
            sched_yield();
            continue;
        }
        p->buf[p->head] = in[i++];
        p->head = (p->head + 1) % KPIPE_BUF;
        p->count++;
    }
    return (int)i;
}

void pipe_close(int idx, int write_end) {
    if (idx < 0 || idx >= KPIPE_MAX || !g_pipes[idx].used) return;
    struct kpipe* p = &g_pipes[idx];
    if (write_end) {
        if (p->writers > 0) p->writers--;
    } else {
        if (p->readers > 0) p->readers--;
    }
    if (p->readers == 0 && p->writers == 0) p->used = false;
}

void pipe_ref(int idx, int write_end) {
    if (idx < 0 || idx >= KPIPE_MAX || !g_pipes[idx].used) return;
    if (write_end) g_pipes[idx].writers++;
    else g_pipes[idx].readers++;
}
