// Kernel commands callable from user space (via SYS_KCMD).
//
// The user-space shell posts a command; the kernel console shell (boot task)
// runs it through its normal command dispatcher with terminal output
// captured, so ALL console commands work over SSH with their full output.
#include "kcmd.h"
#include "kernel.h"
#include "sched/task.h"
#include "drivers/timer/pit.h"
#include "drivers/video/terminal.h"
#include "drivers/network/core/netif.h"
#include "drivers/network/protocols/ip.h"
#include "fs.h"
#include <string.h>

#define KCMD_REQ_CAP  256
#define KCMD_RESP_CAP 8192

/* 0 = idle, 1 = request pending, 2 = response ready */
static volatile int    g_state = 0;
static char            g_req[KCMD_REQ_CAP];
static char            g_resp[KCMD_RESP_CAP];
static volatile size_t g_resp_len = 0;

/* ---- bridge (called from the kernel console shell) ---- */

int kernel_kcmd_take(char* cmd, size_t cap) {
    if (g_state != 1) return 0;
    size_t i = 0;
    while (g_req[i] && i + 1 < cap) { cmd[i] = g_req[i]; i++; }
    cmd[i] = 0;
    return 1;
}

char*  kernel_kcmd_resp(void)     { return g_resp; }
size_t kernel_kcmd_resp_cap(void) { return KCMD_RESP_CAP; }

void kernel_kcmd_reply(size_t len) {
    if (len > KCMD_RESP_CAP) len = KCMD_RESP_CAP;
    if (len < KCMD_RESP_CAP) g_resp[len] = 0;
    g_resp_len = len;
    g_state = 2;
}

/* ---- subset fallback (used if the console shell is not available) ---- */

struct sb { char* p; size_t cap; size_t len; };
static void sb_str(struct sb* s, const char* t) {
    while (*t && s->len + 1 < s->cap) s->p[s->len++] = *t++;
}
static void sb_u32(struct sb* s, uint32_t v) {
    char tmp[12]; int t = 0;
    if (v == 0) tmp[t++] = '0';
    while (v && t < 11) { tmp[t++] = (char)('0' + v % 10); v /= 10; }
    while (t > 0) { if (s->len + 1 < s->cap) s->p[s->len++] = tmp[--t]; }
}
static int starts(const char* s, const char* p) {
    while (*p) { if (*s++ != *p++) return 0; }
    return 1;
}
static void ps_cb(const struct task* t, void* ud) {
    struct sb* s = (struct sb*)ud;
    sb_str(s, "pid "); sb_u32(s, (uint32_t)t->id);
    sb_str(s, "  "); sb_str(s, task_state_str(t->state));
    sb_str(s, "  "); sb_str(s, t->name); sb_str(s, "\n");
}
static int kcmd_fallback(const char* cmd, char* out, size_t cap) {
    struct sb s; s.p = out; s.cap = cap; s.len = 0;
    if (starts(cmd, "uname")) {
        sb_str(&s, "KnitOS " KERNEL_VERSION "\n");
    } else if (starts(cmd, "uptime")) {
        sb_str(&s, "uptime: "); sb_u32(&s, timer_ms() / 1000); sb_str(&s, " s\n");
    } else if (starts(cmd, "ps")) {
        sched_foreach(ps_cb, &s);
    } else if (starts(cmd, "ifconfig")) {
        int n = netif_count();
        for (int i = 0; i < n; i++) {
            struct netif* nif = netif_get(i);
            if (!nif) continue;
            char ip[16];
            sb_str(&s, nif->name); sb_str(&s, ": ");
            if (nif->up) sb_str(&s, "UP ");
            ip_format_address(nif->ip, ip, sizeof(ip));
            sb_str(&s, "inet "); sb_str(&s, ip); sb_str(&s, "\n  ether ");
            static const char hx[] = "0123456789abcdef";
            for (int k = 0; k < 6; k++) {
                char b[3] = { hx[nif->mac[k] >> 4], hx[nif->mac[k] & 15], 0 };
                sb_str(&s, b);
                if (k < 5) sb_str(&s, ":");
            }
            sb_str(&s, "\n");
        }
    } else if (starts(cmd, "df")) {
        uint32_t total = 0, used = 0, freeb = 0;
        fs_get_disk_usage(&total, &used, &freeb);
        sb_str(&s, "total="); sb_u32(&s, total);
        sb_str(&s, " used="); sb_u32(&s, used);
        sb_str(&s, " free="); sb_u32(&s, freeb);
        sb_str(&s, "\n");
    } else {
        return 0;
    }
    if (s.len < s.cap) s.p[s.len] = 0;
    return (int)s.len;
}

/* ---- entry point used by SYS_KCMD ---- */

int kernel_run_command(const char* cmd, char* out, size_t cap) {
    if (!cmd || !out || cap == 0) return 0;

    size_t n = 0;
    while (cmd[n] && n < KCMD_REQ_CAP - 1) { g_req[n] = cmd[n]; n++; }
    g_req[n] = 0;
    g_resp_len = 0;
    g_state = 1;

    /* Ждём, пока консольный shell выполнит команду. */
    uint32_t t0 = timer_ms();
    while (g_state == 1) {
        sched_yield();
        if (timer_ms_since(t0) > 3000) { g_state = 0; break; }
    }

    if (g_state == 2) {
        size_t rl = g_resp_len;
        if (rl > cap) rl = cap;
        for (size_t i = 0; i < rl; i++) out[i] = g_resp[i];
        g_state = 0;
        return (int)rl;
    }

    /* Fallback: ограниченный набор команд, если shell недоступен. */
    return kcmd_fallback(cmd, out, cap);
}
