// ftop — монитор ресурсов KnitOS (аналог top для нашей ОС).
// Использование: ftop [N]  — N обновлений (по умолчанию 10); N=0 — до нажатия 'q'.
#include "lib/libk.h"

static void wr(const char* s) { sys_write(1, s, strlen(s)); }

static void pad2(uint32_t v) {
    if (v < 10) putchar('0');
    char b[8];
    snprintf(b, sizeof(b), "%u", v);
    wr(b);
}

static void right(const char* s, int w) {
    int n = (int)strlen(s);
    for (int i = n; i < w; i++) putchar(' ');
    wr(s);
}

static void left(const char* s, int w) {
    int n = (int)strlen(s);
    wr(s);
    for (int i = n; i < w; i++) putchar(' ');
}

static void num(uint32_t v, int w) {
    char b[16];
    snprintf(b, sizeof(b), "%u", v);
    right(b, w);
}

static void pct(uint32_t tenths, int w) {
    char b[16];
    snprintf(b, sizeof(b), "%u.%u%%", tenths / 10u, tenths % 10u);
    right(b, w);
}

/* Прогресс-бар загрузки: [####------] с цветом (зелёный/жёлтый/красный).
   На консоли ядра ANSI-цвета игнорируются парсером, по SSH — видны. */
#define BAR_WIDTH 24
static void bar(uint32_t tenths, int width) {
    if (tenths > 1000u) tenths = 1000u;
    int filled = (int)((tenths * (uint32_t)width + 500u) / 1000u);
    if (filled > width) filled = width;
    const char* col = (tenths >= 800u) ? "\x1b[31m"
                    : (tenths >= 500u) ? "\x1b[33m" : "\x1b[32m";
    putchar('[');
    wr(col);
    for (int i = 0; i < filled; i++) putchar('#');
    wr("\x1b[0m");
    for (int i = filled; i < width; i++) putchar('-');
    putchar(']');
}

/* Проценты в десятых (part/total*1000) без переполнения 32 бит. */
static uint32_t pct1000(uint32_t part, uint32_t total) {
    if (!total) return 0;
    uint32_t denom = total / 1000u;
    if (denom == 0) denom = 1;
    uint32_t v = part / denom;
    return v > 1000u ? 1000u : v;
}

static void fmt_bytes(uint32_t b, char* out, unsigned long cap) {
    if (b >= 1024u * 1024u) {
        snprintf(out, cap, "%u.%uM", b / (1024u * 1024u), (b / (1024u * 102u)) % 10u);
    } else if (b >= 1024u) {
        snprintf(out, cap, "%uK", b / 1024u);
    } else {
        snprintf(out, cap, "%uB", b);
    }
}

static const char* state_str(uint32_t s) {
    switch (s) {
        case 1: return "READY";
        case 2: return "RUN";
        case 3: return "BLOCK";
        case 4: return "ZOMB";
        default: return "UNUSED";
    }
}

static const char* user_str(uint32_t uid) {
    if (uid == 0) return "root";
    if (uid == 1000) return "user";
    return "other";
}

int main(int argc, char** argv) {
    /* N — число обновлений (по умолчанию 10); N=0 — до нажатия 'q'. */
    int count = 10;
    if (argc > 1 && argv[1] && argv[1][0]) {
        count = atoi(argv[1]);
        if (count < 0) count = 0;
    }

    static struct sysinfo_s si;
    static struct taskinfo_s tasks[32];
    static uint32_t prev_ticks[32];
    static int prev_pid[32];
    int np = 0;
    uint32_t prev_total = 0, prev_idle = 0;
    int iter = 0;

    wr("\x1b[?25l");   /* спрятать курсор терминала, как top */
    for (;;) {
        if (sys_sysinfo(&si) < 0) { puts("ftop: sysinfo failed"); return 1; }
        int n = (int)sys_task_list(tasks, 32);
        if (n < 0) n = 0;

        uint32_t dtotal = si.cpu_ticks - prev_total;
        uint32_t didle = si.idle_ticks - prev_idle;
        if (prev_total == 0) { dtotal = si.cpu_ticks; didle = si.idle_ticks; }
        uint32_t busy_tenths = dtotal ? (uint32_t)(((uint32_t)(dtotal - didle) * 1000u) / dtotal) : 0;

        char b1[24], b2[24];

        /* Перерисовка «на месте», как в top: курсор в начало, затираем кадр. */
        if (iter == 0) wr("\x1b[2J\x1b[H");
        else wr("\x1b[H");
        wr("ftop - KnitOS resource monitor    (q to quit)\n");
        uint32_t secs = si.uptime_ms / 1000u;
        uint32_t dd = secs / 86400u, hh = (secs / 3600u) % 24u, mm = (secs / 60u) % 60u, ss = secs % 60u;
        wr("uptime ");
        num(dd, 1); wr("d ");
        pad2(hh); putchar(':'); pad2(mm); putchar(':'); pad2(ss);
        wr("   tasks "); num((uint32_t)n, 1);
        wr("\n");

        /* CPU: прогресс-бар загрузки (как в top) */
        uint32_t idle_tenths = dtotal ? (uint32_t)(((uint32_t)didle * 1000u) / dtotal) : 0;
        wr("cpu   "); bar(busy_tenths, BAR_WIDTH);
        putchar(' '); pct(busy_tenths, 6);
        wr("  idle "); pct(idle_tenths, 6);
        wr("\n");

        /* Память: бар + числа */
        uint32_t mem_tenths = pct1000(si.heap_used, si.heap_total);
        fmt_bytes(si.heap_total, b1, sizeof(b1));
        fmt_bytes(si.heap_used, b2, sizeof(b2));
        wr("mem   "); bar(mem_tenths, BAR_WIDTH);
        putchar(' '); pct(mem_tenths, 6);
        wr("  "); wr(b2); wr(" / "); wr(b1);
        wr("   frames "); num(si.frames_used, 1); putchar('/'); num(si.frames_total, 1);
        wr("  asdir "); num(si.asdir_used, 1); putchar('/'); num(si.asdir_max, 1);
        wr("  pf "); num(si.pf_count, 1);
        wr("\n");

        /* Диск */
        if (si.disk_total) {
            uint32_t disk_tenths = pct1000(si.disk_used, si.disk_total);
            fmt_bytes(si.disk_total, b1, sizeof(b1));
            fmt_bytes(si.disk_used, b2, sizeof(b2));
            wr("disk  "); bar(disk_tenths, BAR_WIDTH);
            putchar(' '); pct(disk_tenths, 6);
            wr("  "); wr(b2); wr(" / "); wr(b1);
            wr("\n");
        }

        /* Сеть */
        fmt_bytes(si.net_rx_bytes, b1, sizeof(b1));
        fmt_bytes(si.net_tx_bytes, b2, sizeof(b2));
        wr("net   eth0 RX "); num(si.net_rx_packets, 1); wr("p/"); wr(b1);
        wr(" TX "); num(si.net_tx_packets, 1); wr("p/"); wr(b2);
        wr("   drop "); num(si.net_rx_dropped, 1);
        wr("  err "); num(si.net_tx_errors, 1);
        wr("\n\n");

        /* Таблица задач */
        wr(" PID  PPID  USER   S      CPU%   RUNS  NAME\n");
        for (int i = 0; i < n; i++) {
            uint32_t prev = 0;
            for (int j = 0; j < np; j++)
                if (prev_pid[j] == tasks[i].pid) prev = prev_ticks[j];
            uint32_t d = tasks[i].cpu_ticks - prev;
            uint32_t tenths = dtotal ? (uint32_t)(((uint32_t)d * 1000u) / dtotal) : 0;

            num((uint32_t)tasks[i].pid, 4); putchar(' ');
            if (tasks[i].ppid < 0) right("-", 5);
            else num((uint32_t)tasks[i].ppid, 5);
            wr("  ");
            left(user_str(tasks[i].uid), 5); wr("  ");
            left(state_str(tasks[i].state), 5); putchar(' ');
            pct(tenths, 6); putchar(' ');
            num(tasks[i].runs, 6); wr("  ");
            wr(tasks[i].name);
            wr("\n");
        }
        wr("\x1b[J");   /* стереть «хвост» от предыдущего кадра */

        /* Сохраняем срез для следующего интервала */
        for (int i = 0; i < n && i < 32; i++) {
            prev_pid[i] = tasks[i].pid;
            prev_ticks[i] = tasks[i].cpu_ticks;
        }
        np = n;
        prev_total = si.cpu_ticks;
        prev_idle = si.idle_ticks;

        iter++;
        if (count && iter >= count) break;

        /* Выход по 'q' / Ctrl+C (ввод с консоли неблокирующий). */
        char c;
        if (sys_read(0, &c, 1) == 1) {
            if (c == 'q' || c == 'Q' || c == 3) break;
        }
        sys_sleep(1000);
    }
    /* Как top: на выходе очищаем экран, чтобы не оставлять кадр. */
    wr("\x1b[2J\x1b[H");
    wr("\x1b[?25h");   /* вернуть курсор терминала */
    return 0;
}
