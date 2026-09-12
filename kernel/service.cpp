// Настоящий init/service manager (аналог systemd): реестр сервисов,
// авто-старт, stop/restart, супервизор с перезапуском упавших.
#include "service.h"
#include "sched/task.h"
#include "drivers/timer/pit.h"
#include "vfs.h"
#include <string.h>

struct service {
    const char* name;
    const char* desc;
    const uint8_t* elf;
    size_t len;
    uint16_t uid;
    int autostart;
    int restart;
    int enabled;
    int state;
    int pid;
    int restarts;
    uint32_t last_ms;
    uint32_t window_ms;   /* начало окна подсчёта перезапусков */
    int burst;            /* перезапусков в текущем окне */
};

static struct service g_svcs[SERVICE_MAX];
static int g_svc_count = 0;
static int g_supervisor_pid = -1;

static struct service* find(const char* name) {
    if (!name) return 0;
    for (int i = 0; i < g_svc_count; i++)
        if (strcmp(g_svcs[i].name, name) == 0) return &g_svcs[i];
    return 0;
}

void service_register(const char* name, const char* desc,
                      const uint8_t* elf, size_t len, uint16_t uid,
                      int autostart, int restart) {
    if (!name || !elf || len == 0 || g_svc_count >= SERVICE_MAX) return;
    struct service* s = &g_svcs[g_svc_count++];
    s->name = name;
    s->desc = desc ? desc : "";
    s->elf = elf;
    s->len = len;
    s->uid = uid;
    s->autostart = autostart;
    s->restart = restart;
    s->enabled = autostart;
    s->state = SVC_STOPPED;
    s->pid = -1;
    s->restarts = 0;
    s->last_ms = 0;
    s->window_ms = 0;
    s->burst = 0;
}

int service_start(const char* name) {
    struct service* s = find(name);
    if (!s) return -1;
    if (s->state == SVC_RUNNING && s->pid > 0 && task_alive(s->pid)) return 0;
    int pid = task_spawn_user_uid(s->elf, s->len, s->name, s->uid);
    if (pid < 0) { s->state = SVC_FAILED; s->pid = -1; return -2; }
    s->pid = pid;
    s->state = SVC_RUNNING;
    s->last_ms = timer_ms();
    return 0;
}

int service_stop(const char* name) {
    struct service* s = find(name);
    if (!s) return -1;
    if (s->pid > 0) task_kill(s->pid);
    s->pid = -1;
    /* SVC_STOPPED = остановлен вручную; супервизор не перезапускает.
       Флаг enabled (авто-старт при загрузке) сохраняется. */
    s->state = SVC_STOPPED;
    return 0;
}

int service_restart(const char* name) {
    struct service* s = find(name);
    if (!s) return -1;
    if (s->pid > 0) task_kill(s->pid);
    s->pid = -1;
    s->state = SVC_STOPPED;
    s->burst = 0;               /* ручной restart сбрасывает лимит */
    s->window_ms = timer_ms();
    return service_start(name);
}

int service_set_enabled(const char* name, int en) {
    struct service* s = find(name);
    if (!s) return -1;
    s->enabled = en ? 1 : 0;
    return 0;
}

void service_supervise(void) {
    for (int i = 0; i < g_svc_count; i++) {
        struct service* s = &g_svcs[i];
        if (s->state == SVC_RUNNING && s->pid > 0 && !task_alive(s->pid)) {
            s->pid = -1;
            if (s->enabled && s->restart) {
                uint32_t now = timer_ms();
                if (now - s->window_ms > 10000) { s->window_ms = now; s->burst = 0; }
                s->burst++;
                s->restarts++;
                if (s->burst > 5) {
                    /* Слишком часто падает — сдаёмся (как StartLimitBurst). */
                    s->state = SVC_FAILED;
                } else if (service_start(s->name) != 0) {
                    s->state = SVC_FAILED;
                }
            } else {
                s->state = SVC_STOPPED;
            }
        }
    }
}

static void supervisor_task(void* arg) {
    (void)arg;
    for (;;) {
        service_supervise();
        task_sleep_ms(1000);
    }
}

void service_init(void) {
    service_load_config();
    for (int i = 0; i < g_svc_count; i++)
        if (g_svcs[i].enabled) service_start(g_svcs[i].name);
    g_supervisor_pid = task_create(supervisor_task, 0, "init");
    (void)g_supervisor_pid;
}

int service_count(void) { return g_svc_count; }

int service_get(int idx, const char** name, const char** desc,
                int* state, int* pid, int* restarts, int* enabled) {
    if (idx < 0 || idx >= g_svc_count) return -1;
    struct service* s = &g_svcs[idx];
    if (name) *name = s->name;
    if (desc) *desc = s->desc;
    if (state) *state = s->state;
    if (pid) *pid = s->pid;
    if (restarts) *restarts = s->restarts;
    if (enabled) *enabled = s->enabled;
    return 0;
}

/* ---- персистентность enable-флага: /etc/systemd.conf ---- */

void service_save_config(void) {
    char buf[SERVICE_MAX * 32];
    size_t n = 0;
    for (int i = 0; i < g_svc_count && n + 24 < sizeof(buf); i++) {
        const char* nm = g_svcs[i].name;
        while (*nm && n + 3 < sizeof(buf)) buf[n++] = *nm++;
        buf[n++] = '=';
        buf[n++] = g_svcs[i].enabled ? '1' : '0';
        buf[n++] = '\n';
    }
    vfs_write("/etc/systemd.conf", buf, n);
}

void service_load_config(void) {
    char buf[512];
    int n = vfs_read("/etc/systemd.conf", buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = 0;
    char* p = buf;
    while (*p) {
        char* line = p;
        while (*p && *p != '\n') p++;
        if (*p == '\n') { *p = 0; p++; }
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        int en = (eq[1] == '1');
        struct service* s = find(line);
        if (s) { s->enabled = en; s->autostart = en; }
    }
}
