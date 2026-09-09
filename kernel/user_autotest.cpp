#include "user_autotest.h"
#include "sched/task.h"
#include "mm/paging.h"
#include "fs.h"
#include "vfs.h"
#include "ramfs.h"
#include "serial_log.h"
#include "drivers/timer/pit.h"
#include <stdint.h>
#include <stddef.h>

extern char user_demo2_start[], user_demo2_end[];
extern char user_demo3_start[], user_demo3_end[];

#define PDE_USER_FLAG 0x004u

static const char* g_expect = "hello from ring3\nuid=1000\nsetuid0=denied\nuid2=1000\n";

static int wait_wombie(int pid, uint32_t timeout_ms) {
    uint32_t t0 = timer_ms();
    while (timer_ms_since(t0) < timeout_ms) {
        enum task_state st = task_get_state(pid);
        if (st == TASK_ZOMBIE || st == TASK_UNUSED) return 0;
        sched_yield();
        asm volatile ("sti; hlt");
    }
    return -1;
}

static int try_read_tmp(const char* path, char* buf, size_t cap) {
    if (!buf || cap < 2) return -1;
    for (int i = 0; i < 40; i++) {
        int n = vfs_read(path, buf, cap - 1);
        if (n >= 0) {
            buf[n] = 0;
            return n;
        }
        sched_yield();
        asm volatile ("sti; hlt");
    }
    return -1;
}

static int expect_eq(const char* got, int n, const char* want) {
    int i = 0;
    while (want[i]) {
        if (i >= n || got[i] != want[i]) return -1;
        i++;
    }
    return (i == n) ? 0 : -1;
}

int user_autotest_run(void) {
    /* Гарантируем /tmp (ramfs) — работает и без MOS-диска. */
    ramfs_mount_tmp();

    log_msg(LOG_INFO, "autotest", "user_start");

    /* 1) Реальная страничная изоляция: новые каталоги supervisor по умолчанию,
          PDE_USER ставится точечно через paging_mark_user_pde. */
    {
        uint32_t dir = paging_create_identity_dir();
        if (!dir) {
            log_msg(LOG_ERR, "autotest", "isolev_nodir");
            return -1;
        }
        uint32_t* pd = (uint32_t*)(dir & ~0xFFFu);
        if (pd[0] & PDE_USER_FLAG) {
            log_msg(LOG_ERR, "autotest", "isolev_kernel_user");
            paging_free_dir(dir);
            return -2;
        }
        paging_mark_user_pde(dir, 1);
        if (!(pd[1] & PDE_USER_FLAG)) {
            log_msg(LOG_ERR, "autotest", "isolev_mark_failed");
            paging_free_dir(dir);
            return -3;
        }
        paging_free_dir(dir);
        log_msg(LOG_INFO, "autotest", "isolev_ok");
    }

    /* 2) Ring3-процесс demo2: файловые операции, getuid/setuid, getcwd, sleep. */
    {
        size_t sz = (size_t)(user_demo2_end - user_demo2_start);
        if (sz == 0) {
            log_msg(LOG_ERR, "autotest", "demo2_empty");
            return -4;
        }
        int pid = task_spawn_user((const uint8_t*)user_demo2_start, sz, "demo2");
        if (pid < 0) {
            log_fmt3(LOG_ERR, "autotest", "demo2_spawn_failed", "rc", 1u, "ok", 0u, "x", 0u);
            return -5;
        }
        if (wait_wombie(pid, 8000) != 0) {
            log_fmt3(LOG_ERR, "autotest", "demo2_timeout", "tid", (uint32_t)pid, "ok", 0u, "x", 0u);
            return -6;
        }
        char buf[128];
        int n = try_read_tmp("/tmp/udemo.txt", buf, sizeof(buf));
        if (n < 0 || expect_eq(buf, n, g_expect) != 0) {
            log_msg(LOG_ERR, "autotest", "demo2_output_mismatch");
            return -7;
        }
        log_msg(LOG_INFO, "autotest", "demo2_ok");
    }

    /* 3) demo3 нарушает изоляцию (читает supervisor-страницу ядра):
          ядро убивает задачу через #PF вместо паники. Система должна жить. */
    {
        size_t sz = (size_t)(user_demo3_end - user_demo3_start);
        if (sz == 0) {
            log_msg(LOG_ERR, "autotest", "demo3_empty");
            return -8;
        }
        int pid = task_spawn_user((const uint8_t*)user_demo3_start, sz, "demo3");
        if (pid < 0) {
            log_fmt3(LOG_ERR, "autotest", "demo3_spawn_failed", "rc", 1u, "ok", 0u, "x", 0u);
            return -9;
        }
        if (wait_wombie(pid, 4000) != 0) {
            log_fmt3(LOG_ERR, "autotest", "demo3_survived", "tid", (uint32_t)pid, "ok", 0u, "x", 0u);
            return -10;
        }
        log_msg(LOG_INFO, "autotest", "demo3_killed_ok");
    }

    log_msg(LOG_INFO, "autotest", "user_ok");
    return 0;
}