#ifndef SCHED_TASK_H
#define SCHED_TASK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define TASK_MAX         16
#define TASK_STACK_SIZE  8192
#define TASK_NAME_MAX    16
#define TASK_SLICE_TICKS 4
#define TASK_PID_SYSTEMD 0
#define TASK_CWD_MAX     128
#define TASK_FD_MAX      16

#define TASK_FD_NONE 0
#define TASK_FD_SOCK 1
#define TASK_FD_FILE 2

enum task_state {
    TASK_UNUSED = 0,
    TASK_READY,
    TASK_RUNNING,
    TASK_BLOCKED,
    TASK_ZOMBIE
};

enum task_wait_reason {
    WAIT_NONE = 0,
    WAIT_SLEEP,
    WAIT_NET
};

typedef void (*task_entry_fn)(void* arg);

struct task_fd {
    uint8_t type;
    int handle;           /* global socket fd or -1 */
    char path[64];        /* for FD_FILE */
};

struct task {
    int id;
    enum task_state state;
    uint32_t* esp;
    uint8_t* stack;
    task_entry_fn entry;
    void* arg;
    char name[TASK_NAME_MAX];
    uint32_t runs;
    uint32_t wake_ms;
    enum task_wait_reason wait_reason;
    bool is_idle;
    int parent_pid;
    char cwd[TASK_CWD_MAX];
    struct task_fd fds[TASK_FD_MAX];
    uint32_t cr3;         /* 0 = kernel shared page dir */
    bool is_user;         /* ring-3 process (Phase 3+) */
    uint32_t user_entry;  /* ring-3 EIP */
    uint32_t user_stack;  /* ring-3 ESP (top) */
    uint32_t kstack_top;  /* kernel stack top (TSS.esp0) */
    uint16_t uid;         /* user id (0 = root) */
    uint16_t gid;         /* primary group id */
};

void sched_init(void);
bool sched_ready(void);

int task_create(task_entry_fn entry, void* arg, const char* name);
int task_set_idle(int id);

void sched_yield(void);
void task_exit(void);

int task_kill(int id);
enum task_state task_get_state(int id);

void task_block_timeout(enum task_wait_reason reason, uint32_t deadline_ms);
void task_sleep_ms(uint32_t ms);

void sched_wake_net(void);
void sched_on_tick(void);
void sched_maybe_preempt(void);

struct task* sched_current(void);
int sched_current_id(void);
int sched_task_count(void);

typedef void (*task_iter_fn)(const struct task* t, void* userdata);
void sched_foreach(task_iter_fn fn, void* userdata);

const char* task_state_str(enum task_state st);

/* Per-task cwd */
const char* task_getcwd(void);
int task_chdir(const char* path);
int task_getcwd_pid(int pid, char* out, size_t out_cap);

/* Per-task fd table */
int task_fd_alloc(uint8_t type, int handle, const char* path);
int task_fd_close(int fd);
void task_fd_close_all(struct task* t);
int task_fd_get(int fd, uint8_t* type_out, int* handle_out);

/* Phase 4: fork copies cwd/fds; exec replaces entry on a READY child not yet run — or current via trampoline reset */
int task_fork(task_entry_fn entry, void* arg, const char* name);
int task_exec(task_entry_fn entry, void* arg, const char* name);

void task_resources_cleanup(int pid);

/* Allocate private identity CR3 for task (0 = already has / fail). */
int task_enable_aspace(int id);

/*
 * Запуск ring3-процесса из ELF-образа. Загружает сегменты, выделяет
 * стек и создаёт READY-задачу (is_user=1). Возвращает tid или <0.
 */
int task_spawn_user(const uint8_t* elf_img, size_t elf_len, const char* name);

/*
 * exec для ring3-процесса: заменяет образ текущей задачи ПОЛНЫМ файлом
 * программы (ELF), прочитанным из ФС по path. При успехе не возвращается —
 * задача продолжается с новой entry на новом user-стеке (fd/cwd/uid
 * сохраняются). Возвращает <0 при ошибке.
 */
int task_exec_user(const char* path);

/* Per-task uid. 0 = root, обычный user = 1000. */
int task_getuid(void);
int task_setuid(uint16_t uid);
int task_setuid_pid(int pid, uint16_t uid);
/* Принудительная смена uid текущей задачи (для login/logout в привилегированном shell). */
int task_setuid_force(uint16_t uid);

/* Per-task primary gid. */
int task_getgid(void);
int task_setgid(uint16_t gid);
int task_setgid_force(uint16_t gid);

int sched_autotest(void);

#endif
