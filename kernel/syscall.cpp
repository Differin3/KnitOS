#include "syscall.h"
#include "driver_manager.h"
#include "fs.h"
#include "fs_file.h"
#include "vfs.h"
#include "heap.h"
#include "elf.h"
#include "drivers/network/socket.h"
#include "drivers/video/terminal.h"
#include "drivers/input/keyboard.h"
#include "sched/task.h"
#include "mm/paging.h"
#include "pipe.h"
#include <stddef.h>

extern "C" void syscall_handler_asm();

/*
 * Копирование между адресным пространством задачи и ядром.
 * Пока адресное пространство identity-смежное, поэтому безопасность
 * сводится к диапазонной проверке: указатели должны лежать в
 * пользовательском регионе [ELF_USER_VA_MIN, ELF_USER_VA_MAX).
 * Вызовы из ring0 (caller_cs != 0x1B) работают с ядерными указателями.
 */
#define USER_CS 0x1B

#define SYS_BUF_CAP 65536u

static bool user_range_ok(uint32_t addr, uint32_t n, uint32_t max) {
    return addr >= ELF_USER_VA_MIN && addr < max && n <= max - addr;
}

static int user_copy_in(void* dst, const void* src, uint32_t n, uint32_t caller_cs, uint32_t usermax) {
    if (!dst || n == 0) return 0;
    if (caller_cs == USER_CS) {
        if (!user_range_ok((uint32_t)src, n, usermax)) return -1;
    }
    const uint8_t* s = (const uint8_t*)src;
    uint8_t* d = (uint8_t*)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
    return 0;
}

static int user_copy_out(void* dst, const void* src, uint32_t n, uint32_t caller_cs, uint32_t usermax) {
    if (!dst || n == 0) return 0;
    if (caller_cs == USER_CS) {
        if (!user_range_ok((uint32_t)dst, n, usermax)) return -1;
    }
    const uint8_t* s = (const uint8_t*)src;
    uint8_t* d = (uint8_t*)dst;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
    return 0;
}

/* Копия NUL-terminated строки из задачи (до cap-1 байт). 0 = ok. */
static int user_str_copy(char* dst, size_t cap, const char* src, uint32_t caller_cs, uint32_t usermax) {
    if (!dst || cap == 0) return -1;
    if (!src) return -1;
    uint32_t a = (uint32_t)src;
    if (caller_cs == USER_CS && a < ELF_USER_VA_MIN) return -1;
    uint32_t i = 0;
    for (; i + 1 < cap; i++) {
        uint32_t va = a + i;
        if (caller_cs == USER_CS && (va < ELF_USER_VA_MIN || va >= usermax)) return -1;
        char c = *((const char*)va);
        dst[i] = c;
        if (c == 0) return 0;
    }
    dst[i] = 0;
    return 0;
}

/* Первые три fd = консоль (терминал + зеркало в serial). */
static int console_write(const char* buf, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) terminal_putchar(buf[i]);
    return (int)n;
}

/* Ядро-буфер под пользовательский буфер: стек для малых размеров, heap для больших. */
static void* sys_buf_alloc(uint32_t n, void* stackbuf, uint32_t stacksz, int* heap_used) {
    if (n <= stacksz) return stackbuf;
    void* p = malloc(n);
    if (p) *heap_used = 1;
    return p;
}

extern "C" int syscall_handler(struct syscall_args* args, uint32_t caller_cs) {
    if (!args) return -1;

    uint32_t usermax = ELF_USER_VA_MAX;
    uint32_t syscall_num = args->arg0;

    switch (syscall_num) {
        case SYS_READ: {
            int fd = (int)args->arg1;
            char* ubuf = (char*)args->arg2;
            size_t ulen = (size_t)args->arg3;
            if (ulen > SYS_BUF_CAP) return -1;
            uint8_t ty = 0;
            int handle = -1;
            if (fd >= 0 && fd < TASK_FD_MAX && task_fd_get(fd, &ty, &handle) == 0 &&
                ty == TASK_FD_FILE) {
                char kb[512];
                int heap_used = 0;
                void* kbuf = sys_buf_alloc((uint32_t)ulen, kb, sizeof(kb), &heap_used);
                if (!kbuf) return -1;
                int n = vfs_fread(fd, kbuf, ulen);
                if (n > 0 && user_copy_out(ubuf, kbuf, (uint32_t)n, caller_cs, usermax) != 0) {
                    if (heap_used) free(kbuf);
                    return -1;
                }
                if (heap_used) free(kbuf);
                return n;
            }
            if (fd >= 0 && fd < TASK_FD_MAX && task_fd_get(fd, &ty, &handle) == 0 &&
                ty == TASK_FD_PIPE_R) {
                char kb[512];
                uint32_t n = ulen < sizeof(kb) ? (uint32_t)ulen : (uint32_t)sizeof(kb);
                int r = pipe_read(handle, kb, n);
                if (r > 0 && user_copy_out(ubuf, kb, (uint32_t)r, caller_cs, usermax) != 0)
                    return -1;
                return r;
            }
            /* Не занятое файлом fd 0-2 — консоль (stdin: клавиатура). */
            if (fd >= 0 && fd <= 2) {
                char kb[128];
                uint32_t n = ulen < sizeof(kb) ? (uint32_t)ulen : (uint32_t)sizeof(kb);
                uint32_t i = 0;
                for (; i < n; i++) {
                    char c = keyboard_getchar();
                    if (c == 0) break;
                    kb[i] = c;
                }
                if (i && user_copy_out(ubuf, kb, i, caller_cs, usermax) != 0) return -1;
                return (int)i;
            }
            return driver_read(args->arg1, ubuf, ulen, args->arg4);
        }

        case SYS_WRITE: {
            int fd = (int)args->arg1;
            const void* ubuf = (const void*)args->arg2;
            size_t ulen = (size_t)args->arg3;
            if (ulen > SYS_BUF_CAP) return -1;
            char kb[512];
            int heap_used = 0;
            void* kbuf = sys_buf_alloc((uint32_t)ulen, kb, sizeof(kb), &heap_used);
            if (!kbuf) return -1;
            if (user_copy_in(kbuf, ubuf, (uint32_t)ulen, caller_cs, usermax) != 0) {
                if (heap_used) free(kbuf);
                return -1;
            }
            int res;
            uint8_t ty = 0;
            int handle = -1;
            if (fd >= 0 && fd < TASK_FD_MAX && task_fd_get(fd, &ty, &handle) == 0 &&
                ty == TASK_FD_FILE) {
                res = vfs_fwrite(fd, kbuf, ulen);
            } else if (fd >= 0 && fd < TASK_FD_MAX && ty == TASK_FD_PIPE_W) {
                res = pipe_write(handle, kbuf, ulen);
            } else if (fd >= 0 && fd <= 2) {
                res = console_write((const char*)kbuf, (uint32_t)ulen);
            } else {
                res = driver_write(args->arg1, kbuf, ulen, args->arg4);
            }
            if (heap_used) free(kbuf);
            return res;
        }

        case SYS_OPEN: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            int flags = (int)args->arg2;
            if (!flags) flags = O_RDWR;
            uint16_t mode = (uint16_t)args->arg3;
            if (!mode) mode = FS_MODE_FILE;
            return vfs_open(path, flags, mode);
        }

        case SYS_CLOSE: {
            uint8_t cty = 0;
            int chandle = -1;
            if (task_fd_get((int)args->arg1, &cty, &chandle) == 0 &&
                (cty == TASK_FD_PIPE_R || cty == TASK_FD_PIPE_W)) {
                pipe_close(chandle, cty == TASK_FD_PIPE_W);
                task_fd_close((int)args->arg1);
                return 0;
            }
            return vfs_close((int)args->arg1);
        }

        case SYS_LSEEK:
            return vfs_lseek((int)args->arg1, (int32_t)args->arg2, (int)args->arg3);

        case SYS_STAT: {
            struct fs_stat st;
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            if (fs_stat(path, &st) != 0) return -1;
            if (args->arg2) {
                if (user_copy_out((void*)args->arg2, &st, sizeof(st), caller_cs, usermax) != 0)
                    return -1;
            }
            return 0;
        }

        case SYS_FSTAT: {
            struct fs_stat st;
            int r = vfs_fstat((int)args->arg1, &st);
            if (r != 0) return r;
            if (args->arg2) {
                if (user_copy_out((void*)args->arg2, &st, sizeof(st), caller_cs, usermax) != 0)
                    return -1;
            }
            return 0;
        }

        case SYS_DUP:
            return vfs_dup((int)args->arg1);
        case SYS_FSYNC:
            return vfs_fsync((int)args->arg1);
        case SYS_LINK: {
            char a[256], b[256];
            if (user_str_copy(a, sizeof(a), (const char*)args->arg1, caller_cs, usermax) != 0) return -1;
            if (user_str_copy(b, sizeof(b), (const char*)args->arg2, caller_cs, usermax) != 0) return -1;
            return fs_link(a, b);
        }
        case SYS_UNLINK: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            return vfs_unlink(path);
        }
        case SYS_CHMOD: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            return fs_chmod(path, (uint16_t)args->arg2);
        }
        case SYS_CHOWN: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            return fs_chown(path, (uint16_t)args->arg2, (uint16_t)args->arg3);
        }
        case SYS_SYNC:
            return fs_sync();
        case SYS_OPENAT: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg2, caller_cs, usermax) != 0)
                return -1;
            return vfs_openat((int)args->arg1, path, (int)args->arg3, (uint16_t)args->arg4);
        }
        case SYS_GETDENTS: {
            char kbuf[256];
            size_t ulen = (size_t)args->arg3;
            if (ulen > sizeof(kbuf)) ulen = sizeof(kbuf);
            int n = vfs_getdents((int)args->arg1, kbuf, ulen);
            if (n > 0) {
                if (user_copy_out((char*)args->arg2, kbuf, (uint32_t)n, caller_cs, usermax) != 0)
                    return -1;
            }
            return n;
        }
        case SYS_MMAP_RO: {
            /* Simplified read-only file map: load into kernel buffer, return pointer */
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            uint32_t* out_addr = (uint32_t*)args->arg2;
            uint32_t* out_size = (uint32_t*)args->arg3;
            uint32_t sz = 0;
            if (fs_open(path, &sz) != 0 || sz == 0 || sz > 65536) return -1;
            void* mem = malloc(sz);
            if (!mem) return -1;
            if (fs_read(path, mem, sz) < 0) {
                free(mem);
                return -1;
            }
            if (args->arg2) {
                if (user_copy_out(out_addr, &mem, sizeof(uint32_t), caller_cs, usermax) != 0) {
                    free(mem); return -1;
                }
            }
            if (args->arg3) {
                if (user_copy_out(out_size, &sz, sizeof(uint32_t), caller_cs, usermax) != 0) {
                    free(mem); return -1;
                }
            }
            return 0;
        }

        case SYS_IOCTL:
            return driver_ioctl(args->arg1, args->arg2, (void*)args->arg3);

        case SYS_DEVICE_LIST: {
            struct driver tmp[16];
            int max = (int)args->arg3;
            if (max <= 0) return 0;
            if (max > 16) max = 16;
            int n = driver_list_by_type((enum driver_type)args->arg1, tmp, max);
            if (n > 0) {
                if (user_copy_out((void*)args->arg2, tmp, (uint32_t)n * sizeof(struct driver),
                                 caller_cs, usermax) != 0)
                    return -1;
            }
            return n;
        }

        case SYS_DEVICE_INFO: {
            struct driver* drv = driver_find_by_id(args->arg1);
            struct driver* info = (struct driver*)args->arg2;
            if (drv && info) {
                if (user_copy_out(info, drv, sizeof(struct driver), caller_cs, usermax) != 0)
                    return -1;
                return 0;
            }
            return -1;
        }

        case SYS_SOCKET: {
            int s = socket_create((int)args->arg1, (int)args->arg2, (int)args->arg3);
            if (s >= 0) task_fd_alloc(TASK_FD_SOCK, s, 0);
            return s;
        }
        case SYS_BIND: {
            struct sockaddr_in addr;
            if (user_copy_in(&addr, (const void*)args->arg2, sizeof(addr), caller_cs, usermax) != 0)
                return -1;
            return socket_bind((int)args->arg1, &addr);
        }
        case SYS_LISTEN:
            return socket_listen((int)args->arg1, (int)args->arg2);
        case SYS_ACCEPT:
            return socket_accept((int)args->arg1, (int)args->arg2);
        case SYS_CONNECT: {
            struct sockaddr_in addr;
            if (user_copy_in(&addr, (const void*)args->arg2, sizeof(addr), caller_cs, usermax) != 0)
                return -1;
            return socket_connect((int)args->arg1, &addr, (int)args->arg3);
        }
        case SYS_SEND: {
            size_t ulen = (size_t)args->arg3;
            if (ulen > SYS_BUF_CAP) return -1;
            char kb[512];
            int heap_used = 0;
            void* kbuf = sys_buf_alloc((uint32_t)ulen, kb, sizeof(kb), &heap_used);
            if (!kbuf) return -1;
            if (user_copy_in(kbuf, (const void*)args->arg2, (uint32_t)ulen, caller_cs, usermax) != 0) {
                if (heap_used) free(kbuf);
                return -1;
            }
            int res = socket_send((int)args->arg1, kbuf, ulen);
            if (heap_used) free(kbuf);
            return res;
        }
        case SYS_RECV: {
            size_t ulen = (size_t)args->arg3;
            if (ulen > SYS_BUF_CAP) return -1;
            char kb[512];
            int heap_used = 0;
            void* kbuf = sys_buf_alloc((uint32_t)ulen, kb, sizeof(kb), &heap_used);
            if (!kbuf) return -1;
            int res = socket_recv((int)args->arg1, kbuf, ulen, (int)args->arg4);
            if (res > 0 && user_copy_out((void*)args->arg2, kbuf, (uint32_t)res, caller_cs, usermax) != 0) {
                if (heap_used) free(kbuf);
                return -1;
            }
            if (heap_used) free(kbuf);
            return res;
        }
        case SYS_SOCK_CLOSE:
            return socket_close((int)args->arg1);
        case SYS_GETUID:
            return task_getuid();
        case SYS_SETUID:
            return task_setuid((uint16_t)args->arg1);
        case SYS_GETGID:
            return task_getgid();
        case SYS_SETGID:
            return task_setgid((uint16_t)args->arg1);
        case SYS_GETPID:
            return sched_current_id();
        case SYS_GETPPID: {
            struct task* cur = sched_current();
            return cur ? cur->parent_pid : -1;
        }
        case SYS_DUP2:
            return vfs_dup2((int)args->arg1, (int)args->arg2);
        case SYS_PIPE: {
            int idx = pipe_create();
            if (idx < 0) return -1;
            int rfd = task_fd_alloc(TASK_FD_PIPE_R, idx, 0);
            int wfd = task_fd_alloc(TASK_FD_PIPE_W, idx, 0);
            if (rfd < 0 || wfd < 0) return -1;
            int fds[2];
            fds[0] = rfd;
            fds[1] = wfd;
            if (user_copy_out((void*)args->arg1, fds, sizeof(fds), caller_cs, usermax) != 0)
                return -1;
            return 0;
        }
        case SYS_GETCWD: {
            const char* cwd = task_getcwd();
            size_t cap = (size_t)args->arg2;
            if (!cap) return -1;
            uint32_t n = 0;
            while (cwd[n] && n + 1 < cap) n++;
            if (user_copy_out((void*)args->arg1, cwd, n + 1, caller_cs, usermax) != 0)
                return -1;
            return (int)(n + 1);
        }
        case SYS_CHDIR: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            return task_chdir(path);
        }
        case SYS_SLEEP:
            task_sleep_ms((uint32_t)args->arg1);
            return 0;
        case SYS_EXEC: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            /* Успешный exec не возвращается — продолжение в ring3 с новым образом. */
            return task_exec_user(path);
        }
        case SYS_EXECVE: {
            char path[256];
            if (user_str_copy(path, sizeof(path), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            const char* kargv[16];
            static char abuf[16][128];
            int argc = 0;
            uint32_t uargv = args->arg2;
            if (uargv) {
                for (; argc < 16; argc++) {
                    uint32_t uptr = 0;
                    if (user_copy_in(&uptr, (const void*)(uargv + (uint32_t)argc * 4), 4, caller_cs, usermax) != 0) break;
                    if (uptr == 0) break;
                    if (user_str_copy(abuf[argc], sizeof(abuf[argc]), (const char*)uptr, caller_cs, usermax) != 0) break;
                    kargv[argc] = abuf[argc];
                }
            }
            return task_exec_user_argv(path, argc, kargv);
        }
        case SYS_FORK:
            return task_fork_user();
        case SYS_WAIT: {
            int status = 0;
            int r = task_wait_child((int)args->arg1, &status);
            if (r < 0) return r;
            if (args->arg2 &&
                user_copy_out((void*)args->arg2, &status, sizeof(status), caller_cs, usermax) != 0)
                return -1;
            return r;
        }
        case SYS_EXIT:
            task_exit();
            return 0;
        case SYS_YIELD:
            sched_yield();
            return 0;
        case SYS_RING3_DONE:
            paging_ring3_finish();
            return 0;
        default:
            return -1;
    }
}

void syscall_init() {}
