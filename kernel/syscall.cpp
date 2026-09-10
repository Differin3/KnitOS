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
#include "pty.h"
#include "crypto/sha256.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/x25519.h"
#include "crypto/ed25519.h"
#include "crypto/rng.h"
#include "kcmd.h"
#include <string.h>
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
            if (fd >= 0 && fd < TASK_FD_MAX && task_fd_get(fd, &ty, &handle) == 0 &&
                ty == TASK_FD_PTY_S) {
                char kb[512];
                uint32_t n = ulen < sizeof(kb) ? (uint32_t)ulen : (uint32_t)sizeof(kb);
                int r = pty_slave_read(handle, kb, n);
                if (r > 0 && user_copy_out(ubuf, kb, (uint32_t)r, caller_cs, usermax) != 0)
                    return -1;
                return r;
            }
            if (fd >= 0 && fd < TASK_FD_MAX && task_fd_get(fd, &ty, &handle) == 0 &&
                ty == TASK_FD_PTY_M) {
                char kb[512];
                uint32_t n = ulen < sizeof(kb) ? (uint32_t)ulen : (uint32_t)sizeof(kb);
                int r = pty_master_read(handle, kb, n);
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
            } else if (fd >= 0 && fd < TASK_FD_MAX && ty == TASK_FD_PTY_S) {
                res = pty_slave_write(handle, kbuf, ulen);
            } else if (fd >= 0 && fd < TASK_FD_MAX && ty == TASK_FD_PTY_M) {
                res = pty_master_write(handle, kbuf, ulen);
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
                (cty == TASK_FD_PIPE_R || cty == TASK_FD_PIPE_W ||
                 cty == TASK_FD_PTY_M || cty == TASK_FD_PTY_S)) {
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
        case SYS_KILL:
            return task_kill((int)args->arg1);
        case SYS_GETPPID: {
            struct task* cur = sched_current();
            return cur ? cur->parent_pid : -1;
        }
        case SYS_DUP2: {
            int r = task_fd_dup2((int)args->arg1, (int)args->arg2);
            if (r >= 0) return r;
            return vfs_dup2((int)args->arg1, (int)args->arg2);
        }
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
        case SYS_PTY_OPEN: {
            int idx = pty_create();
            if (idx < 0) return -1;
            int mfd = task_fd_alloc(TASK_FD_PTY_M, idx, 0);
            int sfd = task_fd_alloc(TASK_FD_PTY_S, idx, 0);
            if (mfd < 0 || sfd < 0) return -1;
            pty_ref(idx, 1);
            pty_ref(idx, 0);
            int fds[2];
            fds[0] = mfd;
            fds[1] = sfd;
            if (user_copy_out((void*)args->arg1, fds, sizeof(fds), caller_cs, usermax) != 0)
                return -1;
            return 0;
        }
        case SYS_ISATTY: {
            int fd = (int)args->arg1;
            uint8_t ty = 0;
            int h = -1;
            if (fd >= 0 && fd < TASK_FD_MAX && task_fd_get(fd, &ty, &h) == 0) {
                return (ty == TASK_FD_PTY_M || ty == TASK_FD_PTY_S) ? 1 : 0;
            }
            if (fd >= 0 && fd <= 2) return 1; /* неявная консоль */
            return 0;
        }
        case SYS_CRYPTO: {
            struct kcrypto_req req;
            if (user_copy_in(&req, (const void*)args->arg1, sizeof(req), caller_cs, usermax) != 0)
                return -1;
            static uint8_t in1[2048];
            static uint8_t in2[2048];
            static uint8_t in3[4096];
            static uint8_t in4[4096];
            static uint8_t outb[4096];
            switch (req.op) {
            case KC_SHA256: {
                if (req.in1_len > sizeof(in1)) return -1;
                if (req.in1_len && user_copy_in(in1, (const void*)req.in1, req.in1_len, caller_cs, usermax) != 0) return -1;
                if (req.out_cap < 32) return -1;
                sha256(in1, req.in1_len, outb);
                if (user_copy_out((void*)req.out, outb, 32, caller_cs, usermax) != 0) return -1;
                return 32;
            }
            case KC_HMAC_SHA256: {
                if (req.in1_len > sizeof(in1) || req.in2_len > sizeof(in2)) return -1;
                if (req.in1_len && user_copy_in(in1, (const void*)req.in1, req.in1_len, caller_cs, usermax) != 0) return -1;
                if (req.in2_len && user_copy_in(in2, (const void*)req.in2, req.in2_len, caller_cs, usermax) != 0) return -1;
                if (req.out_cap < 32) return -1;
                hmac_sha256(in1, req.in1_len, in2, req.in2_len, outb);
                if (user_copy_out((void*)req.out, outb, 32, caller_cs, usermax) != 0) return -1;
                return 32;
            }
            case KC_X25519: {
                if (req.in1_len != 32 || req.in2_len != 32 || req.out_cap < 32) return -1;
                if (user_copy_in(in1, (const void*)req.in1, 32, caller_cs, usermax) != 0) return -1;
                if (user_copy_in(in2, (const void*)req.in2, 32, caller_cs, usermax) != 0) return -1;
                x25519(outb, in1, in2);
                if (user_copy_out((void*)req.out, outb, 32, caller_cs, usermax) != 0) return -1;
                return 32;
            }
            case KC_RANDOM: {
                uint32_t n = req.out_cap < sizeof(outb) ? req.out_cap : (uint32_t)sizeof(outb);
                rng_bytes(outb, n);
                if (n && user_copy_out((void*)req.out, outb, n, caller_cs, usermax) != 0) return -1;
                return (int)n;
            }
            case KC_ED25519_KEYGEN: {
                if (req.in1_len != 32 || req.out_cap < 32) return -1;
                if (user_copy_in(in1, (const void*)req.in1, 32, caller_cs, usermax) != 0) return -1;
                uint8_t sk[64];
                ed25519_keypair_from_seed(outb, sk, in1);
                if (user_copy_out((void*)req.out, outb, 32, caller_cs, usermax) != 0) return -1;
                return 32;
            }
            case KC_ED25519_SIGN: {
                if (req.in1_len != 64 || req.in2_len > sizeof(in2) || req.out_cap < 64) return -1;
                if (user_copy_in(in1, (const void*)req.in1, 64, caller_cs, usermax) != 0) return -1;
                if (req.in2_len && user_copy_in(in2, (const void*)req.in2, req.in2_len, caller_cs, usermax) != 0) return -1;
                ed25519_sign(outb, in2, req.in2_len, in1);
                if (user_copy_out((void*)req.out, outb, 64, caller_cs, usermax) != 0) return -1;
                return 64;
            }
            case KC_CHACHA20: {
                /* in1=key(32), in2=nonce(12), in3=data, in4_len=counter */
                if (req.in1_len != 32 || req.in2_len != 12) return -1;
                if (req.in3_len > sizeof(in3)) return -1;
                if (user_copy_in(in1, (const void*)req.in1, 32, caller_cs, usermax) != 0) return -1;
                if (user_copy_in(in2, (const void*)req.in2, 12, caller_cs, usermax) != 0) return -1;
                if (req.in3_len && user_copy_in(in3, (const void*)req.in3, req.in3_len, caller_cs, usermax) != 0) return -1;
                chacha20_xor(outb, in3, req.in3_len, in1, in2, req.in4_len);
                if (req.in3_len && user_copy_out((void*)req.out, outb, req.in3_len, caller_cs, usermax) != 0) return -1;
                return (int)req.in3_len;
            }
            case KC_POLY1305: {
                if (req.in1_len != 32 || req.in2_len > sizeof(in2)) return -1;
                if (user_copy_in(in1, (const void*)req.in1, 32, caller_cs, usermax) != 0) return -1;
                if (req.in2_len && user_copy_in(in2, (const void*)req.in2, req.in2_len, caller_cs, usermax) != 0) return -1;
                if (req.out_cap < 16) return -1;
                poly1305(outb, in2, req.in2_len, in1);
                if (user_copy_out((void*)req.out, outb, 16, caller_cs, usermax) != 0) return -1;
                return 16;
            }
            case KC_AEAD_ENC:
            case KC_AEAD_DEC: {
                if (req.in1_len != 32 || req.in2_len != 12) return -1;
                if (user_copy_in(in1, (const void*)req.in1, 32, caller_cs, usermax) != 0) return -1;
                if (user_copy_in(in2, (const void*)req.in2, 12, caller_cs, usermax) != 0) return -1;
                if (req.in3_len > sizeof(in3)) return -1;
                if (req.in3_len && user_copy_in(in3, (const void*)req.in3, req.in3_len, caller_cs, usermax) != 0) return -1;
                if (req.in4_len > sizeof(in4)) return -1;
                if (req.in4_len && user_copy_in(in4, (const void*)req.in4, req.in4_len, caller_cs, usermax) != 0) return -1;
                if (req.op == KC_AEAD_ENC) {
                    if (req.out_cap < req.in4_len + 16) return -1;
                    chacha20poly1305_encrypt(outb, in4, req.in4_len, in3, req.in3_len, in2, in1);
                    if (user_copy_out((void*)req.out, outb, req.in4_len + 16, caller_cs, usermax) != 0) return -1;
                    return (int)(req.in4_len + 16);
                } else {
                    if (req.in4_len < 16) return -1;
                    size_t plen = req.in4_len - 16;
                    if (!chacha20poly1305_decrypt(outb, in4, plen, in3, req.in3_len, in2, in1))
                        return -2;
                    if (plen && user_copy_out((void*)req.out, outb, plen, caller_cs, usermax) != 0) return -1;
                    return (int)plen;
                }
            }
            default:
                return -1;
            }
        }
        case SYS_KCMD: {
            char kcmd[128];
            if (user_str_copy(kcmd, sizeof(kcmd), (const char*)args->arg1, caller_cs, usermax) != 0)
                return -1;
            static char kout[2048];
            int n = kernel_run_command(kcmd, kout, sizeof(kout));
            if (n <= 0) return n;
            size_t ulen = (size_t)args->arg3;
            if (ulen > (size_t)n) ulen = (size_t)n;
            if (user_copy_out((void*)args->arg2, kout, (uint32_t)ulen, caller_cs, usermax) != 0)
                return -1;
            return (int)ulen;
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
