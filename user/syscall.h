#ifndef USER_SYSCALL_H
#define USER_SYSCALL_H

typedef unsigned int uint32_t;
typedef unsigned long size_t;

#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_OPEN        2
#define SYS_CLOSE       3
#define SYS_EXIT        15
#define SYS_YIELD       16

#define SYS_GETUID      30
#define SYS_SETUID      31
#define SYS_GETCWD      33
#define SYS_CHDIR       34
#define SYS_SLEEP       35

#define O_RDONLY  0x0001
#define O_WRONLY  0x0002
#define O_RDWR    0x0003
#define O_CREAT   0x0100
#define O_TRUNC   0x0200

static inline long syscall5(uint32_t num, uint32_t a, uint32_t b,
                            uint32_t c, uint32_t d) {
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(num), "b"(a), "c"(b), "d"(c), "S"(d)
                     : "memory", "cc");
    return ret;
}

static inline long syscall4(uint32_t num, uint32_t a, uint32_t b, uint32_t c) {
    return syscall5(num, a, b, c, 0);
}
static inline long syscall2(uint32_t num, uint32_t a) {
    return syscall5(num, a, 0, 0, 0);
}
static inline long syscall1(uint32_t num) {
    return syscall5(num, 0, 0, 0, 0);
}

static inline long sys_write(long fd, const void* buf, unsigned long n) {
    return syscall4(SYS_WRITE, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n);
}
static inline long sys_read(long fd, void* buf, unsigned long n) {
    return syscall4(SYS_READ, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n);
}
static inline long sys_open(const char* path, int flags, unsigned int mode) {
    return syscall5(SYS_OPEN, (uint32_t)(unsigned long)path, (uint32_t)flags, (uint32_t)mode, 0);
}
static inline long sys_close(long fd) {
    return syscall2(SYS_CLOSE, (uint32_t)fd);
}
static inline long sys_getuid(void) {
    return syscall1(SYS_GETUID);
}
static inline long sys_setuid(unsigned int uid) {
    return syscall2(SYS_SETUID, uid);
}
static inline long sys_sleep(unsigned long ms) {
    return syscall2(SYS_SLEEP, (uint32_t)ms);
}
static inline long sys_getcwd(char* buf, unsigned long cap) {
    return syscall4(SYS_GETCWD, (uint32_t)(unsigned long)buf, (uint32_t)cap, 0);
}
static inline long sys_chdir(const char* path) {
    return syscall2(SYS_CHDIR, (uint32_t)(unsigned long)path);
}

#endif