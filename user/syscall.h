#ifndef USER_SYSCALL_H
#define USER_SYSCALL_H

typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef long ssize_t;

/* ---- syscall numbers (должны совпадать с kernel/syscall.h) ---- */
#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_OPEN        2
#define SYS_CLOSE       3
#define SYS_IOCTL       4
#define SYS_DEVICE_LIST 5
#define SYS_DEVICE_INFO 6

#define SYS_SOCKET      7
#define SYS_BIND        8
#define SYS_LISTEN      9
#define SYS_ACCEPT      10
#define SYS_CONNECT     11
#define SYS_SEND        12
#define SYS_RECV        13
#define SYS_SOCK_CLOSE  14
#define SYS_EXIT        15
#define SYS_YIELD       16
#define SYS_RING3_DONE  17
#define SYS_LSEEK       18
#define SYS_STAT        19
#define SYS_FSTAT       20
#define SYS_DUP         21
#define SYS_FSYNC       22
#define SYS_LINK        23
#define SYS_UNLINK      24
#define SYS_CHMOD       25
#define SYS_SYNC        26
#define SYS_OPENAT      27
#define SYS_GETDENTS    28
#define SYS_MMAP_RO     29

#define SYS_GETUID      30
#define SYS_SETUID      31
#define SYS_CHOWN       32
#define SYS_GETCWD      33
#define SYS_CHDIR       34
#define SYS_SLEEP       35
#define SYS_EXEC        36

/* Расширения для user-space приложений */
#define SYS_FORK        37
#define SYS_WAIT        38
#define SYS_PIPE        39
#define SYS_DUP2        40
#define SYS_GETPID      41
#define SYS_KILL        42
#define SYS_EXECVE      43
#define SYS_GETGID      44
#define SYS_SETGID      45
#define SYS_GETPPID     46

#define SYS_PTY_OPEN    47
#define SYS_ISATTY      48
#define SYS_CRYPTO      49

struct kcrypto_req {
    uint32_t op;
    uint32_t in1; uint32_t in1_len;
    uint32_t in2; uint32_t in2_len;
    uint32_t in3; uint32_t in3_len;
    uint32_t in4; uint32_t in4_len;
    uint32_t out; uint32_t out_cap;
    int      result;
};
#define KC_SHA256       1
#define KC_HMAC_SHA256  2
#define KC_AEAD_ENC     3
#define KC_AEAD_DEC     4
#define KC_X25519       5
#define KC_RANDOM       6
#define KC_ED25519_KEYGEN 7
#define KC_ED25519_SIGN   8
#define KC_CHACHA20       9
#define KC_POLY1305       10

/* ---- flags ---- */
#define O_RDONLY  0x0001
#define O_WRONLY  0x0002
#define O_RDWR    0x0003
#define O_CREAT   0x0100
#define O_TRUNC   0x0200
#define O_APPEND  0x0400
#define O_EXCL    0x0800
#define O_DIRECTORY 0x1000

#define AF_INET   2
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;   /* network byte order */
    uint32_t       sin_addr;   /* network byte order */
};

struct stat {
    uint32_t size;
    uint32_t mode;
    uint32_t mtime;
    uint32_t atime;
    uint32_t ctime;
    uint32_t nlink;
    unsigned short uid;
    unsigned short gid;
    unsigned char flags;
    uint32_t start_sector;
    uint32_t sector_count;
};

/* ---- raw syscall ---- */
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
static inline long syscall3(uint32_t num, uint32_t a, uint32_t b) {
    return syscall5(num, a, b, 0, 0);
}
static inline long syscall2(uint32_t num, uint32_t a) {
    return syscall5(num, a, 0, 0, 0);
}
static inline long syscall1(uint32_t num) {
    return syscall5(num, 0, 0, 0, 0);
}

/* ---- файлы ---- */
static inline long sys_read(long fd, void* buf, unsigned long n) {
    return syscall4(SYS_READ, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n);
}
static inline long sys_write(long fd, const void* buf, unsigned long n) {
    return syscall4(SYS_WRITE, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n);
}
static inline long sys_open(const char* path, int flags, unsigned int mode) {
    return syscall5(SYS_OPEN, (uint32_t)(unsigned long)path, (uint32_t)flags, (uint32_t)mode, 0);
}
static inline long sys_close(long fd) {
    return syscall2(SYS_CLOSE, (uint32_t)fd);
}
static inline long sys_lseek(long fd, long off, int whence) {
    return syscall5(SYS_LSEEK, (uint32_t)fd, (uint32_t)off, (uint32_t)whence, 0);
}
static inline long sys_getdents(long fd, void* buf, unsigned long n) {
    return syscall4(SYS_GETDENTS, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n);
}
static inline long sys_stat(const char* path, struct stat* st) {
    return syscall3(SYS_STAT, (uint32_t)(unsigned long)path, (uint32_t)(unsigned long)st);
}
static inline long sys_fstat(long fd, struct stat* st) {
    return syscall3(SYS_FSTAT, (uint32_t)fd, (uint32_t)(unsigned long)st);
}
static inline long sys_dup(long fd) { return syscall2(SYS_DUP, (uint32_t)fd); }
static inline long sys_dup2(long oldfd, long newfd) {
    return syscall3(SYS_DUP2, (uint32_t)oldfd, (uint32_t)newfd);
}
static inline long sys_unlink(const char* path) {
    return syscall2(SYS_UNLINK, (uint32_t)(unsigned long)path);
}
static inline long sys_fsync(long fd) { return syscall2(SYS_FSYNC, (uint32_t)fd); }

/* ---- процессы ---- */
static inline void sys_exit(int code) { syscall2(SYS_EXIT, (uint32_t)code); }
static inline long sys_yield(void) { return syscall1(SYS_YIELD); }
static inline long sys_fork(void) { return syscall1(SYS_FORK); }
static inline long sys_waitpid(int pid, int* status) {
    return syscall3(SYS_WAIT, (uint32_t)pid, (uint32_t)(unsigned long)status);
}
static inline long sys_wait(int* status) {
    return sys_waitpid(-1, status);
}
static inline long sys_pipe(int fds[2]) {
    return syscall2(SYS_PIPE, (uint32_t)(unsigned long)fds);
}
static inline long sys_pty_open(int fds[2]) {
    return syscall2(SYS_PTY_OPEN, (uint32_t)(unsigned long)fds);
}
static inline long sys_isatty(long fd) {
    return syscall2(SYS_ISATTY, (uint32_t)fd);
}
static inline long sys_getpid(void) { return syscall1(SYS_GETPID); }
static inline long sys_getppid(void) { return syscall1(SYS_GETPPID); }
static inline long sys_kill(long pid, int sig) {
    return syscall3(SYS_KILL, (uint32_t)pid, (uint32_t)sig);
}
static inline long sys_execve(const char* path, char* const argv[], char* const envp[]) {
    return syscall5(SYS_EXECVE, (uint32_t)(unsigned long)path,
                    (uint32_t)(unsigned long)argv, (uint32_t)(unsigned long)envp, 0);
}
/* Старый exec по пути (без argv). */
static inline long sys_exec(const char* path) {
    return syscall2(SYS_EXEC, (uint32_t)(unsigned long)path);
}
static inline long sys_getuid(void) { return syscall1(SYS_GETUID); }
static inline long sys_setuid(unsigned int uid) { return syscall2(SYS_SETUID, uid); }
static inline long sys_getgid(void) { return syscall1(SYS_GETGID); }
static inline long sys_setgid(unsigned int gid) { return syscall2(SYS_SETGID, gid); }
static inline long sys_getcwd(char* buf, unsigned long cap) {
    return syscall4(SYS_GETCWD, (uint32_t)(unsigned long)buf, (uint32_t)cap, 0);
}
static inline long sys_chdir(const char* path) {
    return syscall2(SYS_CHDIR, (uint32_t)(unsigned long)path);
}
static inline long sys_sleep(unsigned long ms) {
    return syscall2(SYS_SLEEP, (uint32_t)ms);
}

/* ---- сокеты ---- */
static inline long sys_socket(int domain, int type, int protocol) {
    return syscall4(SYS_SOCKET, (uint32_t)domain, (uint32_t)type, (uint32_t)protocol);
}
static inline long sys_bind(long fd, const struct sockaddr_in* addr) {
    return syscall3(SYS_BIND, (uint32_t)fd, (uint32_t)(unsigned long)addr);
}
static inline long sys_listen(long fd, int backlog) {
    return syscall3(SYS_LISTEN, (uint32_t)fd, (uint32_t)backlog);
}
static inline long sys_accept(long fd, int timeout_ms) {
    return syscall3(SYS_ACCEPT, (uint32_t)fd, (uint32_t)timeout_ms);
}
static inline long sys_connect(long fd, const struct sockaddr_in* addr, int timeout_ms) {
    return syscall5(SYS_CONNECT, (uint32_t)fd, (uint32_t)(unsigned long)addr, (uint32_t)timeout_ms, 0);
}
static inline long sys_send(long fd, const void* buf, unsigned long n) {
    return syscall4(SYS_SEND, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n);
}
static inline long sys_recv(long fd, void* buf, unsigned long n, int timeout_ms) {
    return syscall5(SYS_RECV, (uint32_t)fd, (uint32_t)(unsigned long)buf, (uint32_t)n, (uint32_t)timeout_ms);
}
static inline long sys_sock_close(long fd) {
    return syscall2(SYS_SOCK_CLOSE, (uint32_t)fd);
}

#endif
