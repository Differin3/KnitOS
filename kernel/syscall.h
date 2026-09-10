#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <stddef.h>

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
#define SYS_KCMD        50

/* Крипто-операции (SYS_CRYPTO). */
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

struct syscall_args {
    uint32_t arg0;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;
};

extern "C" int syscall_handler(struct syscall_args* args, uint32_t caller_cs);
void syscall_init();

#endif
