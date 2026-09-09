#include "syscall.h"

static const char m_start[] = "user demo2 start\n";
static const char m_done[] = "user demo2 done\n";
static const char* payload = "hello from ring3\n";

static void w(const char* s) {
    unsigned long n = 0;
    while (s[n]) n++;
    sys_write(1, s, n);
}

static void wnum(long v) {
    char t[16];
    int i = 0;
    if (v == 0) {
        t[i++] = '0';
    } else {
        if (v < 0) {
            sys_write(1, "-", 1);
            v = -v;
        }
        while (v > 0 && i < 14) {
            t[i++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    while (i > 0) sys_write(1, &t[--i], 1);
}

static void wr(long fd, const char* s) {
    unsigned long n = 0;
    while (s[n]) n++;
    sys_write(fd, s, n);
}

static void wr_num(long fd, long v) {
    char t[16];
    int i = 0;
    if (v == 0) {
        t[i++] = '0';
    } else {
        if (v < 0) v = -v;
        while (v > 0 && i < 14) {
            t[i++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    while (i > 0) {
        char c = t[--i];
        sys_write(fd, &c, 1);
    }
}

void _start(void) {
    w(m_start);

    long fd = sys_open("/tmp/udemo.txt", O_CREAT | O_RDWR, 0644);
    if (fd >= 0) {
        wr(fd, payload);
        long uid = sys_getuid();
        wr(fd, "uid=");
        wr_num(fd, uid);
        wr(fd, "\n");
        /* Не-root не может сменить себе uid; попытка вернуть 0 обязана провалиться. */
        long rc = sys_setuid(0);
        wr(fd, "setuid0=");
        if (rc < 0) wr(fd, "denied");
        else wr(fd, "ALLOWED");
        wr(fd, "\n");
        long uid2 = sys_getuid();
        wr(fd, "uid2=");
        wr_num(fd, uid2);
        wr(fd, "\n");
        sys_close(fd);
    } else {
        w("open(w) fail\n");
        syscall4(SYS_EXIT, 0, 0, 0);
        for (;;) __asm__ volatile("hlt");
    }

    char rbuf[64];
    long rn = 0;
    fd = sys_open("/tmp/udemo.txt", O_RDONLY, 0);
    if (fd >= 0) {
        rn = sys_read(fd, rbuf, sizeof(rbuf) - 1);
        if (rn > 0) rbuf[rn] = 0;
        sys_close(fd);
    }
    w("readback:\n");
    if (rn > 0) sys_write(1, rbuf, (unsigned long)rn);
    else w("(err)\n");

    sys_chdir("/tmp");
    char cwd[128];
    long cn = sys_getcwd(cwd, sizeof(cwd));
    w("cwd: ");
    if (cn > 0) sys_write(1, cwd, (unsigned long)cn);
    w("\n");

    sys_sleep(200);
    w(m_done);
    syscall4(SYS_EXIT, 0, 0, 0);
    for (;;) __asm__ volatile("hlt");
}