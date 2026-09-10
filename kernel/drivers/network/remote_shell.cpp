// Raw remote shell over TCP (telnet-like) — foundation for SSH.
// Runs as a kernel thread, authenticates against /etc/passwd + /etc/shadow,
// and executes a subset of shell commands over the socket.
#include "remote_shell.h"
#include "socket.h"
#include "protocols/ip.h"
#include "serial_log.h"
#include "fs.h"
#include "vfs.h"
#include "utils.h"
#include "user_auth.h"
#include "kernel.h"
#include "string.h"
#include "sched/task.h"
#include "drivers/video/terminal.h"
#include "drivers/timer/pit.h"
#include "drivers/power/rtc.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

static volatile int g_rsh_running = 0;
static volatile int g_rsh_ready = 0;
static volatile int g_rsh_sessions = 0;
static int g_rsh_pid = -1;
static uint16_t g_rsh_port = 0;
static int g_rsh_max = 1;
static int g_rsh_timeout = 1000;

/* ---- вывод ---- */

static void rsh_send(int fd, const char* s, size_t n) {
    if (s && n) socket_send(fd, s, n);
}
static void rsh_puts(int fd, const char* s) {
    if (!s) return;
    size_t n = 0;
    while (s[n]) n++;
    rsh_send(fd, s, n);
}
static void rsh_u32(int fd, uint32_t v) {
    char b[12]; int p = 0;
    if (v == 0) b[p++] = '0';
    else { char t[12]; int q = 0; while (v > 0 && q < 11) { t[q++] = (char)('0' + v % 10); v /= 10; } while (q > 0) b[p++] = t[--q]; }
    b[p] = 0;
    rsh_send(fd, b, (size_t)p);
}
/* '\n' -> "\r\n" для telnet-клиентов. */
static void rsh_text(int fd, const char* s) {
    while (s && *s) {
        if (*s == '\n') rsh_puts(fd, "\r\n");
        else { char c[2] = {*s, 0}; rsh_puts(fd, c); }
        s++;
    }
}

/* ---- ввод ---- */

static int rsh_readline(int fd, char* buf, size_t cap, int timeout_ms, bool echo) {
    static int skip_lf = 0;   /* CRLF-клиенты: пропустить LF сразу после CR */
    size_t len = 0;
    for (;;) {
        uint8_t ch = 0;
        int n = socket_recv(fd, &ch, 1, timeout_ms);
        if (n < 0) return -1;                 /* разрыв/ошибка */
        if (n == 0) { if (len == 0) return -2; continue; } /* таймаут */
        if (skip_lf && ch == '\n') { skip_lf = 0; continue; }
        skip_lf = 0;
        if (ch == 0xFF) {                     /* telnet IAC: пропустить 2 байта */
            uint8_t skip[2];
            socket_recv(fd, skip, 2, timeout_ms);
            continue;
        }
        if (ch == '\r') { skip_lf = 1; if (echo) rsh_puts(fd, "\r\n"); break; }
        if (ch == '\n') { if (echo) rsh_puts(fd, "\r\n"); break; }
        if (ch == 0x7F || ch == 0x08) {
            if (len > 0) { len--; if (echo) rsh_puts(fd, "\b \b"); }
            continue;
        }
        if (ch == 3) { rsh_puts(fd, "^C\r\n"); len = 0; continue; } /* Ctrl+C */
        if (ch < 32) continue;
        if (len + 1 < cap) {
            buf[len++] = (char)ch;
            if (echo) { char e[2] = {(char)ch, 0}; rsh_puts(fd, e); }
        }
    }
    buf[len] = 0;
    return (int)len;
}

/* ---- разбор аргументов ---- */

static int rsh_tokenize(char* line, char** argv, int max) {
    int argc = 0;
    char* p = line;
    while (*p && argc < max) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = 0; p++; }
    }
    return argc;
}

/* ---- команды ---- */

static void rsh_prompt(int fd, const char* user) {
    rsh_puts(fd, user);
    rsh_puts(fd, "@KnitOS:");
    rsh_puts(fd, utils_get_current_directory());
    rsh_puts(fd, "$ ");
}

static bool rsh_cmd(int fd, const char* user, char* line) {
    /* Копия исходной строки (tokenize мутирует line, нужна для 'write <f> <text>'). */
    char orig[256];
    size_t ol = 0;
    while (line[ol] && ol + 1 < sizeof(orig)) { orig[ol] = line[ol]; ol++; }
    orig[ol] = 0;

    char* argv[16];
    int argc = rsh_tokenize(line, argv, 16);
    if (argc == 0) return true;
    const char* c = argv[0];

    auto eq = [&](const char* s) { int i = 0; while (s[i] && c[i] == s[i]) i++; return s[i] == 0 && c[i] == 0; };

    if (eq("exit") || eq("quit") || eq("logout")) return false;
    if (eq("help")) {
        rsh_text(fd,
            "Commands: help echo pwd cd ls cat write mkdir rm whoami id uname date df exit\n");
    } else if (eq("echo")) {
        for (int i = 1; i < argc; i++) { if (i > 1) rsh_puts(fd, " "); rsh_puts(fd, argv[i]); }
        rsh_puts(fd, "\r\n");
    } else if (eq("pwd")) {
        rsh_puts(fd, utils_get_current_directory()); rsh_puts(fd, "\r\n");
    } else if (eq("cd")) {
        if (argc < 2) { rsh_puts(fd, "usage: cd <path>\r\n"); }
        else {
            char abs[128];
            if (utils_resolve_path(argv[1], abs, sizeof(abs)) == 0) {
                char probe[8];
                if (vfs_list(abs, probe, sizeof(probe)) >= 0) utils_set_current_directory(abs);
                else { rsh_puts(fd, "cd: no such directory\r\n"); }
            } else rsh_puts(fd, "cd: invalid path\r\n");
        }
    } else if (eq("ls")) {
        const char* path = argc >= 2 ? argv[1] : utils_get_current_directory();
        char abs[128];
        if (utils_resolve_path(path, abs, sizeof(abs)) != 0) { rsh_puts(fd, "ls: invalid path\r\n"); return true; }
        static char buf[2048];
        int r = vfs_list(abs, buf, sizeof(buf));
        if (r < 0) rsh_puts(fd, "ls: cannot access\r\n");
        else rsh_text(fd, buf);
    } else if (eq("cat")) {
        if (argc < 2) { rsh_puts(fd, "usage: cat <file>\r\n"); }
        else {
            char abs[128];
            if (utils_resolve_path(argv[1], abs, sizeof(abs)) != 0) { rsh_puts(fd, "cat: invalid path\r\n"); return true; }
            static char buf[2048];
            int r = vfs_read(abs, buf, sizeof(buf) - 1);
            if (r < 0) rsh_puts(fd, "cat: not found\r\n");
            else { buf[r] = 0; rsh_text(fd, buf); rsh_puts(fd, "\r\n"); }
        }
    } else if (eq("write")) {
        if (argc < 3) { rsh_puts(fd, "usage: write <file> <text>\r\n"); }
        else {
            char abs[128];
            if (utils_resolve_path(argv[1], abs, sizeof(abs)) != 0) { rsh_puts(fd, "write: invalid path\r\n"); return true; }
            /* текст = всё после имени файла в исходной строке */
            char* text = orig + (argv[2] - line);
            int r = vfs_write(abs, text, strlen(text));
            rsh_puts(fd, r == 0 ? "OK\r\n" : "write failed\r\n");
        }
    } else if (eq("mkdir")) {
        if (argc < 2) { rsh_puts(fd, "usage: mkdir <path>\r\n"); }
        else {
            char abs[128];
            if (utils_resolve_path(argv[1], abs, sizeof(abs)) != 0) { rsh_puts(fd, "mkdir: invalid path\r\n"); return true; }
            rsh_puts(fd, vfs_mkdir(abs) == 0 ? "OK\r\n" : "mkdir failed\r\n");
        }
    } else if (eq("rm")) {
        if (argc < 2) { rsh_puts(fd, "usage: rm <path>\r\n"); }
        else {
            char abs[128];
            if (utils_resolve_path(argv[1], abs, sizeof(abs)) != 0) { rsh_puts(fd, "rm: invalid path\r\n"); return true; }
            rsh_puts(fd, vfs_unlink(abs) == 0 ? "OK\r\n" : "rm failed\r\n");
        }
    } else if (eq("whoami")) {
        rsh_puts(fd, user); rsh_puts(fd, "\r\n");
    } else if (eq("id")) {
        rsh_puts(fd, "uid="); rsh_u32(fd, fs_current_uid());
        rsh_puts(fd, " gid="); rsh_u32(fd, fs_current_gid());
        rsh_puts(fd, "\r\n");
    } else if (eq("uname") || eq("version")) {
        rsh_puts(fd, KERNEL_NAME " " KERNEL_VERSION " (" KERNEL_BUILD ")\r\n");
    } else if (eq("date")) {
        char ts[24]; rtc_format_timestamp(ts, sizeof(ts));
        rsh_puts(fd, rtc_valid() ? ts : "no RTC"); rsh_puts(fd, "\r\n");
    } else if (eq("df")) {
        uint32_t t = 0, u = 0, f = 0;
        if (fs_get_disk_usage(&t, &u, &f) == 0) {
            rsh_puts(fd, "total="); rsh_u32(fd, t);
            rsh_puts(fd, " used="); rsh_u32(fd, u);
            rsh_puts(fd, " free="); rsh_u32(fd, f); rsh_puts(fd, "\r\n");
        } else rsh_puts(fd, "df failed\r\n");
    } else {
        rsh_puts(fd, "unknown command: "); rsh_puts(fd, c); rsh_puts(fd, "\r\n");
    }
    return true;
}

/* ---- одна сессия ---- */

static void rsh_session(int fd) {
    rsh_puts(fd, "\r\nKnitOS remote shell (raw). Type 'exit' to quit.\r\n");
    for (int tries = 0; tries < 3; tries++) {
        rsh_puts(fd, "login: ");
        char uname[UNAME_MAX];
        int n = rsh_readline(fd, uname, sizeof(uname), 30000, true);
        if (n < 0) return;
        const struct user_record* u = user_by_name(uname);
        rsh_puts(fd, "password: ");
        char pw[64];
        n = rsh_readline(fd, pw, sizeof(pw), 30000, false);
        if (n < 0) return;
        if (u && user_check_password(uname, pw)) {
            task_setuid_force(u->uid);
            fs_set_current_uid(u->uid);
            task_setgid_force(u->gid);
            fs_set_current_gid(u->gid);
            struct fs_stat st;
            if (fs_stat(u->home, &st) == 0 && (st.flags & FS_FLAG_DIRECTORY))
                utils_set_current_directory(u->home);
            else
                utils_set_current_directory("/");
            rsh_puts(fd, "Welcome, "); rsh_puts(fd, u->name); rsh_puts(fd, "\r\n");
            char line[256];
            for (;;) {
                rsh_prompt(fd, u->name);
                int r = rsh_readline(fd, line, sizeof(line), 120000, true);
                if (r < 0) return;
                if (!rsh_cmd(fd, u->name, line)) return;
            }
        }
        rsh_puts(fd, "Login incorrect\r\n");
    }
}

/* ---- серверный kthread ---- */

static void rsh_task(void* arg) {
    (void)arg;
    if (ip_get_our_ip() == 0) { g_rsh_running = 0; task_exit(); }

    int sfd = socket_create(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { g_rsh_running = 0; task_exit(); }
    socket_set_owner(sfd, "rshd", -1);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = g_rsh_port;
    addr.sin_addr = 0;
    if (socket_bind(sfd, &addr) != 0 || socket_listen(sfd, 2) != 0) {
        socket_close(sfd);
        log_msg(LOG_ERR, "rsh", "bind/listen failed");
        g_rsh_running = 0;
        task_exit();
    }
    g_rsh_ready = 1;
    log_fmt3(LOG_INFO, "rsh", "listen", "port", (uint32_t)g_rsh_port, "max", (uint32_t)g_rsh_max, "ok", 1);
    terminal_writestring("\n[RSH] remote shell listening");

    for (;;) {
        if (!g_rsh_running) break;
        int cfd = socket_accept(sfd, g_rsh_timeout);
        if (cfd < 0) continue;               /* таймаут — продолжаем ждать */
        g_rsh_sessions++;
        log_msg(LOG_INFO, "rsh", "accept");
        rsh_session(cfd);
        socket_close(cfd);
        log_msg(LOG_INFO, "rsh", "session closed");
        if (g_rsh_max > 0 && g_rsh_sessions >= g_rsh_max) break;
    }

    socket_close(sfd);
    g_rsh_running = 0;
    g_rsh_ready = 0;
    g_rsh_pid = -1;
    task_exit();
}

int rsh_server_start(uint16_t port, int max_sessions, int accept_timeout_ms) {
    if (g_rsh_running) return -1;
    if (ip_get_our_ip() == 0) return -1;
    if (max_sessions < 0) max_sessions = 0;   /* 0 = без ограничения */
    if (accept_timeout_ms < 1000) accept_timeout_ms = 1000;
    g_rsh_port = port ? port : 2323;
    g_rsh_max = max_sessions;
    g_rsh_timeout = accept_timeout_ms;
    g_rsh_sessions = 0;
    g_rsh_ready = 0;
    g_rsh_running = 1;
    int id = task_create(rsh_task, 0, "rshd");
    if (id < 0) { g_rsh_running = 0; return -1; }
    task_enable_aspace(id);
    g_rsh_pid = id;
    return id;
}

void rsh_server_stop(void) {
    if (g_rsh_pid >= 0) task_kill(g_rsh_pid);
    g_rsh_running = 0;
    g_rsh_ready = 0;
    g_rsh_pid = -1;
}

int rsh_server_running(void) { return g_rsh_running; }
