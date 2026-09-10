// FTP server (RFC 959) — control connection + PASV data channel.
// Auth via /etc/passwd + /etc/shadow; file ops via the VFS.
#include "ftp_server.h"
#include "socket.h"
#include "protocols/ip.h"
#include "fs.h"
#include "fs_file.h"
#include "vfs.h"
#include "utils.h"
#include "user_auth.h"
#include "kernel.h"
#include "string.h"
#include "sched/task.h"
#include "serial_log.h"
#include "drivers/video/terminal.h"
#include "drivers/timer/pit.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

static volatile int g_ftp_running = 0;
static int g_ftp_pid = -1;
static uint16_t g_ftp_port = 21;
static int g_ftp_timeout = 1000;
static int g_ftp_data_listen = -1;
static uint16_t g_ftp_data_port = 0;

/* ---- вывод ответов ---- */

static void ftp_send_raw(int fd, const char* s) {
    size_t n = 0; while (s[n]) n++;
    socket_send(fd, s, n);
}
static void ftp_reply(int fd, int code, const char* text) {
    char c[5];
    c[0] = (char)('0' + (code / 100) % 10);
    c[1] = (char)('0' + (code / 10) % 10);
    c[2] = (char)('0' + code % 10);
    c[3] = ' ';
    c[4] = 0;
    ftp_send_raw(fd, c);
    ftp_send_raw(fd, text);
    ftp_send_raw(fd, "\r\n");
}

/* ---- ввод команд (строка до CRLF) ---- */

static int ftp_readline(int fd, char* buf, size_t cap, int timeout_ms) {
    static int skip_lf = 0;
    size_t len = 0;
    for (;;) {
        uint8_t ch = 0;
        int n = socket_recv(fd, &ch, 1, timeout_ms);
        if (n < 0) return -1;
        if (n == 0) { if (len == 0) return -2; continue; }
        if (skip_lf && ch == '\n') { skip_lf = 0; continue; }
        skip_lf = 0;
        if (ch == 0xFF) { uint8_t sk[2]; socket_recv(fd, sk, 2, timeout_ms); continue; }
        if (ch == '\r') { skip_lf = 1; break; }
        if (ch == '\n') break;
        if (len + 1 < cap) buf[len++] = (char)ch;
    }
    buf[len] = 0;
    return (int)len;
}

/* ---- пассивный канал данных ---- */

static int ftp_accept_data(int listen_fd, int timeout_ms) {
    int dfd = socket_accept(listen_fd, timeout_ms);
    return dfd;
}

/* ---- листинг ---- */

static void ftp_send_listing(int dfd, const char* path) {
    static char names[2048];
    int r = vfs_list(path, names, sizeof(names));
    if (r < 0) return;
    char* p = names;
    while (*p) {
        char* nl = p;
        while (*nl && *nl != '\n') nl++;
        size_t nl_len = (size_t)(nl - p);
        if (nl_len) {
            char name[128];
            size_t k = 0;
            bool isdir = false;
            for (size_t i = 0; i < nl_len && k + 1 < sizeof(name); i++) {
                if (p[i] == '/') { isdir = true; continue; }
                if (p[i] == '@') continue;
                name[k++] = p[i];
            }
            name[k] = 0;
            /* stat для размера */
            char full[256];
            size_t fl = 0;
            while (path[fl] && fl + 1 < sizeof(full)) { full[fl] = path[fl]; fl++; }
            if (fl == 0 || full[fl - 1] != '/') { if (fl + 1 < sizeof(full)) full[fl++] = '/'; }
            size_t j = 0;
            while (name[j] && fl + 1 < sizeof(full)) full[fl++] = name[j++];
            full[fl] = 0;
            struct fs_stat st;
            uint32_t size = 0;
            if (fs_stat(full, &st) == 0) size = st.size;
            char line[220];
            int o = 0;
            const char* perm = isdir ? "drwxr-xr-x" : "-rw-r--r--";
            for (int i = 0; perm[i] && o < 200; i++) line[o++] = perm[i];
            line[o++] = ' '; line[o++] = '1'; line[o++] = ' ';
            /* uid gid (упрощённо 0 0) */
            line[o++] = '0'; line[o++] = ' '; line[o++] = '0'; line[o++] = ' ';
            { char t[12]; int q = 0; uint32_t v = size; if (v == 0) t[q++] = '0'; else { char tb[12]; int tc = 0; while (v > 0 && tc < 11) { tb[tc++] = (char)('0' + v % 10); v /= 10; } while (tc > 0) t[q++] = tb[--tc]; } for (int i = 0; i < q && o < 200; i++) line[o++] = t[i]; }
            line[o++] = ' ';
            const char* mon = "Jan 01 00:00";
            for (int i = 0; mon[i] && o < 200; i++) line[o++] = mon[i];
            line[o++] = ' ';
            for (size_t i = 0; i < k && o < 210; i++) line[o++] = name[i];
            line[o++] = '\r'; line[o++] = '\n';
            socket_send(dfd, line, (size_t)o);
        }
        if (*nl == 0) break;
        p = nl + 1;
    }
}

/* ---- одна сессия ---- */

static void ftp_session(int ctrl) {
    ftp_reply(ctrl, 220, "KnitOS FTP server ready");
    char user[UNAME_MAX]; user[0] = 0;
    bool logged = false;
    int data_listen = -1;
    uint16_t data_port = 0;

    char line[256];
    for (;;) {
        int n = ftp_readline(ctrl, line, sizeof(line), 120000);
        if (n < 0) break;

        /* разделить команду и аргумент */
        char cmd[8];
        int ci = 0;
        size_t i = 0;
        while (i < (size_t)n && line[i] != ' ' && ci < 7) {
            char ch = line[i++];
            if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
            cmd[ci++] = ch;
        }
        cmd[ci] = 0;
        while (i < (size_t)n && line[i] == ' ') i++;
        const char* arg = line + i;

        if (strcmp(cmd, "QUIT") == 0) { ftp_reply(ctrl, 221, "Goodbye"); break; }
        else if (strcmp(cmd, "USER") == 0) {
            strncpy(user, arg, sizeof(user) - 1); user[sizeof(user) - 1] = 0;
            ftp_reply(ctrl, 331, "Password required");
        } else if (strcmp(cmd, "PASS") == 0) {
            const struct user_record* u = user_by_name(user);
            if (u && user_check_password(user, arg)) {
                task_setuid_force(u->uid); fs_set_current_uid(u->uid);
                task_setgid_force(u->gid); fs_set_current_gid(u->gid);
                struct fs_stat st;
                if (fs_stat(u->home, &st) == 0 && (st.flags & FS_FLAG_DIRECTORY)) utils_set_current_directory(u->home);
                else utils_set_current_directory("/");
                logged = true;
                ftp_reply(ctrl, 230, "Login successful");
            } else {
                ftp_reply(ctrl, 530, "Login incorrect");
            }
        } else if (!logged) {
            ftp_reply(ctrl, 530, "Please login with USER and PASS");
        } else if (strcmp(cmd, "SYST") == 0) {
            ftp_reply(ctrl, 215, "UNIX Type: L8");
        } else if (strcmp(cmd, "FEAT") == 0) {
            ftp_send_raw(ctrl, "211-Features:\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n");
        } else if (strcmp(cmd, "TYPE") == 0) {
            ftp_reply(ctrl, 200, "Type set");
        } else if (strcmp(cmd, "PWD") == 0 || strcmp(cmd, "XPWD") == 0) {
            char b[160];
            int o = 0;
            const char* cwd = utils_get_current_directory();
            b[o++] = '2'; b[o++] = '5'; b[o++] = '7'; b[o++] = ' ';
            b[o++] = '"';
            for (int j = 0; cwd[j] && o < 150; j++) b[o++] = cwd[j];
            b[o++] = '"';
            const char* tail = " is current directory";
            for (int j = 0; tail[j] && o < 158; j++) b[o++] = tail[j];
            b[o++] = '\r'; b[o++] = '\n'; b[o] = 0;
            ftp_send_raw(ctrl, b);
        } else if (strcmp(cmd, "CWD") == 0) {
            char abs[128];
            if (arg[0] && utils_resolve_path(arg, abs, sizeof(abs)) == 0) {
                char probe[8];
                if (vfs_list(abs, probe, sizeof(probe)) >= 0) { utils_set_current_directory(abs); ftp_reply(ctrl, 250, "Directory changed"); }
                else ftp_reply(ctrl, 550, "Failed to change directory");
            } else ftp_reply(ctrl, 550, "Failed to change directory");
        } else if (strcmp(cmd, "CDUP") == 0) {
            utils_set_current_directory("/");
            ftp_reply(ctrl, 250, "Directory changed");
        } else if (strcmp(cmd, "PASV") == 0) {
            if (g_ftp_data_listen < 0) { ftp_reply(ctrl, 425, "No data listener"); continue; }
            data_listen = g_ftp_data_listen;
            data_port = g_ftp_data_port;
            uint32_t ip = ip_get_our_ip();
            char b[80];
            int o = 0;
            b[o++] = '2'; b[o++] = '2'; b[o++] = '7'; b[o++] = ' ';
            const char* pre = "Entering Passive Mode (";
            for (int j = 0; pre[j]; j++) b[o++] = pre[j];
            uint8_t oct[4] = { (uint8_t)(ip >> 24), (uint8_t)(ip >> 16), (uint8_t)(ip >> 8), (uint8_t)ip };
            for (int k = 0; k < 4; k++) {
                char t[4]; int q = 0; uint32_t v = oct[k];
                if (v == 0) t[q++] = '0'; else { char tb[4]; int tc = 0; while (v > 0 && tc < 3) { tb[tc++] = (char)('0' + v % 10); v /= 10; } while (tc > 0) t[q++] = tb[--tc]; }
                for (int j = 0; j < q; j++) b[o++] = t[j];
                b[o++] = ',';
            }
            { uint32_t hi = data_port / 256, lo = data_port % 256;
              char t[4]; int q = 0; uint32_t v = hi; if (v == 0) t[q++] = '0'; else { char tb[4]; int tc = 0; while (v > 0 && tc < 3) { tb[tc++] = (char)('0' + v % 10); v /= 10; } while (tc > 0) t[q++] = tb[--tc]; } for (int j = 0; j < q; j++) b[o++] = t[j];
              b[o++] = ',';
              q = 0; v = lo; if (v == 0) t[q++] = '0'; else { char tb[4]; int tc = 0; while (v > 0 && tc < 3) { tb[tc++] = (char)('0' + v % 10); v /= 10; } while (tc > 0) t[q++] = tb[--tc]; } for (int j = 0; j < q; j++) b[o++] = t[j];
            }
            b[o++] = ')'; b[o++] = '\r'; b[o++] = '\n'; b[o] = 0;
            ftp_send_raw(ctrl, b);
        } else if (strcmp(cmd, "LIST") == 0 || strcmp(cmd, "NLST") == 0) {
            if (data_listen < 0) { ftp_reply(ctrl, 425, "Use PASV first"); continue; }
            ftp_reply(ctrl, 150, "Opening data connection");
            int dfd = ftp_accept_data(data_listen, 5000);
            if (dfd < 0) { ftp_reply(ctrl, 425, "Cannot open data connection"); continue; }
            const char* path = (arg[0] && strcmp(cmd, "LIST") == 0) ? arg : utils_get_current_directory();
            if (strcmp(cmd, "NLST") == 0) {
                static char nb[2048];
                int r = vfs_list(path, nb, sizeof(nb));
                if (r > 0) socket_send(dfd, nb, (size_t)r);
            } else {
                ftp_send_listing(dfd, path);
            }
            socket_close(dfd);
            ftp_reply(ctrl, 226, "Transfer complete");
        } else if (strcmp(cmd, "RETR") == 0) {
            if (data_listen < 0) { ftp_reply(ctrl, 425, "Use PASV first"); continue; }
            char abs[128];
            if (!arg[0] || utils_resolve_path(arg, abs, sizeof(abs)) != 0) { ftp_reply(ctrl, 550, "File unavailable"); continue; }
            int of = vfs_open(abs, O_RDONLY, 0);
            if (of < 0) { ftp_reply(ctrl, 550, "File unavailable"); continue; }
            ftp_reply(ctrl, 150, "Opening data connection");
            int dfd = ftp_accept_data(data_listen, 5000);
            if (dfd < 0) { vfs_close(of); ftp_reply(ctrl, 425, "Cannot open data connection"); continue; }
            static char buf[1024];
            int r;
            while ((r = vfs_fread(of, buf, sizeof(buf))) > 0) socket_send(dfd, buf, (size_t)r);
            vfs_close(of);
            socket_close(dfd);
            ftp_reply(ctrl, 226, "Transfer complete");
        } else if (strcmp(cmd, "STOR") == 0) {
            if (data_listen < 0) { ftp_reply(ctrl, 425, "Use PASV first"); continue; }
            char abs[128];
            if (!arg[0] || utils_resolve_path(arg, abs, sizeof(abs)) != 0) { ftp_reply(ctrl, 550, "File unavailable"); continue; }
            ftp_reply(ctrl, 150, "Opening data connection");
            int dfd = ftp_accept_data(data_listen, 5000);
            if (dfd < 0) { ftp_reply(ctrl, 425, "Cannot open data connection"); continue; }
            static char buf[1024];
            static char file[16384];
            size_t total = 0;
            int r;
            while ((r = socket_recv(dfd, buf, sizeof(buf), 5000)) > 0) {
                for (int k = 0; k < r && total + 1 < sizeof(file); k++) file[total++] = buf[k];
            }
            socket_close(dfd);
            if (vfs_write(abs, file, total) == 0) ftp_reply(ctrl, 226, "Transfer complete");
            else ftp_reply(ctrl, 550, "Write failed");
        } else if (strcmp(cmd, "DELE") == 0) {
            char abs[128];
            if (arg[0] && utils_resolve_path(arg, abs, sizeof(abs)) == 0 && vfs_unlink(abs) == 0) ftp_reply(ctrl, 250, "Deleted");
            else ftp_reply(ctrl, 550, "Delete failed");
        } else if (strcmp(cmd, "MKD") == 0) {
            char abs[128];
            if (arg[0] && utils_resolve_path(arg, abs, sizeof(abs)) == 0 && vfs_mkdir(abs) == 0) ftp_reply(ctrl, 257, "Directory created");
            else ftp_reply(ctrl, 550, "Create failed");
        } else if (strcmp(cmd, "RMD") == 0) {
            char abs[128];
            if (arg[0] && utils_resolve_path(arg, abs, sizeof(abs)) == 0 && vfs_unlink(abs) == 0) ftp_reply(ctrl, 250, "Removed");
            else ftp_reply(ctrl, 550, "Remove failed");
        } else if (strcmp(cmd, "SIZE") == 0) {
            char abs[128];
            struct fs_stat st;
            if (arg[0] && utils_resolve_path(arg, abs, sizeof(abs)) == 0 && fs_stat(abs, &st) == 0) {
                char b[32]; int o = 0;
                b[o++] = '2'; b[o++] = '1'; b[o++] = '3'; b[o++] = ' ';
                char t[12]; int q = 0; uint32_t v = st.size;
                if (v == 0) t[q++] = '0'; else { char tb[12]; int tc = 0; while (v > 0 && tc < 11) { tb[tc++] = (char)('0' + v % 10); v /= 10; } while (tc > 0) t[q++] = tb[--tc]; }
                for (int j = 0; j < q; j++) b[o++] = t[j];
                b[o++] = '\r'; b[o++] = '\n'; b[o] = 0;
                ftp_send_raw(ctrl, b);
            } else ftp_reply(ctrl, 550, "File unavailable");
        } else if (strcmp(cmd, "NOOP") == 0) {
            ftp_reply(ctrl, 200, "OK");
        } else {
            ftp_reply(ctrl, 502, "Command not implemented");
        }
    }

    (void)data_listen;
    (void)data_port;
}

/* ---- серверный kthread ---- */

static void ftp_task(void* arg) {
    (void)arg;
    if (ip_get_our_ip() == 0) { g_ftp_running = 0; task_exit(); }
    int sfd = socket_create(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { g_ftp_running = 0; task_exit(); }
    socket_set_owner(sfd, "ftpd", -1);
    struct sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_port = g_ftp_port; addr.sin_addr = 0;
    if (socket_bind(sfd, &addr) != 0 || socket_listen(sfd, 2) != 0) {
        socket_close(sfd); log_msg(LOG_ERR, "ftp", "bind/listen failed"); g_ftp_running = 0; task_exit();
    }
    log_fmt3(LOG_INFO, "ftp", "listen", "port", (uint32_t)g_ftp_port, "ok", 1, "x", 0);

    /* Data-листенер создаём ОДИН раз при старте (как control), а не динамически
       в PASV — динамическое создание второго листенера вешало TCP-стек. */
    int lfd = socket_create(AF_INET, SOCK_STREAM, 0);
    if (lfd >= 0) {
        struct sockaddr_in da; da.sin_family = AF_INET; da.sin_port = 2020; da.sin_addr = 0;
        if (socket_bind(lfd, &da) == 0 && socket_listen(lfd, 1) == 0) {
            socket_set_owner(lfd, "ftpd", -1);
            struct sockaddr_in got; socket_getsockname(lfd, &got);
            g_ftp_data_listen = lfd;
            g_ftp_data_port = got.sin_port;
        } else {
            socket_close(lfd);
            g_ftp_data_listen = -1;
        }
    }

    terminal_writestring("\n[FTP] server listening");

    for (;;) {
        if (!g_ftp_running) break;
        int cfd = socket_accept(sfd, g_ftp_timeout);
        if (cfd < 0) continue;
        log_msg(LOG_INFO, "ftp", "accept");
        ftp_session(cfd);
        socket_close(cfd);
        log_msg(LOG_INFO, "ftp", "session closed");
    }
    socket_close(sfd);
    if (g_ftp_data_listen >= 0) { socket_close(g_ftp_data_listen); g_ftp_data_listen = -1; }
    g_ftp_running = 0;
    g_ftp_pid = -1;
    task_exit();
}

int ftp_server_start(uint16_t port, int accept_timeout_ms) {
    if (g_ftp_running) return -1;
    if (ip_get_our_ip() == 0) return -1;
    if (accept_timeout_ms < 1000) accept_timeout_ms = 1000;
    g_ftp_port = port ? port : 21;
    g_ftp_timeout = accept_timeout_ms;
    g_ftp_data_listen = -1;
    g_ftp_data_port = 0;
    g_ftp_running = 1;
    int id = task_create(ftp_task, 0, "ftpd");
    if (id < 0) { g_ftp_running = 0; return -1; }
    task_enable_aspace(id);
    g_ftp_pid = id;
    return id;
}

void ftp_server_stop(void) {
    if (g_ftp_pid >= 0) task_kill(g_ftp_pid);
    g_ftp_running = 0;
    g_ftp_pid = -1;
}

int ftp_server_running(void) { return g_ftp_running; }
