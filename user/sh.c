// M4: minimal user-space shell (fork/exec/wait/pipe over the syscall ABI).
#include "lib/libk.h"

#define LMAX 256
#define AMAX 16

static char g_line[LMAX];
static char g_cmdline[LMAX];
static char* g_argv[AMAX + 1];

static int read_line(char* buf, int cap) {
    int n = 0;
    while (n < cap - 1) {
        char c;
        long r = sys_read(0, &c, 1);
        if (r < 0) return -1;
        if (r == 0) { if (n == 0) return -2; break; }
        if (c == '\n') break;
        if (c == '\r') continue;
        buf[n++] = c;
    }
    buf[n] = 0;
    return n;
}

static int tokenize(char* s, char** argv, int max) {
    int n = 0;
    while (*s && n < max) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        if (*s == '|') { argv[n++] = (char*)"|"; s++; continue; }
        argv[n++] = s;
        while (*s && *s != ' ' && *s != '\t' && *s != '|') s++;
        if (*s) { *s = 0; s++; }
    }
    argv[n] = 0;
    return n;
}

static void get_username(int uid, char* out, int cap);

static void run_exec(char** argv) {
    char path[160];
    if (strchr(argv[0], '/')) {
        strncpy(path, argv[0], sizeof(path) - 1);
        path[sizeof(path) - 1] = 0;
    } else {
        strcpy(path, "/tmp/");
        strcat(path, argv[0]);
        strcat(path, ".elf");
    }
    sys_execve(path, argv, 0);
    printf("sh: %s: not found\n", argv[0]);
    sys_exit(127);
}

static void run_builtin(char** argv, int* handled) {
    *handled = 1;
    if (!strcmp(argv[0], "exit")) {
        sys_exit(0);
    } else if (!strcmp(argv[0], "cd")) {
        const char* d = argv[1] ? argv[1] : (sys_getuid() == 0 ? "/root" : "/");
        if (sys_chdir(d) < 0) printf("sh: cd: %s: no such dir\n", d);
    } else if (!strcmp(argv[0], "pwd")) {
        char cwd[160];
        if (sys_getcwd(cwd, sizeof(cwd)) >= 0) printf("%s\n", cwd);
    } else if (!strcmp(argv[0], "echo")) {
        for (int i = 1; argv[i]; i++) {
            if (i > 1) putchar(' ');
            printf("%s", argv[i]);
        }
        putchar('\n');
    } else if (!strcmp(argv[0], "id")) {
        char u[32];
        get_username((int)sys_getuid(), u, sizeof(u));
        printf("uid=%d(%s) gid=%d\n", (int)sys_getuid(), u, (int)sys_getgid());
    } else if (!strcmp(argv[0], "whoami")) {
        char u[32];
        get_username((int)sys_getuid(), u, sizeof(u));
        printf("%s\n", u);
    } else if (!strcmp(argv[0], "ls")) {
        char cwdbuf[128];
        const char* d = argv[1];
        if (!d) { if (sys_getcwd(cwdbuf, sizeof(cwdbuf)) < 0) cwdbuf[0] = 0; d = cwdbuf; }
        int fd = (int)sys_open(d, O_RDONLY | O_DIRECTORY, 0);
        if (fd < 0) { printf("ls: %s: no such directory\n", d); return; }
        char name[128];
        long n;
        while ((n = sys_getdents(fd, name, sizeof(name))) > 0) {
            printf("%s\n", name);
        }
        sys_close(fd);
    } else if (!strcmp(argv[0], "cat")) {
        if (!argv[1]) {
            /* Без аргумента читаем stdin (как в Linux). */
            char buf[512];
            long n;
            while ((n = sys_read(0, buf, sizeof(buf))) > 0)
                sys_write(1, buf, (unsigned long)n);
            return;
        }
        int fd = (int)sys_open(argv[1], O_RDONLY, 0);
        if (fd < 0) { printf("cat: %s: no such file\n", argv[1]); return; }
        char buf[512];
        long n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) sys_write(1, buf, (unsigned long)n);
        sys_close(fd);
    } else if (!strcmp(argv[0], "touch")) {
        if (!argv[1]) { printf("touch: usage: touch <file>\n"); return; }
        int fd = (int)sys_open(argv[1], O_CREAT | O_WRONLY, 0);
        if (fd < 0) printf("touch: %s: failed\n", argv[1]);
        else sys_close(fd);
    } else if (!strcmp(argv[0], "rm")) {
        if (!argv[1]) { printf("rm: usage: rm <file>\n"); return; }
        if (sys_unlink(argv[1]) < 0) printf("rm: %s: failed\n", argv[1]);
    } else if (!strcmp(argv[0], "help")) {
        printf("builtins: cd pwd ls cat touch rm echo id whoami exit help\n");
        printf("kernel cmds: uname uptime ps ifconfig df\n");
        printf("all other kernel console commands also work\n");
        printf("(ping, traceroute, netstat, ports, date, version, find, ...)\n");
    } else {
        *handled = 0;
    }
}

static void child_run(char** argv) {
    int handled = 0;
    run_builtin(argv, &handled);
    if (handled) sys_exit(0);
    run_exec(argv);
}

/* ---------------- редактор строки (raw PTY) ---------------- */

#define HIST_MAX 16

static char g_hist[HIST_MAX][LMAX];
static int  g_hist_count = 0;
static int  g_hist_pos = -1;

static void hist_add(const char* s) {
    if (!s[0]) return;
    if (g_hist_count > 0 && !strcmp(g_hist[g_hist_count - 1], s)) return;
    if (g_hist_count < HIST_MAX) {
        strcpy(g_hist[g_hist_count++], s);
    } else {
        for (int i = 1; i < HIST_MAX; i++) strcpy(g_hist[i - 1], g_hist[i]);
        strcpy(g_hist[HIST_MAX - 1], s);
    }
}

static void emit(const char* s) { sys_write(1, s, (unsigned long)strlen(s)); }

/* Имя пользователя по uid из /etc/passwd (как в Linux). */
static void get_username(int uid, char* out, int cap) {
    const char* def = (uid == 0) ? "root" : "user";
    int fd = (int)sys_open("/etc/passwd", O_RDONLY, 0);
    if (fd < 0) goto fallback;
    {
        static char pbuf[2048];
        long n = sys_read(fd, pbuf, sizeof(pbuf) - 1);
        sys_close(fd);
        if (n <= 0) goto fallback;
        pbuf[n] = 0;
        char* p = pbuf;
        while (*p) {
            char* line = p;
            while (*p && *p != '\n') p++;
            if (*p == '\n') { *p = 0; p++; }
            char* c1 = strchr(line, ':');
            if (!c1) continue;
            *c1 = 0;
            char* c2 = strchr(c1 + 1, ':');
            if (!c2) continue;
            int u = 0;
            for (char* q = c2 + 1; *q && *q != ':'; q++) u = u * 10 + (*q - '0');
            if (u == uid) {
                int i = 0;
                while (line[i] && i < cap - 1) { out[i] = line[i]; i++; }
                out[i] = 0;
                return;
            }
        }
    }
fallback:
    strncpy(out, def, cap - 1);
    out[cap - 1] = 0;
}

static void redraw(const char* prompt, const char* buf, int len, int pos) {
    emit("\r");
    emit(prompt);
    if (len > 0) sys_write(1, buf, (unsigned long)len);
    emit("\x1b[K");
    int back = len - pos;
    if (back > 0) {
        char esc[16];
        int k = 0;
        esc[k++] = 0x1b; esc[k++] = '[';
        int v = back, d[8], n = 0;
        while (v) { d[n++] = v % 10; v /= 10; }
        while (n) esc[k++] = (char)('0' + d[--n]);
        esc[k++] = 'D';
        esc[k] = 0;
        emit(esc);
    }
}

static const char* g_cmds[] = {
    "cd", "pwd", "ls", "cat", "touch", "rm", "echo", "id", "exit", "help",
    "uname", "uptime", "ps", "ifconfig", "df", "ping", "traceroute", "netstat",
    "ports", "date", "version", "whoami", "users", "groups", "find", "log",
    "arp", "route", "httpget", "dhcp", "dns",
    "hello", "demo3", "argtest", "ptytest", "launcher", "httpd", "sh", "ksshd", "sshd",
    0
};

static void complete(char* buf, int* lenp, int* posp, int cap, const char* prompt) {
    int len = *lenp, pos = *posp;
    int start = pos;
    while (start > 0 && buf[start - 1] != ' ' && buf[start - 1] != '\t') start--;
    int wlen = pos - start;
    const char* word = buf + start;
    int first_cmd = (start == 0);

    static char matches[64][64];
    int nmatch = 0;
    if (first_cmd) {
        for (int i = 0; g_cmds[i] && nmatch < 64; i++) {
            if (wlen == 0 || strncmp(g_cmds[i], word, wlen) == 0) {
                strncpy(matches[nmatch], g_cmds[i], 63);
                matches[nmatch][63] = 0;
                nmatch++;
            }
        }
    }
    /* файлы текущего каталога */
    {
        char cwd[128];
        const char* d = ".";
        if (sys_getcwd(cwd, sizeof(cwd)) >= 0) d = cwd;
        int fd = (int)sys_open(d, O_RDONLY | O_DIRECTORY, 0);
        if (fd >= 0) {
            char name[64];
            long n;
            while ((n = sys_getdents(fd, name, sizeof(name))) > 0 && nmatch < 64) {
                if (wlen == 0 || strncmp(name, word, wlen) == 0) {
                    strncpy(matches[nmatch], name, 63);
                    matches[nmatch][63] = 0;
                    nmatch++;
                }
            }
            sys_close(fd);
        }
    }

    if (nmatch == 1) {
        const char* rest = matches[0] + wlen;
        int rl = (int)strlen(rest);
        if (len + rl < cap - 1) {
            for (int i = len; i >= pos; i--) buf[i + rl] = buf[i];
            for (int i = 0; i < rl; i++) buf[pos + i] = rest[i];
            len += rl; pos += rl;
            redraw(prompt, buf, len, pos);
        }
    } else if (nmatch > 1) {
        emit("\n");
        for (int i = 0; i < nmatch; i++) { emit(matches[i]); emit("  "); }
        emit("\n");
        redraw(prompt, buf, len, pos);
    }
    *lenp = len; *posp = pos;
}

static int read_line_edited(char* buf, int cap, const char* prompt) {
    int len = 0, pos = 0;
    g_hist_pos = -1;
    buf[0] = 0;
    emit(prompt);
    for (;;) {
        char c;
        long r = sys_read(0, &c, 1);
        if (r < 0) return -1;
        if (r == 0) { emit("\n"); return -2; }
        if (c == '\r' || c == '\n') { emit("\n"); buf[len] = 0; return len; }

        if (c == 0x7f || c == 0x08) {
            if (pos > 0) {
                for (int i = pos - 1; i < len - 1; i++) buf[i] = buf[i + 1];
                len--; pos--; buf[len] = 0;
                redraw(prompt, buf, len, pos);
            }
            continue;
        }
        if (c == 0x1b) {
            char a = 0, b = 0;
            if (sys_read(0, &a, 1) <= 0) continue;
            if (a == '[' || a == 'O') {
                if (sys_read(0, &b, 1) <= 0) continue;
                if (b == 'A') {
                    if (g_hist_count == 0) continue;
                    if (g_hist_pos < 0) g_hist_pos = g_hist_count;
                    if (g_hist_pos > 0) g_hist_pos--;
                    strcpy(buf, g_hist[g_hist_pos]);
                    len = pos = (int)strlen(buf);
                    redraw(prompt, buf, len, pos);
                } else if (b == 'B') {
                    if (g_hist_pos < 0) continue;
                    if (g_hist_pos < g_hist_count - 1) {
                        g_hist_pos++;
                        strcpy(buf, g_hist[g_hist_pos]);
                    } else {
                        g_hist_pos = -1; buf[0] = 0;
                    }
                    len = pos = (int)strlen(buf);
                    redraw(prompt, buf, len, pos);
                } else if (b == 'C') {
                    if (pos < len) { pos++; redraw(prompt, buf, len, pos); }
                } else if (b == 'D') {
                    if (pos > 0) { pos--; redraw(prompt, buf, len, pos); }
                } else if (b == 'H') {
                    pos = 0; redraw(prompt, buf, len, pos);
                } else if (b == 'F') {
                    pos = len; redraw(prompt, buf, len, pos);
                } else if (b == '3') {
                    char t; sys_read(0, &t, 1);   /* Delete: ESC [ 3 ~ */
                    if (pos < len) {
                        for (int i = pos; i < len - 1; i++) buf[i] = buf[i + 1];
                        len--; buf[len] = 0;
                        redraw(prompt, buf, len, pos);
                    }
                }
            }
            continue;
        }
        if (c == 0x03) { emit("^C\n"); len = pos = 0; buf[0] = 0; emit(prompt); continue; }
        if (c == 0x04) {
            if (len == 0) { emit("\n"); return -2; }
            if (pos < len) {
                for (int i = pos; i < len - 1; i++) buf[i] = buf[i + 1];
                len--; buf[len] = 0;
                redraw(prompt, buf, len, pos);
            }
            continue;
        }
        if (c == 0x01) { pos = 0; redraw(prompt, buf, len, pos); continue; }
        if (c == 0x05) { pos = len; redraw(prompt, buf, len, pos); continue; }
        if (c == 0x0b) { len = pos; buf[len] = 0; redraw(prompt, buf, len, pos); continue; }
        if (c == 0x15) { len = pos = 0; buf[0] = 0; redraw(prompt, buf, len, pos); continue; }
        if (c == '\t') { complete(buf, &len, &pos, cap, prompt); continue; }

        if ((unsigned char)c >= 0x20 && len < cap - 1) {
            for (int i = len; i > pos; i--) buf[i] = buf[i - 1];
            buf[pos] = c; len++; pos++;
            buf[len] = 0;
            if (pos == len) sys_write(1, &c, 1);
            else redraw(prompt, buf, len, pos);
        }
    }
}

static void run_line(char* line) {
    strcpy(g_cmdline, line);
    int na = tokenize(line, g_argv, AMAX);
    if (na == 0) return;

    int pipe_at = -1;
    for (int i = 0; i < na; i++) {
        if (!strcmp(g_argv[i], "|")) { pipe_at = i; break; }
    }
    if (pipe_at > 0 && pipe_at < na - 1) {
        g_argv[pipe_at] = 0;
        char** left = g_argv;
        char** right = &g_argv[pipe_at + 1];
        int fds[2];
        if (sys_pipe(fds) < 0) { printf("sh: pipe failed\n"); return; }
        long p1 = sys_fork();
        if (p1 == 0) {
            sys_dup2(fds[1], 1);
            sys_close(fds[0]);
            sys_close(fds[1]);
            child_run(left);
        }
        long p2 = sys_fork();
        if (p2 == 0) {
            sys_dup2(fds[0], 0);
            sys_close(fds[0]);
            sys_close(fds[1]);
            child_run(right);
        }
        sys_close(fds[0]);
        sys_close(fds[1]);
        int st;
        if (p1 > 0) sys_waitpid((int)p1, &st);
        if (p2 > 0) sys_waitpid((int)p2, &st);
        return;
    }

    int handled = 0;
    run_builtin(g_argv, &handled);
    if (!handled) {
        /* Try a kernel command (full line, args included), else exec.
           sys_kcmd returns >=0 if the kernel handled it (0 = no output),
           or <0 if unknown — then run an external /tmp/<name>.elf. */
        static char kout[4096];
        long n = sys_kcmd(g_cmdline, kout, sizeof(kout));
        if (n >= 0) {
            if (n > 0) sys_write(1, kout, (unsigned long)n);
        } else {
            long pid = sys_fork();
            if (pid == 0) run_exec(g_argv);
            if (pid > 0) { int st; sys_waitpid((int)pid, &st); }
            else printf("sh: fork failed\n");
        }
    }
}

int main(int argc, char** argv) {
    /* Non-interactive: sh -c "command" (used by sshd for exec requests). */
    if (argc >= 3 && !strcmp(argv[1], "-c")) {
        char line[LMAX];
        strncpy(line, argv[2], LMAX - 1);
        line[LMAX - 1] = 0;
        run_line(line);
        return 0;
    }
    int tty = (sys_isatty(0) == 1);
    if (tty) sys_pty_raw(0, 1);
    for (;;) {
        char cwd[128];
        if (sys_getcwd(cwd, sizeof(cwd)) < 0) cwd[0] = 0;
        char who[32];
        get_username((int)sys_getuid(), who, sizeof(who));
        const char* sig = sys_getuid() == 0 ? "#" : "$";
        char prompt[160];
        strcpy(prompt, who);
        strcat(prompt, "@knitos:");
        strcat(prompt, cwd);
        strcat(prompt, sig);
        strcat(prompt, " ");
        int n;
        if (tty) {
            n = read_line_edited(g_line, sizeof(g_line), prompt);
        } else {
            printf("%s", prompt);
            n = read_line(g_line, sizeof(g_line));
        }
        if (n == -2) { if (!tty) printf("\n"); break; }
        if (n <= 0) continue;
        hist_add(g_line);
        run_line(g_line);
    }
    return 0;
}
