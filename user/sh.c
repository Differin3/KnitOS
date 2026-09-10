// M4: minimal user-space shell (fork/exec/wait/pipe over the syscall ABI).
#include "lib/libk.h"

#define LMAX 256
#define AMAX 16

static char g_line[LMAX];
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
        printf("uid=%d gid=%d\n", (int)sys_getuid(), (int)sys_getgid());
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
        if (!argv[1]) { printf("cat: usage: cat <file>\n"); return; }
        int fd = (int)sys_open(argv[1], O_RDONLY, 0);
        if (fd < 0) { printf("cat: %s: no such file\n", argv[1]); return; }
        char buf[512];
        long n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) sys_write(1, buf, (unsigned long)n);
        sys_close(fd);
    } else if (!strcmp(argv[0], "help")) {
        printf("builtins: cd pwd ls cat echo id exit help\n");
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

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    for (;;) {
        char cwd[128];
        if (sys_getcwd(cwd, sizeof(cwd)) < 0) cwd[0] = 0;
        const char* who = sys_getuid() == 0 ? "root" : "user";
        const char* sig = sys_getuid() == 0 ? "#" : "$";
        printf("%s@knitos:%s%s ", who, cwd, sig);
        int n = read_line(g_line, sizeof(g_line));
        if (n == -2) { printf("\n"); break; }
        if (n <= 0) continue;
        int na = tokenize(g_line, g_argv, AMAX);
        if (na == 0) continue;

        int pipe_at = -1;
        for (int i = 0; i < na; i++) {
            if (!strcmp(g_argv[i], "|")) { pipe_at = i; break; }
        }
        if (pipe_at > 0 && pipe_at < na - 1) {
            g_argv[pipe_at] = 0;
            char** left = g_argv;
            char** right = &g_argv[pipe_at + 1];
            int fds[2];
            if (sys_pipe(fds) < 0) { printf("sh: pipe failed\n"); continue; }
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
            continue;
        }

        int handled = 0;
        run_builtin(g_argv, &handled);
        if (!handled) {
            long pid = sys_fork();
            if (pid == 0) run_exec(g_argv);
            if (pid > 0) { int st; sys_waitpid((int)pid, &st); }
            else printf("sh: fork failed\n");
        }
    }
    return 0;
}
