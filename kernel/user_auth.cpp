#include "user_auth.h"
#include "fs.h"
#include "string.h"
#include "drivers/timer/pit.h"
#include "serial_log.h"
#include <stddef.h>

#define PASSWD_PATH "/etc/passwd"
#define SHADOW_PATH "/etc/shadow"

static struct user_record g_users[UMAX_USERS];
static int g_user_count = 0;

static struct group_record g_groups[GMAX_GROUPS];
static int g_group_count = 0;
#define GROUP_PATH "/etc/group"

/* Теневая база: строки "name:salt|hash", линейно в памяти. */
#define SHADOW_BUF 4096
static char g_shadow[SHADOW_BUF];
static size_t g_shadow_len = 0;

/* ---- мелкие helper'ы ---- */

static void hex8(uint32_t v, char* out) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) {
        out[i] = hx[v & 0xF];
        v >>= 4;
    }
    out[8] = 0;
}

/* Псевдослучайная соль из таймера + счётчика. */
static void gen_salt(char* out) {
    static uint32_t counter = 0;
    uint32_t a = timer_ms() ^ (counter++ * 2654435761u);
    a ^= (a >> 13) * 2654435761u;
    hex8(a, out);
}

static uint32_t hash_password(const char* salt, const char* password) {
    /* FNV-1a по соли, затем по паролю. */
    uint32_t h = 2166136261u;
    size_t i = 0;
    while (salt[i]) { h ^= (uint32_t)(uint8_t)salt[i++]; h *= 16777619u; }
    i = 0;
    while (password[i]) { h ^= (uint32_t)(uint8_t)password[i++]; h *= 16777619u; }
    return h;
}

/* Соберём строку: name|salt|hash */
static size_t shadow_line(const char* name, const char* salt, uint32_t hash,
                          char* out, size_t cap) {
    size_t o = 0;
    char hs[9];
    hex8(hash, hs);
    size_t i;
    for (i = 0; name[i] && o + 1 < cap; i++) out[o++] = name[i];
    if (o + 1 < cap) out[o++] = '|';
    for (i = 0; salt[i] && o + 1 < cap; i++) out[o++] = salt[i];
    if (o + 1 < cap) out[o++] = '|';
    for (i = 0; hs[i] && o + 1 < cap; i++) out[o++] = hs[i];
    if (o < cap) out[o] = 0;
    return o;
}

static void clear_users(void) {
    for (int i = 0; i < UMAX_USERS; i++) {
        memset(&g_users[i], 0, sizeof(struct user_record));
        g_users[i].valid = false;
    }
    g_user_count = 0;
    g_shadow[0] = 0;
    g_shadow_len = 0;
}

static const char* shadow_for(const char* name) {
    /* Ищем строку "name|..." в g_shadow. */
    size_t r = 0;
    while (r < g_shadow_len) {
        size_t line_start = r;
        while (r < g_shadow_len && g_shadow[r] != '\n') r++;
        size_t line_len = r - line_start;
        if (line_len && g_shadow[line_start] != '#') {
            /* name до '|' */
            size_t sep = 0;
            while (sep < line_len && g_shadow[line_start + sep] != '|') sep++;
            if (sep == strlen(name) &&
                strncmp(g_shadow + line_start, name, sep) == 0) {
                g_shadow[r] = 0; /* временно терминируем строку */
                const char* line = g_shadow + line_start;
                g_shadow[r] = '\n'; /* вернуть обратно */
                return line;
            }
        }
        if (r < g_shadow_len) r++;
    }
    return 0;
}

int users_count(void) { return g_user_count; }
const struct user_record* users_get(int i) {
    if (i < 0 || i >= g_user_count) return 0;
    return &g_users[i];
}
const struct user_record* user_by_name(const char* name) {
    if (!name) return 0;
    for (int i = 0; i < g_user_count; i++)
        if (g_users[i].valid && strcmp(g_users[i].name, name) == 0)
            return &g_users[i];
    return 0;
}
const struct user_record* user_by_uid(uint16_t uid) {
    for (int i = 0; i < g_user_count; i++)
        if (g_users[i].valid && g_users[i].uid == uid)
            return &g_users[i];
    return 0;
}
int user_find(const char* name, struct user_record* out) {
    const struct user_record* u = user_by_name(name);
    if (!u || !out) return -1;
    *out = *u;
    return 0;
}

uint16_t users_next_uid(void) {
    uint16_t best = 1000;
    for (int i = 0; i < g_user_count; i++)
        if (g_users[i].valid && g_users[i].uid >= best && g_users[i].uid < 65000)
            best = (uint16_t)(g_users[i].uid + 1);
    return best;
}

static int write_passwd_db(void) {
    char newpw[SHADOW_BUF];
    size_t total = 0;
    for (int i = 0; i < g_user_count; i++) {
        const struct user_record* pu = &g_users[i];
        if (!pu->valid) continue;
        size_t o = total;
        size_t k;
        for (k = 0; pu->name[k] && o + k + 1 < sizeof(newpw) - 1; k++) newpw[o++] = pu->name[k];
        if (o + 1 < sizeof(newpw)) newpw[o++] = ':';
        if (o + 1 < sizeof(newpw)) newpw[o++] = 'x';
        if (o + 1 < sizeof(newpw)) newpw[o++] = ':';
        { char t[8]; int tt = 0; uint32_t v = pu->uid; if (v==0) t[tt++]='0'; else { char tb[8]; int tc=0; while(v>0){tb[tc++]='0'+(v%10);v/=10;} while(tc>0)t[tt++]=tb[--tc]; } if (o+tt<sizeof(newpw)){ memcpy(newpw+o,t,tt); o+=tt; } }
        if (o + 1 < sizeof(newpw)) newpw[o++] = ':';
        { char t[8]; int tt = 0; uint32_t v = pu->gid; if (v==0) t[tt++]='0'; else { char tb[8]; int tc=0; while(v>0){tb[tc++]='0'+(v%10);v/=10;} while(tc>0)t[tt++]=tb[--tc]; } if (o+tt<sizeof(newpw)){ memcpy(newpw+o,t,tt); o+=tt; } }
        if (o + 1 < sizeof(newpw)) newpw[o++] = ':';
        for (k = 0; pu->name[k] && o + k + 1 < sizeof(newpw) - 1; k++) newpw[o++] = pu->name[k]; /* comment поля */
        if (o + 1 < sizeof(newpw)) newpw[o++] = ':';
        for (k = 0; pu->home[k] && o + k + 1 < sizeof(newpw) - 1; k++) newpw[o++] = pu->home[k];
        if (o + 1 < sizeof(newpw)) newpw[o++] = ':';
        for (k = 0; pu->shell[k] && o + k + 1 < sizeof(newpw) - 1; k++) newpw[o++] = pu->shell[k];
        if (o + k + 1 < sizeof(newpw)) newpw[o++] = '\n';
        total = o;
    }
    if (total < sizeof(newpw)) newpw[total] = 0;
    return fs_write(PASSWD_PATH, newpw, total);
}

int user_add(const char* name, uint16_t uid, uint16_t gid, const char* home) {
    if (!name || !name[0] || g_user_count >= UMAX_USERS) return -1;
    if (user_by_name(name)) return -1;
    int slot = g_user_count;
    struct user_record* u = &g_users[slot];
    memset(u, 0, sizeof(*u));
    strncpy(u->name, name, UNAME_MAX - 1);
    u->uid = uid ? uid : users_next_uid();
    u->gid = gid ? gid : u->uid;
    strncpy(u->home, home && home[0] ? home : "/home/", UHOME_MAX - 1);
    strncpy(u->shell, "/bin/sh", USHELL_MAX - 1);
    u->valid = true;
    u->shadow = false;

    g_user_count++;
    if (write_passwd_db() != 0) {
        g_user_count--;
        return -1;
    }
    return (int)u->uid;
}

int user_del(const char* name) {
    if (!name || !name[0]) return -1;
    if (strcmp(name, "root") == 0) return -1; /* root нельзя удалить */
    int slot = -1;
    for (int i = 0; i < g_user_count; i++)
        if (g_users[i].valid && strcmp(g_users[i].name, name) == 0) { slot = i; break; }
    if (slot < 0) return -1;
    /* убрать запись из shadow */
    {
        char tmp[SHADOW_BUF];
        size_t tn = 0;
        size_t r = 0;
        while (r < g_shadow_len) {
            size_t ls = r;
            while (r < g_shadow_len && g_shadow[r] != '\n') r++;
            size_t ln = r - ls;
            size_t sep = 0;
            while (sep < ln && g_shadow[ls + sep] != '|') sep++;
            bool target = (sep == strlen(name) && strncmp(g_shadow + ls, name, sep) == 0);
            if (!target && tn + ln + 1 < sizeof(tmp)) {
                memcpy(tmp + tn, g_shadow + ls, ln); tn += ln;
                if (tn < sizeof(tmp)) tmp[tn++] = '\n';
            }
            if (r < g_shadow_len) r++;
        }
        if (tn < sizeof(tmp)) tmp[tn] = 0;
        memcpy(g_shadow, tmp, tn);
        g_shadow_len = tn;
        fs_write(SHADOW_PATH, g_shadow, g_shadow_len);
    }
    /* сдвинуть массив */
    for (int i = slot; i < g_user_count - 1; i++) g_users[i] = g_users[i + 1];
    g_user_count--;
    return write_passwd_db();
}

int user_mod(const char* name, const char* newname, uint16_t uid, uint16_t gid, const char* home) {
    if (!name || !name[0]) return -1;
    struct user_record* u = 0;
    for (int i = 0; i < g_user_count; i++)
        if (g_users[i].valid && strcmp(g_users[i].name, name) == 0) { u = &g_users[i]; break; }
    if (!u) return -1;
    if (newname && newname[0]) {
        if (user_by_name(newname)) return -1;
        strncpy(u->name, newname, UNAME_MAX - 1);
    }
    if (uid) u->uid = uid;
    if (gid) u->gid = gid;
    if (home && home[0]) strncpy(u->home, home, UHOME_MAX - 1);
    return write_passwd_db();
}

static void write_shadow_file(void) {
    fs_write(SHADOW_PATH, g_shadow, g_shadow_len);
}

int user_set_password(const char* name, const char* password) {
    const struct user_record* u = user_by_name(name);
    if (!u) return -1;
    char salt[9];
    gen_salt(salt);
    uint32_t h = hash_password(salt, password);
    char line[UHASH_LEN + 48];
    size_t ll = shadow_line(name, salt, h, line, sizeof(line));

    /* Заменить или дописать строку в g_shadow. */
    char tmp[SHADOW_BUF];
    size_t tn = 0;
    size_t r = 0;
    while (r < g_shadow_len) {
        size_t ls = r;
        while (r < g_shadow_len && g_shadow[r] != '\n') r++;
        size_t ln = r - ls;
        bool is_target = true;
        size_t sep = 0;
        while (sep < ln && g_shadow[ls + sep] != '|') sep++;
        if (sep != strlen(name) || strncmp(g_shadow + ls, name, sep) != 0) is_target = false;
        if (is_target) {
            /* пропускаем старую, вставим новую ниже */
            if (r < g_shadow_len) r++;
            continue;
        }
        if (tn + ln + 1 < sizeof(tmp)) { memcpy(tmp + tn, g_shadow + ls, ln); tn += ln; if (tn < sizeof(tmp)) tmp[tn++] = '\n'; }
        if (r < g_shadow_len) r++;
    }
    if (tn + ll + 1 < sizeof(tmp)) { memcpy(tmp + tn, line, ll); tn += ll; if (tn < sizeof(tmp)) tmp[tn++] = '\n'; }
    if (tn >= sizeof(tmp)) tn = sizeof(tmp) - 1;
    tmp[tn] = 0;
    memcpy(g_shadow, tmp, tn);
    g_shadow_len = tn;
    write_shadow_file();

    /* отметим в памяти */
    for (int i = 0; i < g_user_count; i++)
        if (g_users[i].valid && strcmp(g_users[i].name, name) == 0)
            g_users[i].shadow = true;
    return 0;
}

bool user_check_password(const char* name, const char* password) {
    const struct user_record* u = user_by_name(name);
    if (!u) return false;
    const char* line = shadow_for(name);
    if (!line) {
        /* Нет записи в shadow → разрешён только ПУСТОЙ пароль (dev/root),
           иначе это обход авторизации любым паролем. */
        return (password == 0 || password[0] == 0);
    }
    /* line = name|salt|hash — пропускаем name| */
    size_t p = 0;
    while (line[p] && line[p] != '|') p++;
    if (line[p] != '|') return false;
    p++;
    char salt[9];
    size_t i = 0;
    while (line[p] && line[p] != '|' && i < 8) salt[i++] = line[p++];
    salt[i] = 0;
    if (line[p] != '|') return false;
    p++;
    char hash_hex[9];
    size_t h = 0;
    while (line[p] && line[p] != '|' && line[p] != '\n' && h < 8) hash_hex[h++] = line[p++];
    if (h == 0) return false;
    hash_hex[h] = 0;
    uint32_t want = 0;
    for (size_t k = 0; k < h; k++) {
        char c = hash_hex[k];
        want = (want << 4) | (uint32_t)(c <= '9' ? c - '0' : 10 + (c | 32) - 'a');
    }
    uint32_t got = hash_password(salt, password);
    return got == want;
}

static void create_default_users(void) {
    /* root: uid 0, без пароля (dev-режим) */
    char pw[SHADOW_BUF];
    size_t n = 0;
    const char* rootline =
        "root:x:0:0:root:/root:/bin/sh\n"
        "demo:x:1000:1000:demo:/home/demo:/bin/sh\n";
    size_t rl = strlen(rootline);
    memcpy(pw, rootline, rl);
    n = rl;

    fs_write(PASSWD_PATH, pw, n);

    /* demo с паролем "demo" */
    char salt[9];
    gen_salt(salt);
    uint32_t h = hash_password(salt, "demo");
    char line[UHASH_LEN + 48];
    size_t ll = shadow_line("demo", salt, h, line, sizeof(line));
    char sh[SHADOW_BUF];
    size_t sn = 0;
    memcpy(sh + sn, line, ll); sn += ll;
    sh[sn++] = '\n';
    sh[sn] = 0;
    fs_write(SHADOW_PATH, sh, sn);
}

int users_init(void) {
    clear_users();
    /* Также загружаем группы. */
    for (int i = 0; i < GMAX_GROUPS; i++) memset(&g_groups[i], 0, sizeof(struct group_record));
    g_group_count = 0;

    char pw[SHADOW_BUF];
    int pr = fs_read(PASSWD_PATH, pw, sizeof(pw) - 1);
    if (pr <= 0) {
        create_default_users();
        pr = fs_read(PASSWD_PATH, pw, sizeof(pw) - 1);
        if (pr <= 0) return -1;
    }
    pw[pr < (int)sizeof(pw) ? pr : (int)sizeof(pw) - 1] = 0;

    /* parse passwd — токенизация по ':' */
    size_t pos = 0;
    while (pos < (size_t)pr && g_user_count < UMAX_USERS) {
        size_t ls = pos;
        while (pos < (size_t)pr && pw[pos] != '\n') pos++;
        size_t ln = pos - ls;
        if (ln && pw[ls] != '#') {
            char fline[256];
            size_t fl = ln;
            if (fl >= sizeof(fline)) fl = sizeof(fline) - 1;
            memcpy(fline, pw + ls, fl);
            fline[fl] = 0;
            /* разбиваем по ':' */
            char* f[7];
            int nf = 0;
            char* p = fline;
            f[nf++] = p;
            while (*p && nf < 7) {
                if (*p == ':') { *p = 0; f[nf++] = p + 1; }
                p++;
            }
            if (nf >= 4) {
                char f2[UNAME_MAX], f4[UHOME_MAX], f5[USHELL_MAX];
                strncpy(f2, f[0], UNAME_MAX - 1); f2[UNAME_MAX - 1] = 0;
                /* Поддержка 7-полевого (name:x:uid:gid:comment:home:shell)
                   и 6-полевого (name:x:uid:gid:home:shell) формата. */
                int home_idx = 5, shell_idx = 6;
                if (nf == 6)      { home_idx = 4; shell_idx = 5; }
                else if (nf == 5) { home_idx = 4; shell_idx = -1; }
                strncpy(f4, (home_idx >= 0 && home_idx < nf) ? f[home_idx] : "/home/", UHOME_MAX - 1);
                f4[UHOME_MAX - 1] = 0;
                strncpy(f5, (shell_idx >= 0 && shell_idx < nf) ? f[shell_idx] : "/bin/sh", USHELL_MAX - 1);
                f5[USHELL_MAX - 1] = 0;
                uint16_t uid = 0, gid = 0;
                const char* us = f[2];
                while (*us >= '0' && *us <= '9') { uid = (uint16_t)(uid * 10 + (*us - '0')); us++; }
                us = f[3];
                while (*us >= '0' && *us <= '9') { gid = (uint16_t)(gid * 10 + (*us - '0')); us++; }
                struct user_record* u = &g_users[g_user_count];
                memset(u, 0, sizeof(*u));
                strncpy(u->name, f2, UNAME_MAX - 1);
                u->uid = uid; u->gid = gid;
                strncpy(u->home, f4, UHOME_MAX - 1);
                strncpy(u->shell, f5, USHELL_MAX - 1);
                u->valid = true;
                g_user_count++;
            }
        }
        if (pos < (size_t)pr) pos++;
    }

    /* load shadow */
    int sr = fs_read(SHADOW_PATH, g_shadow, sizeof(g_shadow) - 1);
    if (sr > 0) {
        g_shadow[sr < (int)sizeof(g_shadow) ? sr : (int)sizeof(g_shadow) - 1] = 0;
        g_shadow_len = (size_t)sr;
    } else {
        g_shadow[0] = 0;
        g_shadow_len = 0;
    }

    /* отметить наличие пароля */
    for (int i = 0; i < g_user_count; i++) {
        if (shadow_for(g_users[i].name)) g_users[i].shadow = true;
    }

    /* Создаём домашние каталоги пользователей (если ещё нет) и отдаём их владельцу. */
    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i].home[0]) {
            struct fs_stat st;
            if (fs_stat(g_users[i].home, &st) != 0) {
                fs_create_dir(g_users[i].home);
            }
            /* владелец home — сам пользователь (root может chown) */
            fs_chown(g_users[i].home, g_users[i].uid, g_users[i].gid);
        }
    }

    return g_user_count;
}

void user_auth_dump(void) {
    extern void terminal_writestring(const char*);
    extern void terminal_putchar(char);
    char num[12];
    int n;
    terminal_writestring("\n[USERS] count=");
    n = g_user_count;
    int np = 0;
    if (n == 0) num[np++] = '0';
    else { char tmp[12]; int t = 0; while (n > 0 && t < 11) { tmp[t++] = '0' + (n % 10); n /= 10; } while (t > 0) num[np++] = tmp[--t]; }
    num[np] = 0;
    terminal_writestring(num);
    for (int i = 0; i < g_user_count; i++) {
        terminal_writestring("\n  ");
        terminal_writestring(g_users[i].name);
        terminal_writestring(" uid=");
        int v = g_users[i].uid;
        np = 0;
        if (v == 0) num[np++] = '0';
        else { char tmp[12]; int t = 0; while (v > 0 && t < 11) { tmp[t++] = '0' + (v % 10); v /= 10; } while (t > 0) num[np++] = tmp[--t]; }
        num[np] = 0;
        terminal_writestring(num);
        terminal_writestring(" home=");
        terminal_writestring(g_users[i].home);
        terminal_writestring(g_users[i].shadow ? " [pw]" : " [nopw]");
    }
    (void)terminal_putchar;
}

/* ---- Группы (/etc/group = name:gid:members) ---- */

static int write_group_db(void) {
    char out[SHADOW_BUF];
    size_t total = 0;
    for (int i = 0; i < g_group_count; i++) {
        const struct group_record* g = &g_groups[i];
        if (!g->valid) continue;
        size_t o = total, k;
        for (k = 0; g->name[k] && o + k + 1 < sizeof(out) - 1; k++) out[o++] = g->name[k];
        if (o + 1 < sizeof(out)) out[o++] = ':';
        { char t[8]; int tt = 0; uint32_t v = g->gid; if (v==0) t[tt++]='0'; else { char tb[8]; int tc=0; while(v>0){tb[tc++]='0'+(v%10);v/=10;} while(tc>0)t[tt++]=tb[--tc]; } if (o+tt<sizeof(out)){ memcpy(out+o,t,tt); o+=tt; } }
        if (o + 1 < sizeof(out)) out[o++] = ':';
        for (k = 0; g->members[k] && o + k + 1 < sizeof(out) - 1; k++) out[o++] = g->members[k];
        if (o + k + 1 < sizeof(out)) out[o++] = '\n';
        total = o;
    }
    if (total < sizeof(out)) out[total] = 0;
    return fs_write(GROUP_PATH, out, total);
}

static void create_default_groups(void) {
    const char* data =
        "root:0:root\n"
        "demo:1000:demo\n";
    fs_write(GROUP_PATH, data, strlen(data));
}

int groups_init(void) {
    for (int i = 0; i < GMAX_GROUPS; i++) memset(&g_groups[i], 0, sizeof(struct group_record));
    g_group_count = 0;
    char buf[SHADOW_BUF];
    int r = fs_read(GROUP_PATH, buf, sizeof(buf) - 1);
    if (r <= 0) {
        create_default_groups();
        r = fs_read(GROUP_PATH, buf, sizeof(buf) - 1);
        if (r <= 0) return -1;
    }
    buf[r < (int)sizeof(buf) ? r : (int)sizeof(buf) - 1] = 0;
    size_t pos = 0;
    while (pos < (size_t)r && g_group_count < GMAX_GROUPS) {
        size_t ls = pos;
        while (pos < (size_t)r && buf[pos] != '\n') pos++;
        size_t ln = pos - ls;
        if (ln && buf[ls] != '#') {
            char line[128];
            size_t fl = ln;
            if (fl >= sizeof(line)) fl = sizeof(line) - 1;
            memcpy(line, buf + ls, fl);
            line[fl] = 0;
            char* f[3];
            int nf = 0;
            char* p = line;
            f[nf++] = p;
            while (*p && nf < 3) { if (*p == ':') { *p = 0; f[nf++] = p + 1; } p++; }
            if (nf >= 2) {
                struct group_record* g = &g_groups[g_group_count];
                strncpy(g->name, f[0], GNAME_MAX - 1);
                uint16_t gid = 0;
                const char* us = f[1];
                while (*us >= '0' && *us <= '9') { gid = (uint16_t)(gid * 10 + (*us - '0')); us++; }
                g->gid = gid;
                if (nf >= 3) strncpy(g->members, f[2], sizeof(g->members) - 1);
                g->valid = true;
                g_group_count++;
            }
        }
        if (pos < (size_t)r) pos++;
    }
    return g_group_count;
}

int groups_count(void) { return g_group_count; }
const struct group_record* groups_get(int i) {
    if (i < 0 || i >= g_group_count) return 0;
    return &g_groups[i];
}
const struct group_record* group_by_gid(uint16_t gid) {
    for (int i = 0; i < g_group_count; i++)
        if (g_groups[i].valid && g_groups[i].gid == gid) return &g_groups[i];
    return 0;
}
const struct group_record* group_by_name(const char* name) {
    for (int i = 0; i < g_group_count; i++)
        if (g_groups[i].valid && strcmp(g_groups[i].name, name) == 0) return &g_groups[i];
    return 0;
}
uint16_t groups_next_gid(void) {
    uint16_t best = 1000;
    for (int i = 0; i < g_group_count; i++)
        if (g_groups[i].valid && g_groups[i].gid >= best && g_groups[i].gid < 65000)
            best = (uint16_t)(g_groups[i].gid + 1);
    return best;
}
const char* gid_to_group_name(uint16_t gid) {
    const struct group_record* g = group_by_gid(gid);
    return g ? g->name : 0;
}
int group_add(const char* name, uint16_t gid) {
    if (!name || !name[0] || g_group_count >= GMAX_GROUPS) return -1;
    if (group_by_name(name)) return -1;
    struct group_record* g = &g_groups[g_group_count];
    memset(g, 0, sizeof(*g));
    strncpy(g->name, name, GNAME_MAX - 1);
    g->gid = gid ? gid : groups_next_gid();
    g->valid = true;
    g_group_count++;
    return write_group_db();
}
