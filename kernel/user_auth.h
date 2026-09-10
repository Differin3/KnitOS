#ifndef USER_AUTH_H
#define USER_AUTH_H

#include <stdint.h>
#include <stdbool.h>

#define UMAX_USERS   16
#define UNAME_MAX    32
#define UHOME_MAX    64
#define USHELL_MAX   32
#define UHASH_LEN    17    /* 8 hex salt + '|' + 8 hex hash + NUL */

#define GNAME_MAX    32
#define GMAX_GROUPS  16

struct user_record {
    char name[UNAME_MAX];
    uint16_t uid;
    uint16_t gid;
    char home[UHOME_MAX];
    char shell[USHELL_MAX];
    bool valid;
    bool shadow;         /* есть запись в /etc/shadow (пароль задан) */
};

struct group_record {
    char name[GNAME_MAX];
    uint16_t gid;
    char members[UNAME_MAX * 6]; /* csv список участников */
    bool valid;
};

int  users_init(void);                    /* загрузить passwd/shadow, создать default если нет */
int  users_count(void);
const struct user_record* users_get(int i);
const struct user_record* user_by_name(const char* name);
const struct user_record* user_by_uid(uint16_t uid);
int  user_find(const char* name, struct user_record* out);

int  user_add(const char* name, uint16_t uid, uint16_t gid, const char* home);
int  user_set_password(const char* name, const char* password);
bool user_check_password(const char* name, const char* password);
uint16_t users_next_uid(void);
/* Удалить пользователя (из passwd/shadow и списка). Роут/группа-членства. */
int  user_del(const char* name);
/* Изменить пользователя: новые имя/uid/gid/home (0 = не менять). */
int  user_mod(const char* name, const char* newname, uint16_t uid, uint16_t gid, const char* home);

int  groups_init(void);                    /* загрузить /etc/group */
int  groups_count(void);
const struct group_record* groups_get(int i);
const struct group_record* group_by_gid(uint16_t gid);
const struct group_record* group_by_name(const char* name);
int  group_add(const char* name, uint16_t gid);
uint16_t groups_next_gid(void);
const char* gid_to_group_name(uint16_t gid);

/* Отладка: печать базы пользователей (список + uid/home/пароль-флаг). */
void user_auth_dump(void);

#endif
