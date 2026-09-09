#ifndef USER_AUTOTEST_H
#define USER_AUTOTEST_H

/* Ring3 user-space + privilege-level autotest: real page isolation (PDE_USER),
 * per-task uid (getuid/setuid/chown), user buffer hygiene via embedded ring3
 * demos (files, stdin, crashing kill). Emits [AUTOTEST]/[INF][autotest] markers.
 * Returns 0 on success. */
int user_autotest_run(void);

#endif