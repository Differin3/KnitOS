#ifndef FTP_SERVER_H
#define FTP_SERVER_H

#include <stdint.h>

/* Запустить FTP-сервер (control на port, PASV для данных).
   Возвращает tid kthread или -1. */
int ftp_server_start(uint16_t port, int accept_timeout_ms);
void ftp_server_stop(void);
int ftp_server_running(void);

#endif
