#ifndef KERNEL_SERVICE_H
#define KERNEL_SERVICE_H

#include <stdint.h>
#include <stddef.h>

#define SERVICE_MAX 8

/* Состояния сервиса. */
#define SVC_STOPPED 0
#define SVC_RUNNING 1
#define SVC_FAILED  2

/* Регистрирует сервис (вызывается при загрузке, после установки /tmp/*.elf). */
void service_register(const char* name, const char* desc,
                      const uint8_t* elf, size_t len, uint16_t uid,
                      int autostart, int restart);

/* Запускает autostart-сервисы и создаёт супервизор. */
void service_init(void);

/* Управление. Возвращают 0 при успехе, <0 при ошибке. */
int service_start(const char* name);
int service_stop(const char* name);
int service_restart(const char* name);
int service_set_enabled(const char* name, int en);

/* Периодическая проверка (вызывает супервизор): перезапуск упавших. */
void service_supervise(void);

/* Интроспекция для команд. */
int service_count(void);
int service_get(int idx, const char** name, const char** desc,
                int* state, int* pid, int* restarts, int* enabled);

/* Сохранение/загрузка состояния enable в /etc/systemd.conf. */
void service_load_config(void);
void service_save_config(void);

#endif
