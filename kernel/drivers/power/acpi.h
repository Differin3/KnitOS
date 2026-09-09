#ifndef ACPI_H
#define ACPI_H

#include <stdint.h>
#include <stdbool.h>

/* Инициализация ACPI: поиск RSDP, разбор RSDT/XSDT, FADT, DSDT (_S5). */
bool acpi_init(void);

/* Доступен хоть какой-то механизм ACPI (S5 и/или reset). */
bool acpi_available(void);

/* S5 (power off) через PM1a/PM1b_CNT. */
bool acpi_pm1_supported(void);
uint16_t acpi_pm1a_cnt_blk(void);
uint16_t acpi_s5_slp_typa(void);

/* ACPI Reset register из FADT. */
bool acpi_reset_supported(void);
bool acpi_reset_is_memory(void);
uint32_t acpi_reset_address(void);
uint8_t acpi_reset_value(void);

/*
 * Выполняет команду S5 shutdown. Возвращается только если система
 * не смогла/не успела выключиться (тогда можно пробовать fallback-порты).
 */
void acpi_power_off(void);

/*
 * Выполняет reset через ACPI Reset register. Возвращается только если
 * регистр отсутствует/недоступен (имеет смысл откатиться на KBC/0xCF9).
 */
void acpi_reboot(void);

#endif