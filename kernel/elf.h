#ifndef KERNEL_ELF_H
#define KERNEL_ELF_H

#include <stdint.h>
#include <stddef.h>

/* Минимальный адрес для пользовательского кода. Ядро с .bss занимает до
   ~5.7MB, поэтому user-образы грузим с 8MB, чтобы не затирать ядро. */
#define ELF_USER_VA_MIN  0x00800000u

/* Максимальный пользовательский адрес (конец стека последнего слота). */
#define ELF_USER_VA_MAX  0x05000000u

/* Валидация образа ELF32 (ET_EXEC, i386, LE). 0 = ok. */
int elf32_validate(const uint8_t* img, size_t len);

/*
 * Загрузка ELF32 в identity-адресное пространство:
 * копирует PT_LOAD по p_vaddr (>= ELF_USER_VA_MIN), обнуляет BSS (p_memsz).
 * Возвращает 0 и entry point в *out_entry.
 */
int elf32_load(const uint8_t* img, size_t len, uint32_t* out_entry);

/* Диапазон [lo,hi+memsz) всех PT_LOAD сегментов образа для пометки PDE_USER. */
int elf32_user_ranges(const uint8_t* img, size_t len, uint32_t* lo_out, uint32_t* hi_out);

#endif