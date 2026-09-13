#ifndef MM_PAGING_H
#define MM_PAGING_H

#include <stdint.h>

void paging_init(void);
void paging_load_cr3(uint32_t cr3);
uint32_t paging_kernel_cr3(void);
int paging_enabled(void);

/* Map physical MMIO/FB range into kernel page directory (4MB PSE). */
void paging_map_physical(uint32_t phys, uint32_t bytes);

/* Private identity-mapped page directories (PSE 4MB). Returns phys addr of PDE or 0. */
uint32_t paging_create_identity_dir(void);
uint32_t paging_clone_dir(uint32_t src_cr3);
/* Глубокий клон: user-PDE копируются в новые физические 4MB-кадры
   (неидентичное отображение), чтобы процессы не делили память. */
uint32_t paging_clone_dir_deep(uint32_t src_cr3);
/* Освобождает физические кадры всех user-PDE (для exec/выхода). */
void paging_free_user_frames(uint32_t cr3);
void paging_free_dir(uint32_t cr3);

/* Пометить один 4MB PDE как user-доступный в указанном каталоге (для сегментов
   конкретного ring3-процесса и его стека). */
void paging_mark_user_pde(uint32_t cr3, uint32_t pde_index);
void paging_clear_user_pde(uint32_t cr3, uint32_t pde_index);

/* Сделать user-PDE приватным: скопировать текущее (identity) содержимое
   4MB-страницы в новый физический кадр и перенаправить PDE на него.
   Нужно, чтобы несколько user-приложений не делили один и тот же код/данные
   по адресу 0x800000. Возвращает 0 при успехе. */
int paging_privatize_user_pde(uint32_t cr3, uint32_t pde_index);

/* Test helpers: unmap/remap one 4MB PDE in a given dir (not kernel dir preferred). */
void paging_unmap_pde(uint32_t cr3, uint32_t pde_index);
int paging_pde_present(uint32_t cr3, uint32_t pde_index);

/* Identity-map smoke + intentional #PF recovery. Returns 0 on success. */
int paging_autotest(void);

/* Flat GDT + user segments; iret to stub; syscall back. Returns 0 ok. */
int paging_ring3_autotest(void);

/* TSS.esp0 для входа ring3->ring0 через syscall/IRQ (стек ядра задачи). */
void paging_set_user_esp0(uint32_t esp0);

/* Установка GDT с user-сегментами + TSS (+ пере-инициализация IDT под новые сегменты). */
void paging_setup_user_mode(void);

/* Per-task aspace isolation smoke. Returns 0 on success. */
int paging_aspace_autotest(void);

extern "C" void page_fault_handler_main(uint32_t error_code);
extern "C" void paging_ring3_finish(void);

#endif
