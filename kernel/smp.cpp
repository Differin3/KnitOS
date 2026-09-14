// SMP: подъём дополнительных ядер (AP) через LAPIC + INIT-SIPI.
#include "smp.h"
#include "serial_log.h"
#include "mm/paging.h"
#include "drivers/power/acpi.h"
#include "drivers/timer/pit.h"
#include "heap.h"

#define TRAMPOLINE_ADDR 0x8000u
#define SMP_MAX_CPUS    8
#define SMP_STACK_SIZE  16384

/* Фиксированные смещения внутри трамполина (совпадают с boot/trampoline.asm). */
#define TRAMP_GDTR_BASE_OFF 0x42   /* dd base внутри gdtr (gdtr в 0x40) */
#define TRAMP_CR3_OFF       0xA0
#define TRAMP_STACK_OFF     0xA4
#define TRAMP_ENTRY_OFF     0xA8
#define TRAMP_GDT_OFF       0x100

extern "C" {
    extern char trampoline_start[], trampoline_end[];
    extern void ap_entry(void);
}

struct cpu_state {
    int      online;
    uint8_t  apic_id;
    uint8_t* stack;
};

static struct cpu_state g_cpus[SMP_MAX_CPUS];
static volatile int    g_online = 1;   /* BSP уже в сети */
static uint32_t        g_lapic = 0;

/* --- LAPIC MMIO --- */
static uint32_t lapic_read(uint32_t reg) {
    return *(volatile uint32_t*)(g_lapic + reg);
}
static void lapic_write(uint32_t reg, uint32_t val) {
    *(volatile uint32_t*)(g_lapic + reg) = val;
}

/* База локального APIC из MSR IA32_APIC_BASE (0x1B). */
static uint32_t apic_base_msr(void) {
    uint32_t eax = 0, edx = 0;
    asm volatile ("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0x1B));
    return eax & 0xFFFFF000u;
}

/* APIC ID текущего ядра. */
static uint8_t bsp_apic_id(void) {
    return (uint8_t)(lapic_read(0x20) >> 24);
}

/* Короткая занятая задержка (~миллисекунды). На этом этапе sti ещё нет,
   поэтому timer_delay_ms (hlt) использовать нельзя. */
static void smp_pause(void) {
    for (volatile int i = 0; i < 300000; i++) { }
}

/* INIT-SIPI одному AP по его apic_id. */
static void send_ipi_init_sipi(uint8_t apic_id) {
    uint32_t icr_hi = (uint32_t)apic_id << 24;

    /* INIT assert */
    lapic_write(0x310, icr_hi);
    lapic_write(0x300, 0x0000C500);
    smp_pause();

    /* INIT deassert */
    lapic_write(0x300, 0x00008500);
    smp_pause();

    /* SIPI (дважды — надёжнее). */
    for (int i = 0; i < 2; i++) {
        lapic_write(0x310, icr_hi);
        lapic_write(0x300, 0x00000608);
        smp_pause();
    }
}

/* Точка входа AP: вызывается из трамполина уже в protected mode c
   включённым пейджингом. Здесь мы пока только сигнализируем о запуске. */
extern "C" void ap_entry(void) {
    g_online++;
    log_u32(LOG_INFO, "smp", "ap up", (uint32_t)g_online, 0, 0);
    /* Дальше — заглушка: спим до этапа 3 (scheduler SMP). */
    for (;;) asm volatile ("hlt");
}

int smp_cpu_count(void) {
    return g_online;
}

void smp_init(void) {
    uint32_t ncpu = acpi_cpu_count();
    if (ncpu <= 1) return;

    uint32_t base = apic_base_msr();
    if (!base) base = acpi_lapic_base();
    if (!base) return;
    g_lapic = base;
    paging_map_physical(base, 0x1000);

    /* Включаем LAPIC (spurious-вектор + software enable). */
    lapic_write(0xF0, lapic_read(0xF0) | 0x100);

    /* Копируем трамполин в низкую память. */
    uint32_t tsize = (uint32_t)(uintptr_t)trampoline_end - (uint32_t)(uintptr_t)trampoline_start;
    for (uint32_t i = 0; i < tsize; i++)
        ((volatile uint8_t*)TRAMPOLINE_ADDR)[i] = ((volatile uint8_t*)trampoline_start)[i];

    /* Заполняем слоты данных трамполина. */
    *(volatile uint32_t*)(TRAMPOLINE_ADDR + TRAMP_GDTR_BASE_OFF) = TRAMPOLINE_ADDR + TRAMP_GDT_OFF;
    *(volatile uint32_t*)(TRAMPOLINE_ADDR + TRAMP_CR3_OFF)   = paging_kernel_cr3();
    *(volatile uint32_t*)(TRAMPOLINE_ADDR + TRAMP_ENTRY_OFF) = (uint32_t)(uintptr_t)&ap_entry;

    /* Поднимаем AP. */
    int ap_index = 0;
    uint8_t bsp_id = bsp_apic_id();
    for (uint32_t i = 0; i < acpi_apic_id_count(); i++) {
        uint8_t apic_id = acpi_apic_id(i);
        if (apic_id == bsp_id) continue;
        if (ap_index >= SMP_MAX_CPUS) break;

        uint8_t* stack = (uint8_t*)malloc(SMP_STACK_SIZE);
        if (!stack) continue;
        *(volatile uint32_t*)(TRAMPOLINE_ADDR + TRAMP_STACK_OFF) =
            (uint32_t)(uintptr_t)(stack + SMP_STACK_SIZE);

        g_cpus[ap_index].apic_id = apic_id;
        g_cpus[ap_index].stack = stack;
        g_cpus[ap_index].online = 0;
        send_ipi_init_sipi(apic_id);
        ap_index++;
    }

    /* Ждём, пока AP'ы подадут признаки жизни (busy-wait: прерывания ещё off). */
    for (volatile int t = 0; t < 6000 && g_online < (int)ncpu; t++) smp_pause();

    log_u32(LOG_INFO, "smp", "cpus online", (uint32_t)g_online, ncpu, base);
}
