#include "mm/paging.h"
#include "serial_log.h"
#include "idt.h"
#include "sched/task.h"
#include <stddef.h>

#define PDE_PRESENT  0x001
#define PDE_RW       0x002
#define PDE_USER     0x004
#define PDE_PSE      0x080

#define PAGE_DIR_ENTRIES 1024
#define IDENTITY_MB      128
#define FAULT_PDE        15   /* 60MB — left unmapped until #PF */

static uint32_t g_page_dir[PAGE_DIR_ENTRIES] __attribute__((aligned(4096)));
static uint32_t g_kernel_cr3 = 0;
static int g_paging_on = 0;
static volatile uint32_t g_pf_count = 0;
static volatile uint32_t g_ring3_flag = 0;

#define PAGING_ASDIR_MAX 8
static uint32_t g_asdirs[PAGING_ASDIR_MAX][PAGE_DIR_ENTRIES] __attribute__((aligned(4096)));
static uint8_t g_asdir_used[PAGING_ASDIR_MAX];

static uint32_t g_ring3_cont_esp = 0;
static uint32_t g_ring3_cont_eip = 0;

static void paging_fill_identity(uint32_t* dir, int skip_fault_pde) {
    for (int i = 0; i < PAGE_DIR_ENTRIES; i++) dir[i] = 0;
    for (int i = 0; i < (IDENTITY_MB / 4); i++) {
        if (skip_fault_pde && i == FAULT_PDE) continue;
        uint32_t addr = (uint32_t)i * 0x400000u;
        dir[i] = addr | PDE_PRESENT | PDE_RW | PDE_PSE | PDE_USER;
    }
}

static uint32_t* paging_dir_ptr(uint32_t cr3) {
    if (!cr3) cr3 = g_kernel_cr3;
    return (uint32_t*)(cr3 & ~0xFFFu);
}

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t gran;
    uint8_t base_high;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

struct tss_entry {
    uint32_t prev;
    uint32_t esp0;
    uint32_t ss0;
    uint32_t unused[23];
} __attribute__((packed));

static struct gdt_entry g_gdt[6];
static struct gdt_ptr g_gp;
static struct tss_entry g_tss;
static uint8_t g_user_stack[4096] __attribute__((aligned(16)));
static uint8_t g_kernel_irq_stack[4096] __attribute__((aligned(16)));

static void gdt_set(int num, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    g_gdt[num].base_low = (uint16_t)(base & 0xFFFF);
    g_gdt[num].base_mid = (uint8_t)((base >> 16) & 0xFF);
    g_gdt[num].base_high = (uint8_t)((base >> 24) & 0xFF);
    g_gdt[num].limit_low = (uint16_t)(limit & 0xFFFF);
    g_gdt[num].gran = (uint8_t)((limit >> 16) & 0x0F);
    g_gdt[num].gran |= (uint8_t)(gran & 0xF0);
    g_gdt[num].access = access;
}

static void gdt_install(void) {
    g_gp.limit = (uint16_t)(sizeof(g_gdt) - 1);
    g_gp.base = (uint32_t)&g_gdt;

    gdt_set(0, 0, 0, 0, 0);
    gdt_set(1, 0, 0xFFFFF, 0x9A, 0xCF); /* kernel code 0x08 */
    gdt_set(2, 0, 0xFFFFF, 0x92, 0xCF); /* kernel data 0x10 */
    gdt_set(3, 0, 0xFFFFF, 0xFA, 0xCF); /* user code 0x18 */
    gdt_set(4, 0, 0xFFFFF, 0xF2, 0xCF); /* user data 0x20 */

    for (unsigned i = 0; i < sizeof(g_tss) / 4; i++) ((uint32_t*)&g_tss)[i] = 0;
    g_tss.ss0 = 0x10;
    g_tss.esp0 = (uint32_t)(g_kernel_irq_stack + sizeof(g_kernel_irq_stack));
    gdt_set(5, (uint32_t)&g_tss, sizeof(g_tss) - 1, 0x89, 0x00); /* TSS 0x28 */

    asm volatile ("lgdt %0" : : "m"(g_gp));
    asm volatile (
        "mov $0x10, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%ax, %%ss\n"
        "ljmp $0x08, $1f\n"
        "1:\n"
        "mov $0x28, %%ax\n"
        "ltr %%ax\n"
        : : : "ax", "memory"
    );

    /* IDT selectors must match new GDT (kernel code = 0x08) */
    idt_init();
}

void paging_load_cr3(uint32_t cr3) {
    if (!cr3) cr3 = g_kernel_cr3;
    if (!cr3) return;
    asm volatile ("mov %0, %%cr3" : : "r"(cr3) : "memory");
}

void paging_set_user_esp0(uint32_t esp0) {
    g_tss.esp0 = esp0;
}

void paging_setup_user_mode(void) {
    gdt_install();
}

uint32_t paging_kernel_cr3(void) {
    return g_kernel_cr3;
}

int paging_enabled(void) {
    return g_paging_on;
}

void paging_init(void) {
    if (g_paging_on) return;

    for (int i = 0; i < PAGING_ASDIR_MAX; i++) g_asdir_used[i] = 0;
    paging_fill_identity(g_page_dir, 1);

    g_kernel_cr3 = (uint32_t)&g_page_dir;

    uint32_t cr4;
    asm volatile ("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 0x10; /* PSE */
    asm volatile ("mov %0, %%cr4" : : "r"(cr4));

    asm volatile ("mov %0, %%cr3" : : "r"(g_kernel_cr3) : "memory");

    uint32_t cr0;
    asm volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000u; /* PG */
    asm volatile ("mov %0, %%cr0" : : "r"(cr0) : "memory");

    g_paging_on = 1;
    log_msg(LOG_INFO, "mm", "paging on");
}

void paging_map_physical(uint32_t phys, uint32_t bytes) {
    if (!g_paging_on || bytes == 0) return;
    uint32_t start = phys & ~0x3FFFFFu;
    uint32_t end = (phys + bytes + 0x3FFFFFu) & ~0x3FFFFFu;
    for (uint32_t addr = start; addr < end; addr += 0x400000u) {
        uint32_t pde = addr >> 22;
        if (pde >= PAGE_DIR_ENTRIES) break;
        g_page_dir[pde] = addr | PDE_PRESENT | PDE_RW | PDE_PSE | PDE_USER;
        /* В user-каталогах MMIO/FB — supervisor (без PDE_USER), чтобы ring3 не
           могло дотянуться до видеопамяти и контроллеров напрямую. */
        for (int i = 0; i < PAGING_ASDIR_MAX; i++) {
            if (!g_asdir_used[i]) continue;
            g_asdirs[i][pde] = addr | PDE_PRESENT | PDE_RW | PDE_PSE;
        }
    }
    asm volatile ("mov %0, %%cr3" : : "r"(g_kernel_cr3) : "memory");
}

void paging_mark_user_pde(uint32_t cr3, uint32_t pde_index) {
    uint32_t* dir = paging_dir_ptr(cr3);
    if (!dir || pde_index >= PAGE_DIR_ENTRIES) return;
    dir[pde_index] |= PDE_USER;
}

void paging_clear_user_pde(uint32_t cr3, uint32_t pde_index) {
    uint32_t* dir = paging_dir_ptr(cr3);
    if (!dir || pde_index >= PAGE_DIR_ENTRIES) return;
    dir[pde_index] &= ~(uint32_t)PDE_USER;
}

static void paging_fill_supervisor(uint32_t* dir) {
    for (int i = 0; i < PAGE_DIR_ENTRIES; i++) dir[i] = 0;
    for (int i = 0; i < (IDENTITY_MB / 4); i++) {
        uint32_t addr = (uint32_t)i * 0x400000u;
        /* Без PDE_USER: ring3 не может читать/писать ядро, VGA и буферы. */
        dir[i] = addr | PDE_PRESENT | PDE_RW | PDE_PSE;
    }
}

uint32_t paging_create_identity_dir(void) {
    if (!g_paging_on) paging_init();
    for (int i = 0; i < PAGING_ASDIR_MAX; i++) {
        if (g_asdir_used[i]) continue;
        g_asdir_used[i] = 1;
        /* Пользовательский каталог: все страницы supervisor. Только сегменты
           конкретной программы и её стек помечаются PDE_USER отдельно. */
        paging_fill_supervisor(g_asdirs[i]);
        for (int p = (IDENTITY_MB / 4); p < PAGE_DIR_ENTRIES; p++) {
            g_asdirs[i][p] = g_page_dir[p] & ~(uint32_t)PDE_USER;
        }
        return (uint32_t)&g_asdirs[i][0];
    }
    return 0;
}

uint32_t paging_clone_dir(uint32_t src_cr3) {
    uint32_t* src = paging_dir_ptr(src_cr3);
    if (!src) return 0;
    uint32_t dst_cr3 = paging_create_identity_dir();
    if (!dst_cr3) return 0;
    uint32_t* dst = paging_dir_ptr(dst_cr3);
    for (int i = 0; i < PAGE_DIR_ENTRIES; i++) dst[i] = src[i];
    return dst_cr3;
}

/* Пул физических 4MB-кадров для deep-copy fork: [80MB, 128MB). */
#define FORK_FRAME_BASE   0x05000000u
#define FORK_FRAME_END    0x08000000u
#define FORK_FRAME_SIZE   0x00400000u
#define FORK_FRAME_COUNT  ((FORK_FRAME_END - FORK_FRAME_BASE) / FORK_FRAME_SIZE)
static uint8_t g_fork_frames[FORK_FRAME_COUNT];
static uint32_t g_fork_frame_next = 0;

static uint32_t fork_frame_alloc(void) {
    for (uint32_t i = 0; i < FORK_FRAME_COUNT; i++) {
        uint32_t idx = (g_fork_frame_next + i) % FORK_FRAME_COUNT;
        if (!g_fork_frames[idx]) {
            g_fork_frames[idx] = 1;
            g_fork_frame_next = (idx + 1) % FORK_FRAME_COUNT;
            return FORK_FRAME_BASE + idx * FORK_FRAME_SIZE;
        }
    }
    return 0;
}

static int fork_frame_is_pool(uint32_t phys) {
    return phys >= FORK_FRAME_BASE && phys < FORK_FRAME_END;
}

static void fork_frame_free(uint32_t phys) {
    if (!fork_frame_is_pool(phys)) return;
    g_fork_frames[(phys - FORK_FRAME_BASE) / FORK_FRAME_SIZE] = 0;
}

uint32_t paging_clone_dir_deep(uint32_t src_cr3) {
    uint32_t* src = paging_dir_ptr(src_cr3);
    if (!src) return 0;
    uint32_t dst_cr3 = paging_create_identity_dir();
    if (!dst_cr3) return 0;
    uint32_t* dst = paging_dir_ptr(dst_cr3);
    for (int i = 0; i < PAGE_DIR_ENTRIES; i++) {
        uint32_t e = src[i];
        if (!(e & PDE_PRESENT) || !(e & PDE_USER) || !(e & PDE_PSE)) {
            dst[i] = e;
            continue;
        }
        uint32_t phys = fork_frame_alloc();
        if (!phys) {
            paging_free_dir(dst_cr3);
            return 0;
        }
        const uint8_t* s = (const uint8_t*)(e & 0xFFC00000u);
        uint8_t* d = (uint8_t*)phys;
        for (uint32_t k = 0; k < FORK_FRAME_SIZE; k++) d[k] = s[k];
        dst[i] = phys | (e & 0xFFFu);
    }
    return dst_cr3;
}

void paging_free_dir(uint32_t cr3) {
    if (!cr3 || cr3 == g_kernel_cr3) return;
    uint32_t* dir = paging_dir_ptr(cr3);
    if (dir) {
        for (int i = 0; i < PAGE_DIR_ENTRIES; i++) {
            uint32_t e = dir[i];
            if ((e & PDE_PRESENT) && (e & PDE_USER) && (e & PDE_PSE)) {
                fork_frame_free(e & 0xFFC00000u);
            }
        }
    }
    for (int i = 0; i < PAGING_ASDIR_MAX; i++) {
        if ((uint32_t)&g_asdirs[i][0] == cr3) {
            g_asdir_used[i] = 0;
            return;
        }
    }
}

void paging_unmap_pde(uint32_t cr3, uint32_t pde_index) {
    uint32_t* dir = paging_dir_ptr(cr3);
    if (!dir || pde_index >= PAGE_DIR_ENTRIES) return;
    dir[pde_index] = 0;
    uint32_t cur;
    asm volatile ("mov %%cr3, %0" : "=r"(cur));
    if ((cur & ~0xFFFu) == ((cr3 ? cr3 : g_kernel_cr3) & ~0xFFFu)) {
        asm volatile ("mov %0, %%cr3" : : "r"(cur) : "memory");
    }
}

int paging_pde_present(uint32_t cr3, uint32_t pde_index) {
    uint32_t* dir = paging_dir_ptr(cr3);
    if (!dir || pde_index >= PAGE_DIR_ENTRIES) return 0;
    return (dir[pde_index] & PDE_PRESENT) ? 1 : 0;
}

extern "C" void page_fault_handler_main(uint32_t error_code) {
    uint32_t fault_addr;
    asm volatile ("mov %%cr2, %0" : "=r"(fault_addr));
    g_pf_count++;

    uint32_t cr3;
    asm volatile ("mov %%cr3, %0" : "=r"(cr3));
    uint32_t* dir = (uint32_t*)(cr3 & ~0xFFFu);

    uint32_t pde_i = fault_addr >> 22;

    /* Protection violation: PDE присутствует (P=1), но права не сошлись.
       Из ring3 — нарушение страничной изоляции → убить задачу (не паниковать).
       Из ring0 — баг ядра. */
    if (error_code & 0x1u) {
        struct task* cur = sched_current();
        if ((error_code & 0x4u) && cur && cur->is_user) {
            log_fmt3(LOG_ERR, "mm", "user fault killed",
                     "addr", fault_addr, "err", error_code, "tid", (uint32_t)cur->id);
            task_exit();
        }
        log_fmt3(LOG_ERR, "mm", "pf panic", "addr", fault_addr, "err", error_code, "n", g_pf_count);
        while (1) asm volatile ("hlt");
    }

    /* 0xffe00000+ — recursive/high-регион; сюда ядро обращаться не должно.
       Не-present-фолт тут === порча return-адреса/указателя. Диагностика. */
    if (fault_addr >= 0xffe00000u && !(error_code & 0x1u) && !(error_code & 0x4u)) {
        static const char pr[] = "\r\n[CRASH_HIGH]\r\n";
        for (int i = 0; pr[i]; i++) {
            uint8_t cc = (uint8_t)pr[i];
            asm volatile ("1: inb $0x3fd, %%al; testb $0x20, %%al; jz 1b" ::: "eax");
            asm volatile ("outb %0, %1" : : "a"(cc), "Nd"(0x3f8));
        }
        uint32_t* fc = &error_code;             /* ferr-36: копия err, ниже pushad-регистров */
        uint32_t ferr = (uint32_t)(fc + 9);     /* адрес CPU-err = ESP в момент #PF */
        uint32_t saved_esp = ferr;
        uint32_t saved_eip = fc[10];            /* EIP фолтящей инструкции */
        uint32_t saved_cs  = fc[11];
        uint32_t saved_efl = fc[12];
        struct task* cur = sched_current();
        log_fmt3(LOG_ERR, "mm", "CRASH_HIGH",
                 "addr", fault_addr, "err", error_code, "cr3", cr3);
        log_fmt3(LOG_ERR, "mm", "ctx",
                 "eip", saved_eip, "cs", saved_cs, "sesp", saved_esp);
        log_fmt3(LOG_ERR, "mm", "task",
                 "id", cur ? (uint32_t)cur->id : 0xFFFFFFFFu,
                 "user", cur ? (uint32_t)cur->is_user : 2u, "efl", saved_efl);
        log_fmt3(LOG_ERR, "mm", "regs",
                 "eax", fc[8], "edx", fc[6], "ebx", fc[5]);
        for (int i = 0; i < 16; i += 2) {
            log_fmt3(LOG_ERR, "mm", "fc",
                     "i", (uint32_t)i, "a", fc[i], "b", fc[i + 1]);
        }
        for (int off = 0x10; off < 0xC0; off += 24) {
            uint32_t w0 = 0xDEADBEEFu, w1 = 0xDEADBEEFu;
            uint32_t a0 = ferr + off, a1 = ferr + off + 4;
            uint32_t d0 = a0 >> 22, d1 = a1 >> 22;
            if (d0 < PAGE_DIR_ENTRIES && (dir[d0] & PDE_PRESENT)) w0 = *(uint32_t*)a0;
            if (d1 < PAGE_DIR_ENTRIES && (dir[d1] & PDE_PRESENT)) w1 = *(uint32_t*)a1;
            log_fmt3(LOG_ERR, "mm", "stk",
                     "a0", a0, "v0", w0, "v1", w1);
        }
        while (1) asm volatile ("hlt");
    }

    if (pde_i >= PAGE_DIR_ENTRIES) {
        log_fmt3(LOG_ERR, "mm", "pf panic", "addr", fault_addr, "err", error_code, "n", g_pf_count);
        while (1) asm volatile ("hlt");
    }
    if (!(dir[pde_i] & PDE_PRESENT)) {
        /* Demand paging: PDE ещё не размечена. Доступ USER даём только если отказ
           пришёл из ring3; kernel-фолты остаются supervisor-страницами. */
        uint32_t flags = PDE_PRESENT | PDE_RW | PDE_PSE;
        if (error_code & 0x4u) flags |= PDE_USER;
        uint32_t addr = pde_i * 0x400000u;
        dir[pde_i] = addr | flags;
        asm volatile ("mov %0, %%cr3" : : "r"(cr3) : "memory");
        log_fmt3(LOG_INFO, "mm", "pf map", "addr", fault_addr, "pde", pde_i, "n", g_pf_count);
        return;
    }
    log_fmt3(LOG_ERR, "mm", "pf panic", "addr", fault_addr, "err", error_code, "n", g_pf_count);
    while (1) asm volatile ("hlt");
}

int paging_autotest(void) {
    if (!g_paging_on) paging_init();

    volatile uint32_t* p = (volatile uint32_t*)0x00100000;
    uint32_t v = *p;
    *p = v;

    uint32_t before = g_pf_count;
    volatile uint8_t* fault = (volatile uint8_t*)(FAULT_PDE * 0x400000u + 0x100);
    uint8_t tmp = *fault;
    *fault = tmp;

    if (g_pf_count <= before) {
        log_fmt3(LOG_ERR, "mm", "pf missing", "n", g_pf_count, "ok", 0u, "x", 0u);
        return -1;
    }
    return 0;
}

extern "C" void ring3_user_stub(void);
extern "C" void ring3_enter(uint32_t user_eip, uint32_t user_esp,
                            uint32_t* cont_esp_out, uint32_t* cont_eip_out);

extern "C" void paging_ring3_finish(void) {
    g_ring3_flag = 1;
    uint32_t esp = g_ring3_cont_esp;
    uint32_t eip = g_ring3_cont_eip;
    asm volatile (
        "cli\n"
        "mov %0, %%esp\n"
        "jmp *%1\n"
        : : "r"(esp), "r"(eip) : "memory"
    );
}

int paging_ring3_autotest(void) {
    if (!g_paging_on) paging_init();
    gdt_install();

    g_ring3_flag = 0;
    g_tss.esp0 = (uint32_t)(g_kernel_irq_stack + sizeof(g_kernel_irq_stack));

    uint32_t user_esp = (uint32_t)(g_user_stack + sizeof(g_user_stack));
    uint32_t user_eip = (uint32_t)&ring3_user_stub;

    ring3_enter(user_eip, user_esp, &g_ring3_cont_esp, &g_ring3_cont_eip);

    if (!g_ring3_flag) {
        log_msg(LOG_ERR, "mm", "ring3 no flag");
        return -1;
    }
    asm volatile ("sti");
    return 0;
}

/* Isolation: dir A unmaps PDE; access from A PF-maps only A; B stays unmapped. */
int paging_aspace_autotest(void) {
    if (!g_paging_on) paging_init();

    const uint32_t pde = 20; /* 80MB */
    uint32_t a = paging_create_identity_dir();
    uint32_t b = paging_create_identity_dir();
    if (!a || !b || a == b) return -1;

    paging_unmap_pde(a, pde);
    paging_unmap_pde(b, pde);
    if (paging_pde_present(a, pde) || paging_pde_present(b, pde)) return -2;

    uint32_t prev;
    asm volatile ("mov %%cr3, %0" : "=r"(prev));
    paging_load_cr3(a);

    uint32_t before = g_pf_count;
    volatile uint8_t* va = (volatile uint8_t*)(pde * 0x400000u + 0x200);
    uint8_t tmp = *va;
    *va = tmp;

    if (g_pf_count <= before) {
        paging_load_cr3(prev);
        paging_free_dir(a);
        paging_free_dir(b);
        return -3;
    }
    if (!paging_pde_present(a, pde)) {
        paging_load_cr3(prev);
        paging_free_dir(a);
        paging_free_dir(b);
        return -4;
    }
    if (paging_pde_present(b, pde)) {
        paging_load_cr3(prev);
        paging_free_dir(a);
        paging_free_dir(b);
        return -5;
    }

    paging_load_cr3(prev);
    paging_free_dir(a);
    paging_free_dir(b);
    return 0;
}
