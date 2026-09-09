#include "drivers/power/acpi.h"
#include "serial_log.h"
#include "mm/paging.h"
#include <stddef.h>

extern "C" {
extern int memcmp(const void* a, const void* b, size_t n);
}

#define ACPI_RSDP_SIG "RSD PTR "

#define ACPI_PM1_SLP_EN        (1u << 13)
#define ACPI_PM1_SLP_TYP_MASK  (7u << 10)
#define ACPI_PM1_SCI_EN        (1u << 0)

/*
 * RSDP (ACPI 1.0/2.0+). В rev>=2 после checked-checksum (offset 20)
 * идут: uint32 length, uint64 xsdt_address, extended_checksum.
 */
struct acpi_rsdp {
    char     signature[8];
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_address;
} __attribute__((packed));

struct acpi_sdt_header {
    char     signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

struct acpi_rsdt {
    struct acpi_sdt_header header;
    uint32_t entries[1];
} __attribute__((packed));

struct acpi_gas {
    uint8_t  address_space;   /* 0 = SystemMemory, 1 = SystemIO */
    uint8_t  bit_width;
    uint8_t  bit_offset;
    uint8_t  access_width;
    uint64_t address;
} __attribute__((packed));

/* FADT (ACPI 2.0+ layout). Поля x_* валидны только при revision>=2
   и header.length >= их смещения. */
struct acpi_fadt {
    struct acpi_sdt_header header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t  reserved0;
    uint8_t  preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t  acpi_enable;
    uint8_t  acpi_disable;
    uint8_t  s4bios_req;
    uint8_t  pstate_control;
    uint32_t pm1a_event_block;
    uint32_t pm1b_event_block;
    uint32_t pm1a_control_block;
    uint32_t pm1b_control_block;
    uint32_t pm2_control_block;
    uint32_t pm_timer_block;
    uint32_t gpe0_block;
    uint32_t gpe1_block;
    uint8_t  pm1_event_length;
    uint8_t  pm1_control_length;
    uint8_t  pm2_control_length;
    uint8_t  pm_timer_length;
    uint8_t  gpe0_length;
    uint8_t  gpe1_length;
    uint8_t  gpe1_base;
    uint8_t  cst_control;
    uint16_t plvl2_latency;
    uint16_t plvl3_latency;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t  duty_offset;
    uint8_t  duty_width;
    uint8_t  day_alarm;
    uint8_t  month_alarm;
    uint8_t  century;
    uint16_t iapc_boot_arch;
    uint8_t  reserved1;
    uint32_t flags;
    struct acpi_gas reset_reg;
    uint8_t  reset_value;
    uint8_t  arm_boot_arch[3];
    uint8_t  fadt_minor_version;
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    struct acpi_gas x_pm1a_event_block;
    struct acpi_gas x_pm1b_event_block;
    struct acpi_gas x_pm1a_control_block;
    struct acpi_gas x_pm1b_control_block;
    struct acpi_gas x_pm2_control_block;
    struct acpi_gas x_pm_timer_block;
    struct acpi_gas x_gpe0_block;
    struct acpi_gas x_gpe1_block;
} __attribute__((packed));

static bool     g_pm1_ok = false;
static uint16_t g_pm1a_cnt = 0;
static uint16_t g_pm1b_cnt = 0;
static uint8_t  g_slp_typa = 5;   /* default S5 (QEMU/Bochs/VBox) */
static uint8_t  g_slp_typb = 5;

static bool     g_reset_ok = false;
static bool     g_reset_mem = false;
static uint32_t g_reset_addr = 0;
static uint8_t  g_reset_value = 0;

static bool g_acpi_avail = false;

static inline void acpi_outb(uint16_t port, uint8_t val) {
    asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline void acpi_outw(uint16_t port, uint16_t val) {
    asm volatile ("outw %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint16_t acpi_inw(uint16_t port) {
    uint16_t r;
    asm volatile ("inw %1, %0" : "=a"(r) : "Nd"(port));
    return r;
}

static inline void acpi_io_wait(void) {
    asm volatile ("outb %%al, $0x80" : : "a"((uint8_t)0));
}

static uint8_t acpi_checksum(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) sum += p[i];
    return sum;
}

/* Физический адрес ACPI-таблицы -> виртуальный. Ядро имеет identity-map
   первых 128 МБ; более высокие таблицы подмапиваем странично. */
static void* acpi_phys_to_virt(uint32_t phys, uint32_t bytes) {
    if (!phys) return 0;
    if (phys + bytes > 0x08000000u) {
        paging_map_physical(phys, bytes);
    }
    return (void*)(uintptr_t)phys;
}

/* Допустимые ревизии RSDP: 0 (ACPI 1.0), 1 (некоторые BIOS), 2+ (ACPI 2.0/3.0...). */
static bool acpi_revision_ok(uint8_t rev) {
    return rev == 0 || rev == 1 || rev >= 2;
}

static bool acpi_rsdp_valid(const struct acpi_rsdp* r) {
    if (memcmp(r->signature, ACPI_RSDP_SIG, 8) != 0) return false;
    if (!acpi_revision_ok(r->revision)) return false;
    if (acpi_checksum(r, 20) == 0) return true;
    if (r->revision >= 2) {
        const uint8_t* b = (const uint8_t*)r;
        uint32_t len = b[20] | (b[21] << 8) | (b[22] << 16) | (b[23] << 24);
        if (len >= 36 && acpi_checksum(r, len) == 0) return true;
    }
    return false;
}

static bool acpi_table_valid(const struct acpi_sdt_header* h);

static uint32_t acpi_ebda_base(void) {
    uint16_t seg = *(volatile uint16_t*)0x40E;
    uint32_t base = (uint32_t)seg << 4;
    if (base < 0x80000u || base >= 0xA0000u) return 0;
    return base;
}

/* Корневая таблица (XSDT для rev>=2, иначе RSDT) для данного RSDP.
   Возвращает 0, если аннонсированный корень не является валидным RSDT/XSDT. */
static const struct acpi_sdt_header* acpi_root_from_rsdp(
        const struct acpi_rsdp* rsdp, uint32_t* root_phys_out) {
    if (rsdp->revision >= 2) {
        const uint8_t* b = (const uint8_t*)rsdp;
        uint32_t xsdt = (uint32_t)(*(const uint64_t*)(b + 24)) & 0xFFFFFFFFu;
        if (xsdt) {
            const struct acpi_sdt_header* root =
                (const struct acpi_sdt_header*)acpi_phys_to_virt(xsdt, sizeof(struct acpi_sdt_header));
            if (root && root->length >= sizeof(struct acpi_sdt_header)) {
                root = (const struct acpi_sdt_header*)acpi_phys_to_virt(xsdt, root->length);
                if (root && memcmp(root->signature, "XSDT", 4) == 0 && acpi_table_valid(root)) {
                    *root_phys_out = xsdt;
                    return root;
                }
            }
        }
    }
    if (rsdp->rsdt_address) {
        const struct acpi_sdt_header* root =
            (const struct acpi_sdt_header*)
                acpi_phys_to_virt(rsdp->rsdt_address, sizeof(struct acpi_sdt_header));
        if (root && root->length >= sizeof(struct acpi_sdt_header)) {
            root = (const struct acpi_sdt_header*)
                acpi_phys_to_virt(rsdp->rsdt_address, root->length);
            if (root && memcmp(root->signature, "RSDT", 4) == 0 && acpi_table_valid(root)) {
                *root_phys_out = rsdp->rsdt_address;
                return root;
            }
        }
    }
    return 0;
}

static bool acpi_table_valid(const struct acpi_sdt_header* h) {
    if (!h || h->length < sizeof(struct acpi_sdt_header)) return false;
    return (acpi_checksum(h, h->length) == 0);
}

/* Поиск SDT по сигнатуре в RSDT (32-бит) или XSDT (64-бит). */
static const struct acpi_sdt_header* acpi_find_table(
        const struct acpi_sdt_header* root, uint32_t root_phys,
        const char* sig) {
    uint8_t stride = (memcmp(root->signature, "XSDT", 4) == 0) ? 8 : 4;
    uint32_t count =
        (root->length - sizeof(struct acpi_sdt_header)) / stride;
    const uint8_t* entries =
        (const uint8_t*)root + sizeof(struct acpi_sdt_header);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t phys = 0;
        if (stride == 8) {
            phys = (uint32_t)(*(const uint64_t*)(entries + i * 8u)) & 0xFFFFFFFFu;
        } else {
            phys = *(const uint32_t*)(entries + i * 4u);
        }
        if (!phys) continue;
        const struct acpi_sdt_header* h =
            (const struct acpi_sdt_header*)acpi_phys_to_virt(phys, sizeof(struct acpi_sdt_header));
        if (!h || memcmp(h->signature, sig, 4) != 0) continue;
        if (h->length < sizeof(struct acpi_sdt_header)) continue;
        const struct acpi_sdt_header* full =
            (const struct acpi_sdt_header*)acpi_phys_to_virt(phys, h->length);
        if (full && memcmp(full->signature, sig, 4) == 0) return full;
    }
    (void)root_phys;
    return 0;
}

static void acpi_parse_fadt(const struct acpi_fadt* fadt) {
    uint32_t len = fadt->header.length;

    /* 1) PM1a/PM1b_CNT_BLK из legacy-части. */
    uint32_t pm1a = fadt->pm1a_control_block;
    uint32_t pm1b = fadt->pm1b_control_block;

    /* 2) Предпочитаем x_* GAS при revision>=2. */
    if (fadt->header.revision >= 2 &&
        len >= offsetof(struct acpi_fadt, x_pm1a_control_block) + sizeof(struct acpi_gas)) {
        const struct acpi_gas* g = &fadt->x_pm1a_control_block;
        if (g->address_space == 1 && (g->address & 0xFFFFu) != 0) {
            pm1a = (uint32_t)(g->address & 0xFFFFu);
        }
        const struct acpi_gas* gb = &fadt->x_pm1b_control_block;
        if (gb->address_space == 1 && (gb->address & 0xFFFFu) != 0) {
            pm1b = (uint32_t)(gb->address & 0xFFFFu);
        }
    }

    if (pm1a) {
        g_pm1a_cnt = (uint16_t)(pm1a & 0xFFFFu);
        g_pm1b_cnt = (uint16_t)(pm1b & 0xFFFFu);
        g_pm1_ok = true;
    }

    /* 3) Reset register (offset 0x74). */
    if (len >= offsetof(struct acpi_fadt, reset_reg) + sizeof(struct acpi_gas)) {
        const struct acpi_gas* rr = &fadt->reset_reg;
        if ((rr->address & 0xFFFFFFFFu) != 0 &&
            len >= offsetof(struct acpi_fadt, reset_value) + 1) {
            g_reset_ok = true;
            g_reset_mem = (rr->address_space == 0);
            g_reset_addr = (uint32_t)(rr->address & 0xFFFFFFFFu);
            g_reset_value = fadt->reset_value;
        }
    }
}

/* ACPI PkgLength (однобайтовая "small" форма; для _S5 достаточно). */
static bool acpi_aml_pkg_length(const uint8_t* d, size_t max,
                                uint32_t* out_len, size_t* out_used) {
    if (max < 1) return false;
    uint8_t lead = d[0];
    if (lead & 0x80) return false;           /* multi-byte form: не встречается в _S5 */
    *out_len = lead & 0x3F;                  /* bits [5:0] */
    *out_used = 1;
    return true;
}

/* Целочисленные константы AML: ZeroOp/OneOp/OnesOp/ByteConst/WordConst. */
static bool acpi_aml_read_int(const uint8_t* d, size_t max,
                              uint32_t* out, size_t* used) {
    if (max < 1) return false;
    uint8_t op = d[0];
    if (op == 0x00) { *out = 0;   *used = 1; return true; }
    if (op == 0x01) { *out = 1;   *used = 1; return true; }
    if (op == 0xFF) { *out = 0xFF;*used = 1; return true; }
    if (op == 0x0A && max >= 2) { *out = d[1]; *used = 2; return true; }
    if (op == 0x0B && max >= 3) { *out = d[1] | (d[2] << 8); *used = 3; return true; }
    return false;
}

/* Поиск SLP_TYPa/b в DSDT: NameOp "_S5_" + PackageOp + {SLP_TYPa, SLP_TYPb}. */
static bool acpi_parse_s5(const struct acpi_sdt_header* dsdt) {
    const uint8_t* body = (const uint8_t*)dsdt + sizeof(struct acpi_sdt_header);
    size_t len = dsdt->length - sizeof(struct acpi_sdt_header);
    size_t i = 0;

    while (i + 6 < len) {
        if (memcmp(&body[i], "_S5_", 4) == 0) {
            size_t p = i + 4;
            if (p < len && body[p] == 0x12) {       /* PackageOp */
                uint32_t pkglen;
                size_t used;
                size_t j = p + 1;
                if (j < len &&
                    acpi_aml_pkg_length(&body[j], len - j, &pkglen, &used)) {
                    j += used;
                    if (j < len && pkglen >= 1) {
                        uint8_t n_elem = body[j];
                        j++;
                        size_t end = j + pkglen;    /* NumElements + elements */
                        if (n_elem >= 2 && end <= len && j < end) {
                            uint32_t v0, v1, u0;
                            if (acpi_aml_read_int(&body[j], end - j, &v0, &u0) &&
                                j + u0 < end &&
                                acpi_aml_read_int(&body[j + u0], end - (j + u0), &v1, &u0)) {
                                if (v0 <= 7 && v1 <= 7) {
                                    g_slp_typa = (uint8_t)v0;
                                    g_slp_typb = (uint8_t)v1;
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        i++;
    }
    return false;
}

bool acpi_init(void) {
    if (g_acpi_avail || g_pm1_ok || g_reset_ok) return g_acpi_avail;

    uint32_t ebda = acpi_ebda_base();
    bool found = false;

    /* Ищем RSDP: сначала в EBDA, затем в BIOS-области 0xE0000-0xFFFFF.
       Кандидат принимается только если из него извлекаются корневая таблица
       и FADT (отсекает случайные "RSD PTR " строки). */
    for (int pass = 0; pass < 2 && !found; pass++) {
        uint32_t lo, hi;
        if (pass == 0) {
            if (!ebda) continue;
            lo = ebda;
            hi = ebda + 0x400u;
        } else {
            lo = 0xE0000u;
            hi = 0x100000u;
        }
        for (uint32_t a = lo; a < hi && !found; a += 16) {
            const struct acpi_rsdp* rsdp = (const struct acpi_rsdp*)(uintptr_t)a;
            if (!acpi_rsdp_valid(rsdp)) continue;

            uint32_t root_phys = 0;
            const struct acpi_sdt_header* root =
                acpi_root_from_rsdp(rsdp, &root_phys);
            if (!root) continue;

            log_u32(LOG_INFO, "acpi", "RSDP found", rsdp->revision,
                    rsdp->rsdt_address, 0);

            const struct acpi_sdt_header* fadt_hdr =
                acpi_find_table(root, root_phys, "FACP");
            if (!fadt_hdr) continue;

            const struct acpi_fadt* fadt = (const struct acpi_fadt*)fadt_hdr;
            acpi_parse_fadt(fadt);

            if (g_pm1_ok && fadt->dsdt) {
                const struct acpi_sdt_header* dsdt =
                    (const struct acpi_sdt_header*)
                        acpi_phys_to_virt(fadt->dsdt, sizeof(struct acpi_sdt_header));
                if (dsdt && dsdt->length >= sizeof(struct acpi_sdt_header) &&
                    memcmp(dsdt->signature, "DSDT", 4) == 0) {
                    dsdt = (const struct acpi_sdt_header*)
                        acpi_phys_to_virt(fadt->dsdt, dsdt->length);
                    if (!acpi_table_valid(dsdt)) {
                        log_msg(LOG_ERR, "acpi", "DSDT checksum mismatch");
                    } else if (!acpi_parse_s5(dsdt)) {
                        log_u32(LOG_INFO, "acpi", "S5 not parsed, default SLP_TYP",
                                g_slp_typa, 0, 0);
                    }
                }
            }
            found = true;
        }
    }

    if (!found) {
        log_msg(LOG_INFO, "acpi", "RSDP not found");
        return false;
    }

    g_acpi_avail = g_pm1_ok || g_reset_ok;
    log_u32(LOG_INFO, "acpi", "init done", g_pm1_ok ? g_pm1a_cnt : 0u,
            g_reset_ok ? g_reset_addr : 0u, g_reset_value);
    return g_acpi_avail;
}

bool acpi_available(void)            { return g_acpi_avail; }
bool acpi_pm1_supported(void)        { return g_pm1_ok; }
uint16_t acpi_pm1a_cnt_blk(void)     { return g_pm1a_cnt; }
uint16_t acpi_s5_slp_typa(void)      { return g_slp_typa; }
bool acpi_reset_supported(void)      { return g_reset_ok; }
bool acpi_reset_is_memory(void)      { return g_reset_mem; }
uint32_t acpi_reset_address(void)    { return g_reset_addr; }
uint8_t acpi_reset_value(void)       { return g_reset_value; }

void acpi_power_off(void) {
    if (!g_pm1_ok) return;

    uint16_t slp_typa = (uint16_t)(g_slp_typa & 0x07u);
    uint16_t slp_typb = (uint16_t)(g_slp_typb & 0x07u);

    /* Сохраняем текущие биты (SCI_EN и пр.), меняем только SLP_TYP/SLP_EN.
       Последовательность из ACPI spec: сначала SLP_TYP без SLP_EN, затем с ним. */
    uint16_t cnt = acpi_inw(g_pm1a_cnt);
    cnt &= (uint16_t)~(ACPI_PM1_SLP_TYP_MASK | ACPI_PM1_SLP_EN);
    cnt |= (uint16_t)((slp_typa << 10) & ACPI_PM1_SLP_TYP_MASK);
    cnt |= ACPI_PM1_SCI_EN;

    acpi_outw(g_pm1a_cnt, cnt);
    acpi_io_wait();
    acpi_outw(g_pm1a_cnt, (uint16_t)(cnt | ACPI_PM1_SLP_EN));

    if (g_pm1b_cnt && g_pm1b_cnt != g_pm1a_cnt) {
        cnt = acpi_inw(g_pm1b_cnt);
        cnt &= (uint16_t)~(ACPI_PM1_SLP_TYP_MASK | ACPI_PM1_SLP_EN);
        cnt |= (uint16_t)((slp_typb << 10) & ACPI_PM1_SLP_TYP_MASK);
        cnt |= ACPI_PM1_SCI_EN;
        acpi_outw(g_pm1b_cnt, cnt);
        acpi_io_wait();
        acpi_outw(g_pm1b_cnt, (uint16_t)(cnt | ACPI_PM1_SLP_EN));
    }
    acpi_io_wait();
}

void acpi_reboot(void) {
    if (!g_reset_ok) return;

    acpi_io_wait();
    if (g_reset_mem) {
        volatile uint8_t* p = (volatile uint8_t*)(uintptr_t)g_reset_addr;
        *p = g_reset_value;
    } else {
        acpi_outb((uint16_t)g_reset_addr, g_reset_value);
    }
    acpi_io_wait();
}