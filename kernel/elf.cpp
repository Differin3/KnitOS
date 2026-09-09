#include "elf.h"
#include "serial_log.h"

#define ELF_MAG0 0x7F
#define ELF_MAG1 'E'
#define ELF_MAG2 'L'
#define ELF_MAG3 'F'

#define ELFCLASS32 1
#define ELFDATA2LSB 1
#define ET_EXEC 2
#define EM_386 3
#define PT_LOAD 1

struct elf32_ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct elf32_phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} __attribute__((packed));

static bool elf32_bounds_ok(const uint8_t* img, size_t len,
                            uint32_t off, uint32_t sz) {
    return off <= len && sz <= len - off;
}

int elf32_validate(const uint8_t* img, size_t len) {
    if (!img || len < sizeof(struct elf32_ehdr)) return -1;
    const struct elf32_ehdr* h = (const struct elf32_ehdr*)img;
    if (h->e_ident[0] != ELF_MAG0 || h->e_ident[1] != ELF_MAG1 ||
        h->e_ident[2] != ELF_MAG2 || h->e_ident[3] != ELF_MAG3) return -2;
    if (h->e_ident[4] != ELFCLASS32) return -3;
    if (h->e_ident[5] != ELFDATA2LSB) return -4;
    if (h->e_type != ET_EXEC) return -5;
    if (h->e_machine != EM_386) return -6;
    if (h->e_phentsize < sizeof(struct elf32_phdr)) return -7;
    if (!elf32_bounds_ok(img, len, h->e_phoff, (uint32_t)h->e_phentsize * h->e_phnum))
        return -8;
    return 0;
}

int elf32_load(const uint8_t* img, size_t len, uint32_t* out_entry) {
    if (elf32_validate(img, len) != 0) return -1;
    const struct elf32_ehdr* h = (const struct elf32_ehdr*)img;

    const struct elf32_phdr* ph = (const struct elf32_phdr*)(img + h->e_phoff);
    uint32_t n = h->e_phnum;

    for (uint32_t i = 0; i < n; i++) {
        if (ph[i].p_type != PT_LOAD) continue;

        uint32_t vaddr = ph[i].p_vaddr;
        uint32_t filesz = ph[i].p_filesz;
        uint32_t memsz = ph[i].p_memsz;
        uint32_t off = ph[i].p_offset;

        /* Безопасный диапазон: выше ядра и ниже зарезервированных стеков. */
        if (vaddr < ELF_USER_VA_MIN) return -9;
        if (memsz == 0) continue;
        if (filesz > memsz) return -10;
        if (vaddr + memsz <= vaddr || vaddr + memsz > ELF_USER_VA_MAX) return -11;
        if (!elf32_bounds_ok(img, len, off, filesz)) return -12;

        uint8_t* dst = (uint8_t*)vaddr;
        const uint8_t* src = img + off;
        for (uint32_t j = 0; j < filesz; j++) dst[j] = src[j];
        for (uint32_t j = filesz; j < memsz; j++) dst[j] = 0;
        log_fmt3(LOG_INFO, "elf", "load seg", "va", vaddr, "filesz", filesz, "memsz", memsz);
    }

    if (out_entry) *out_entry = h->e_entry;
    return 0;
}

/* Минимальный и максимальный адреса (vaddr..vaddr+memsz) всех PT_LOAD сегментов.
   Используется для пометки PDE_USER в каталоге задачи перед запуском. */
int elf32_user_ranges(const uint8_t* img, size_t len, uint32_t* lo_out, uint32_t* hi_out) {
    if (elf32_validate(img, len) != 0) return -1;
    if (!lo_out || !hi_out) return -2;
    const struct elf32_ehdr* h = (const struct elf32_ehdr*)img;
    const struct elf32_phdr* ph = (const struct elf32_phdr*)(img + h->e_phoff);
    uint32_t lo = 0xFFFFFFFF;
    uint32_t hi = 0;
    for (uint32_t i = 0; i < h->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_memsz == 0) continue;
        uint32_t vaddr = ph[i].p_vaddr;
        uint32_t end = vaddr + ph[i].p_memsz;
        if (vaddr < ELF_USER_VA_MIN || end <= vaddr || end > ELF_USER_VA_MAX) return -3;
        if (vaddr < lo) lo = vaddr;
        if (end > hi) hi = end;
    }
    if (hi == 0) return -4;
    *lo_out = lo;
    *hi_out = hi;
    return 0;
}