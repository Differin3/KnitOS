#include "idt.h"
#include "serial_log.h"
#include "sched/task.h"

extern "C" {
    extern void idt_load(uint32_t);
    extern void keyboard_handler();
    extern void default_handler();
    extern void syscall_handler_asm();
    extern void pit_handler();
    extern void nic_irq_handler();
    extern void page_fault_handler();
    extern void isr0(); extern void isr1(); extern void isr2(); extern void isr3();
    extern void isr4(); extern void isr5(); extern void isr6(); extern void isr7();
    extern void isr8(); extern void isr9(); extern void isr10(); extern void isr11();
    extern void isr12(); extern void isr13(); extern void isr14(); extern void isr15();
    extern void isr16(); extern void isr17(); extern void isr18(); extern void isr19();
    extern void isr20(); extern void isr21(); extern void isr22(); extern void isr23();
    extern void isr24(); extern void isr25(); extern void isr26(); extern void isr27();
    extern void isr28(); extern void isr29(); extern void isr30(); extern void isr31();
}

/* Логирует необработанное исключение CPU и останавливает ядро. */
extern "C" void exception_handler(uint32_t* f) {
    struct task* cur = sched_current();
    debugf("\n[EXC] vec=%d err=%x eip=%x cs=%x efl=%x cur=%d/%s\n",
           f[0], f[1], f[2], f[3], f[4],
           cur ? cur->id : -1, cur ? cur->name : "?");
    while (1) asm volatile ("hlt");
}

#define IDT_ENTRIES 256
idt_entry idt[IDT_ENTRIES];
idt_ptr idtp;

void idt_set_gate(uint8_t num, uint32_t base, uint16_t sel, uint8_t flags) {
    idt[num].base_low  = base & 0xFFFF;
    idt[num].base_high = (base >> 16) & 0xFFFF;
    idt[num].selector  = sel;
    idt[num].zero      = 0;
    idt[num].flags     = flags;
}

void idt_init() {
    idtp.limit = (sizeof(idt_entry) * IDT_ENTRIES) - 1;
    idtp.base  = (uint32_t)&idt;

    // Use the live CS from GRUB/Multiboot — hardcoding 0x08 triple-faults on IRQ
    uint16_t kernel_cs = 0;
    asm volatile ("mov %%cs, %0" : "=r"(kernel_cs));

    for (int i = 0; i < IDT_ENTRIES; i++) {
        idt_set_gate((uint8_t)i, (uint32_t)default_handler, kernel_cs, 0x8E);
    }

    // CPU exceptions 0..31 -> логирующий обработчик (иначе исключение
    // зациклится через default_handler: iret вернётся на сбойную инструкцию).
    void (*isrs[32])() = {
        isr0, isr1, isr2, isr3, isr4, isr5, isr6, isr7,
        isr8, isr9, isr10, isr11, isr12, isr13, isr14, isr15,
        isr16, isr17, isr18, isr19, isr20, isr21, isr22, isr23,
        isr24, isr25, isr26, isr27, isr28, isr29, isr30, isr31
    };
    for (int i = 0; i < 32; i++) {
        idt_set_gate((uint8_t)i, (uint32_t)isrs[i], kernel_cs, 0x8E);
    }

    // IRQ0 PIT = 32
    idt_set_gate(32, (uint32_t)pit_handler, kernel_cs, 0x8E);
    // IRQ1 keyboard = 33
    idt_set_gate(33, (uint32_t)keyboard_handler, kernel_cs, 0x8E);
    // Common NIC lines in QEMU: IRQ9-11 -> 41-43
    idt_set_gate(41, (uint32_t)nic_irq_handler, kernel_cs, 0x8E);
    idt_set_gate(42, (uint32_t)nic_irq_handler, kernel_cs, 0x8E);
    idt_set_gate(43, (uint32_t)nic_irq_handler, kernel_cs, 0x8E);

    // #PF vector 14
    idt_set_gate(14, (uint32_t)page_fault_handler, kernel_cs, 0x8E);

    // Syscall int 0x80 — DPL=3, trap gate (IF сохраняется): блокирующие
    // syscall'ы (sleep/yield) переключают задачи, и унаследованный IF у
    // resumed-потока обязан быть 1 (иначе его hlt никогда не проснётся).
    idt_set_gate(0x80, (uint32_t)syscall_handler_asm, kernel_cs, 0xEF);

    idt_load((uint32_t)&idtp);
}
