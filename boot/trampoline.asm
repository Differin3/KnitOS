; SMP AP trampoline (16->32 bit). Собирается как сырой бинарник (nasm -f bin,
; org 0x8000). Копируется BSP по физическому 0x8000. AP стартует в real mode
; (SIPI vector 0x08 => CS=0x0800, IP=0) и переводится в protected mode.
;
; Раскладка (абсолютные адреса, совпадает с TRAMP_* в smp.cpp):
;   0x8000  16-bit entry
;   0x8040  GDTR (dw limit=23, dd base)   — base заполняет BSP
;   0x8060  32-bit entry
;   0x80A0  cr3_slot (dd)                 — заполняет BSP
;   0x80A4  stack_slot (dd)               — заполняет BSP
;   0x80A8  entry_slot (dd)               — заполняет BSP
;   0x8100  GDT (null, 32-bit code 0x08, 32-bit data 0x10)

BITS 16
org 0x8000

entry16:
    cli
    cld
    lgdt [cs:0x40]              ; GDTR по адресу 0x8040
    mov eax, cr0
    or  eax, 1                  ; PE
    mov cr0, eax
    db 0x66                     ; 32-bit far jump
    db 0xEA
    dd 0x8060                   ; 32-bit entry (абсолютный адрес)
    dw 0x08

times (0x40 - ($ - $$)) db 0
gdtr:
    dw 23                       ; 3 записи GDT * 8 - 1
    dd 0                        ; base (0x8100) — заполняет BSP

times (0x60 - ($ - $$)) db 0

BITS 32
entry32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov eax, cr4
    or  eax, 0x10                 ; PSE — ядро использует 4MB-страницы
    mov cr4, eax

    mov eax, [0x80A0]           ; cr3_slot
    mov cr3, eax
    mov eax, cr0
    or  eax, 0x80000000         ; PG
    mov cr0, eax

    mov esp, [0x80A4]           ; stack_slot
    mov eax, [0x80A8]           ; entry_slot
    call eax

hang:
    cli
    hlt
    jmp hang

times (0xA0 - ($ - $$)) db 0
cr3_slot:   dd 0
stack_slot: dd 0
entry_slot: dd 0

times (0x100 - ($ - $$)) db 0
gdt:
    dq 0x0000000000000000       ; null
    dq 0x00CF9A000000FFFF       ; 32-bit code 0x08
    dq 0x00CF92000000FFFF       ; 32-bit data 0x10
gdt_end:
