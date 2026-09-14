BITS 32

; Загрузка IDT (32-bit)
global idt_load
idt_load:
    mov eax, [esp + 4]
    lidt [eax]
    ret

; PIT IRQ0
global pit_handler
extern pit_handler_main
pit_handler:
    pushad
    cld
    call pit_handler_main
    popad
    iret

; Обработчик клавиатуры
global keyboard_handler
extern keyboard_handler_main
keyboard_handler:
    pushad
    cld
    call keyboard_handler_main
    ; EOI для мастер и для slave, чтобы исключить блокировку
    mov al, 0x20
    out 0xA0, al
    out 0x20, al
    popad
    iret

; NIC IRQ (shared stub for RTL8139/virtio — typically IRQ11 -> vector 43)
global nic_irq_handler
extern nic_irq_handler_main
nic_irq_handler:
    pushad
    cld
    call nic_irq_handler_main
    popad
    iret

; Обработчик системных вызовов (int 0x80)
; Параметры: eax = номер вызова, ebx = arg1, ecx = arg2, edx = arg3, esi = arg4
global syscall_handler_asm
extern syscall_handler
syscall_handler_asm:
    ; Сохраняем указатель на кадр прерывания (EIP/CS/EFLAGS/ESP/SS) для fork.
    mov [g_syscall_frame_ptr], esp
    ; Сохраняем регистры до pushad (чтобы использовать их значения)
    push esi  ; arg4
    push edx  ; arg3
    push ecx  ; arg2
    push ebx  ; arg1
    push eax  ; arg0 (номер системного вызова)
    
    ; Теперь сохраняем все регистры
    pushad
    
    ; Вызываем C обработчик (аргументы: указатель на структуру на стеке, CS вызывающего)
    ; Структура находится по смещению 32 от текущего esp (8 регистров * 4)
    mov eax, esp
    add eax, 32
    ; Смещение CS: 5 аргументов (20 байт) + 4 байта = 24 от базы структуры
    mov edx, [eax + 24]  ; caller CS (0x1B = ring3, 0x08 = ring0)
    push edx
    push eax
    call syscall_handler
    add esp, 8  ; Убираем аргументы (args*, cs)

    ; Сохраняем результат в место где был сохранен EAX в pushad
    ; После pushad EAX находится по смещению 28 от текущего esp
    mov [esp + 28], eax
    
    ; Восстанавливаем регистры (результат уже в eax)
    popad
    
    ; Восстанавливаем стек (убираем структуру аргументов)
    add esp, 20  ; 5 * 4 байта (arg0-arg4)
    
    iret

; Page fault (#PF, vector 14) — CPU pushes error code
global page_fault_handler
extern page_fault_handler_main
page_fault_handler:
    pushad
    cld
    mov eax, [esp + 32]   ; error code after pushad
    push eax
    call page_fault_handler_main
    add esp, 4
    popad
    add esp, 4            ; pop error code
    iret

; Ring-3 smoke stub: int 0x80 SYS_RING3_DONE then hang
global ring3_user_stub
ring3_user_stub:
    mov eax, 17           ; SYS_RING3_DONE
    int 0x80
.hang:
    jmp .hang

; void ring3_enter(uint32_t user_eip, uint32_t user_esp, uint32_t* cont_esp_out, uint32_t* cont_eip_out)
; Saves kernel continuation, irets to ring3. Returns here after paging_ring3_finish.
global ring3_enter
ring3_enter:
    push ebp
    mov ebp, esp
    ; args: [ebp+8]=eip [ebp+12]=esp [ebp+16]=cont_esp* [ebp+20]=cont_eip*
    mov eax, [ebp+16]
    mov [eax], esp          ; save ESP (with this frame) for restore
    mov eax, [ebp+20]
    mov dword [eax], ring3_cont

    mov ecx, [ebp+8]        ; user eip
    mov edx, [ebp+12]       ; user esp
    push dword 0x23         ; SS
    push edx                ; ESP
    pushfd
    or dword [esp], 0x200   ; IF
    push dword 0x1B         ; CS
    push ecx                ; EIP
    iretd

ring3_cont:
    pop ebp
    ret

; void user_mode_enter(uint32_t user_eip, uint32_t user_esp)
; Переключение ring0 -> ring3 (вызывается из задачи, больше не возвращается).
global user_mode_enter
user_mode_enter:
    mov ecx, [esp + 4]   ; user eip
    mov edx, [esp + 8]   ; user esp
    mov ax, 0x23         ; user data selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    push dword 0x23      ; SS
    push edx             ; user ESP
    pushfd
    or dword [esp], 0x200 ; IF=1
    push dword 0x1B      ; user CS
    push ecx             ; user EIP
    iretd

; void user_mode_enter_fork(uint32_t user_eip, uint32_t user_esp)
; Как user_mode_enter, но восстанавливает регистры родителя из g_fork_regs
; и кладёт EAX=0 (возврат fork в ребёнке).
global user_mode_enter_fork
user_mode_enter_fork:
    mov ecx, [esp + 4]   ; user eip
    mov edx, [esp + 8]   ; user esp
    mov ax, 0x23
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    push dword 0x23      ; SS
    push edx             ; user ESP
    pushfd
    or dword [esp], 0x200 ; IF=1
    push dword 0x1B      ; user CS
    push ecx             ; user EIP
    xor eax, eax         ; fork() == 0 в ребёнке
    mov ebp, [g_fork_regs + 0]
    mov edi, [g_fork_regs + 4]
    mov esi, [g_fork_regs + 8]
    mov ebx, [g_fork_regs + 12]
    mov edx, [g_fork_regs + 16]
    mov ecx, [g_fork_regs + 20]
    iretd

; Указатель на кадр прерывания int 0x80 (заполняется в syscall_handler_asm).
global g_syscall_frame_ptr
section .bss
align 4
g_syscall_frame_ptr: resd 1
global g_fork_regs
g_fork_regs: resd 6
section .text
global default_handler
default_handler:
    mov al, 0x20
    out 0xA0, al
    out 0x20, al
    iret

; --- Exception stubs (vectors 0..31): push vector + optional error code,
;     call exception_handler which logs to serial and halts. ---
extern exception_handler
%macro ISR_NOERR 1
global isr%1
isr%1:
    push dword 0
    push dword %1
    jmp isr_common
%endmacro
%macro ISR_ERRCODE 1
global isr%1
isr%1:
    push dword %1
    jmp isr_common
%endmacro

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERRCODE 8
ISR_NOERR 9
ISR_ERRCODE 10
ISR_ERRCODE 11
ISR_ERRCODE 12
ISR_ERRCODE 13
ISR_ERRCODE 14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERRCODE 17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERRCODE 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERRCODE 29
ISR_ERRCODE 30
ISR_NOERR 31

; frame layout at [eax]: vec, err, eip, cs, eflags, (esp, ss)
isr_common:
    pushad
    cld
    mov eax, esp
    add eax, 32
    push eax
    call exception_handler
    add esp, 4
    popad
    add esp, 8
    iret

