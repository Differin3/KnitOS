BITS 32
section .text
global _start
extern main
extern exit

; Стандартная точка входа user-программы: читает argc/argv с исходного стека
; (их формирует ядро), вызывает main(argc, argv), затем exit(ret).
_start:
    mov eax, [esp]          ; argc
    lea ebx, [esp + 4]      ; argv
    push ebx                ; 2-й аргумент
    push eax                ; 1-й аргумент
    call main
    add esp, 8
    push eax                ; код возврата
    call exit
    hlt
