; Инклюдит сырой 16/32-битный трамполин SMP (boot/trampoline.bin),
; собранный nasm -f bin. Байты попадают в образ ядра; BSP копирует их в 0x8000.
BITS 32
section .trampoline_blob
global trampoline_start
global trampoline_end
trampoline_start:
    incbin "boot/trampoline.bin"
trampoline_end:
