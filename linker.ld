ENTRY(_start)

SECTIONS
{
    . = 1M;

    .boot :
    {
        *(.multiboot_header)
    }

    .text :
    {
        *(.text)
    }

    .rodata :
    {
        *(.rodata)
        *(.user)
    }

    .data :
    {
        *(.data)
    }

    .bss :
    {
        *(.bss)
    }
}

