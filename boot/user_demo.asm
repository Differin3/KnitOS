BITS 32

section .user progbits alloc noexec nowrite
global user_demo_start
global user_demo_end
global user_demo_size
global user_demo2_start
global user_demo2_end
global user_demo2_size
global user_demo3_start
global user_demo3_end
global user_demo3_size
global user_launcher_start
global user_launcher_end
global user_launcher_size
global user_argtest_start
global user_argtest_end
global user_argtest_size
global user_ptytest_start
global user_ptytest_end
global user_ptytest_size

user_demo_start:
    incbin "user/hello.elf"
user_demo_end:
user_demo_size:
    dd user_demo_end - user_demo_start

user_demo2_start:
    incbin "user/demo2.elf"
user_demo2_end:
user_demo2_size:
    dd user_demo2_end - user_demo2_start

user_demo3_start:
    incbin "user/demo3.elf"
user_demo3_end:
user_demo3_size:
    dd user_demo3_end - user_demo3_start

user_launcher_start:
    incbin "user/launcher.elf"
user_launcher_end:
user_launcher_size:
    dd user_launcher_end - user_launcher_start

user_argtest_start:
    incbin "user/argtest.elf"
user_argtest_end:
user_argtest_size:
    dd user_argtest_end - user_argtest_start

user_ptytest_start:
    incbin "user/ptytest.elf"
user_ptytest_end:
user_ptytest_size:
    dd user_ptytest_end - user_ptytest_start