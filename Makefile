# Makefile для Linux/WSL
# Использует обычный gcc вместо кросс-компилятора

ASM = nasm
CC = gcc
LD = ld

ASMFLAGS = -f elf32
CFLAGS = -m32 -ffreestanding -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra -fno-pic -fno-stack-protector -nostdlib -Ikernel
LDFLAGS = -m elf_i386 -T linker.ld -nostdlib

BOOT_SRC = boot/boot.asm
INTERRUPTS_SRC = boot/interrupts.asm
USER_DEMO_SRC = boot/user_demo.asm
SCHED_SWITCH_SRC = kernel/sched/switch.asm
SCHED_TASK_SRC = kernel/sched/task.cpp
ELF_SRC = kernel/elf.cpp
USER_HELLO_SRC = user/hello.c
USER_DEMO2_SRC = user/demo2.c
USER_DEMO3_SRC = user/demo3.c
USER_LAUNCHER_SRC = user/launcher.c
USER_LINK = user/link.ld
KERNEL_SRC = kernel/kernel.cpp
IDT_SRC = kernel/idt.cpp
KEYBOARD_SRC = kernel/drivers/input/keyboard.cpp
TERMINAL_SRC = kernel/drivers/video/terminal.cpp
ATA_SRC = kernel/drivers/storage/ata.cpp
AHCI_SRC = kernel/drivers/storage/ahci.cpp
NVME_SRC = kernel/drivers/storage/nvme.cpp
PCI_SRC = kernel/drivers/pci/pci.cpp
FS_SRC = kernel/fs.cpp
FS_AUTOTEST_SRC = kernel/fs_autotest.cpp
UTILS_SRC = kernel/utils.cpp
LS_SRC = kernel/utils/ls.cpp
FIND_SRC = kernel/utils/find.cpp
NANO_SRC = kernel/utils/nano.cpp
DISK_MANAGER_SRC = kernel/drivers/storage/disk_manager.cpp
MOUNT_SRC = kernel/mount.cpp
DEV_SRC = kernel/dev.cpp
DRIVER_MANAGER_SRC = kernel/driver_manager.cpp
SYSCALL_SRC = kernel/syscall.cpp
KERNEL_API_SRC = kernel/kernel_api.cpp
PIC_SRC = kernel/drivers/pic/pic.cpp
PIT_SRC = kernel/drivers/timer/pit.cpp
ACPI_SRC = kernel/drivers/power/acpi.cpp
RTC_SRC = kernel/drivers/power/rtc.cpp
NIC_SRC = kernel/drivers/network/nic.cpp
SKB_SRC = kernel/drivers/network/core/skb.cpp
NETIF_SRC = kernel/drivers/network/core/netif.cpp
NET_QUEUE_SRC = kernel/drivers/network/core/net_queue.cpp
NET_RX_SRC = kernel/drivers/network/core/net_rx.cpp
NET_WAIT_SRC = kernel/drivers/network/core/net_wait.cpp
NET_PORTS_SRC = kernel/drivers/network/core/net_ports.cpp
RTL8139_SRC = kernel/drivers/network/drivers/rtl8139/rtl8139.cpp
PCNET_SRC = kernel/drivers/network/drivers/pcnet/pcnet.cpp
VIRTIO_NET_SRC = kernel/drivers/network/drivers/virtio_net/virtio_net.cpp
ETHERNET_SRC = kernel/drivers/network/protocols/ethernet.cpp
ARP_SRC = kernel/drivers/network/protocols/arp.cpp
IP_SRC = kernel/drivers/network/protocols/ip.cpp
ROUTE_SRC = kernel/drivers/network/protocols/route.cpp
UDP_SRC = kernel/drivers/network/protocols/udp.cpp
ICMP_SRC = kernel/drivers/network/protocols/icmp.cpp
TCP_SRC = kernel/drivers/network/protocols/tcp.cpp
TCP_CONNECTION_SRC = kernel/drivers/network/protocols/tcp_connection.cpp
DNS_SRC = kernel/drivers/network/dns/dns.cpp
DHCP_SRC = kernel/drivers/network/dhcp/dhcp.cpp
NETWORK_CONFIG_SRC = kernel/drivers/network/network_config.cpp
SOCKET_SRC = kernel/drivers/network/socket.cpp
HTTP_SERVER_SRC = kernel/drivers/network/http_server.cpp
HTTP_PROTOCOL_SRC = kernel/drivers/network/http_protocol.cpp
HTTP_GZIP_SRC = kernel/drivers/network/http_gzip.cpp
SERIAL_LOG_SRC = kernel/serial_log.cpp
HEAP_SRC = kernel/heap.cpp
STRING_SRC = kernel/string.cpp
KERNEL_OBJ = boot/boot.o boot/interrupts.o boot/user_demo.o kernel/sched/switch.o kernel/sched/task.o \
	kernel/elf.o kernel/kernel.o kernel/idt.o kernel/serial_log.o kernel/heap.o kernel/string.o \
	kernel/mm/paging.o kernel/vga_autotest.o kernel/keyboard_autotest.o kernel/user_autotest.o \
	kernel/drivers/video/fb.o \
	kernel/drivers/pic/pic.o kernel/drivers/timer/pit.o \
	kernel/drivers/power/acpi.o kernel/drivers/power/rtc.o \
	kernel/drivers/input/keyboard.o kernel/drivers/video/terminal.o \
	kernel/drivers/storage/ata.o kernel/drivers/storage/ahci.o kernel/drivers/storage/nvme.o \
	kernel/drivers/pci/pci.o kernel/fs.o kernel/fs_cache.o kernel/ramfs.o kernel/vfs.o kernel/fs_file.o kernel/fs_autotest.o kernel/utils.o kernel/utils/ls.o kernel/utils/find.o kernel/utils/nano.o \
	kernel/drivers/storage/disk_manager.o kernel/mount.o kernel/dev.o kernel/driver_manager.o \
	kernel/syscall.o kernel/kernel_api.o kernel/user_auth.o \
	kernel/pipe.o \
	kernel/pty.o \
	kernel/drivers/network/nic.o kernel/drivers/network/socket.o \
	kernel/drivers/network/core/skb.o kernel/drivers/network/core/netif.o \
	kernel/drivers/network/core/net_queue.o kernel/drivers/network/core/net_rx.o \
	kernel/drivers/network/core/net_wait.o kernel/drivers/network/core/net_ports.o \
	kernel/drivers/network/http_protocol.o kernel/drivers/network/http_gzip.o kernel/drivers/network/http_server.o \
	kernel/drivers/network/remote_shell.o kernel/drivers/network/ftp_server.o \
	kernel/crypto/sha256.o kernel/crypto/chacha20poly1305.o kernel/crypto/x25519.o kernel/crypto/crypto_selftest.o \
	kernel/drivers/network/drivers/rtl8139/rtl8139.o kernel/drivers/network/drivers/pcnet/pcnet.o \
	kernel/drivers/network/drivers/virtio_net/virtio_net.o \
	kernel/drivers/network/protocols/ethernet.o kernel/drivers/network/protocols/arp.o \
	kernel/drivers/network/protocols/ip.o kernel/drivers/network/protocols/route.o \
	kernel/drivers/network/protocols/udp.o kernel/drivers/network/protocols/icmp.o \
	kernel/drivers/network/protocols/tcp.o kernel/drivers/network/protocols/tcp_connection.o \
	kernel/drivers/network/dns/dns.o kernel/drivers/network/dhcp/dhcp.o \
	kernel/drivers/network/network_config.o
KERNEL_BIN = iso/boot/kernel.bin
ISO = myos.iso

all: $(ISO)

check: all
	@test -s $(KERNEL_BIN) || { echo "missing $(KERNEL_BIN)"; exit 1; }
	@test -s $(ISO) || { echo "missing $(ISO)"; exit 1; }
	@echo "check OK: $(ISO) ($$(stat -c%s $(ISO)) bytes)"

$(ISO): $(KERNEL_BIN)
	grub-mkrescue -o $(ISO) iso/

$(KERNEL_BIN): $(KERNEL_OBJ)
	$(LD) $(LDFLAGS) -o $(KERNEL_BIN) $(KERNEL_OBJ)

boot/boot.o: $(BOOT_SRC)
	$(ASM) $(ASMFLAGS) -o boot/boot.o $(BOOT_SRC)

boot/interrupts.o: $(INTERRUPTS_SRC)
	$(ASM) $(ASMFLAGS) -o boot/interrupts.o $(INTERRUPTS_SRC)

user/hello.elf: $(USER_HELLO_SRC) user/syscall.h user/link.ld
	$(CC) -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
		-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib -Iuser -c -o user/hello.o $(USER_HELLO_SRC)
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 -o user/hello.elf user/hello.o

user/demo2.elf: $(USER_DEMO2_SRC) user/syscall.h user/link.ld
	$(CC) -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
		-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib -Iuser -c -o user/demo2.o $(USER_DEMO2_SRC)
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 -o user/demo2.elf user/demo2.o

user/demo3.elf: $(USER_DEMO3_SRC) user/syscall.h user/link.ld
	$(CC) -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
		-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib -Iuser -c -o user/demo3.o $(USER_DEMO3_SRC)
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 -o user/demo3.elf user/demo3.o

# ---- user-space library (libk) + crt0 + M1 test app ----
USER_CFLAGS = -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
	-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib -Iuser
USER_LIB_OBJ = user/lib/string.o user/lib/stdlib.o user/lib/stdio.o

user/crt0.o: user/crt0.asm
	$(ASM) $(ASMFLAGS) -o user/crt0.o user/crt0.asm

user/lib/string.o: user/lib/string.c user/lib/libk.h
	$(CC) $(USER_CFLAGS) -c -o user/lib/string.o user/lib/string.c

user/lib/stdlib.o: user/lib/stdlib.c user/lib/libk.h
	$(CC) $(USER_CFLAGS) -c -o user/lib/stdlib.o user/lib/stdlib.c

user/lib/stdio.o: user/lib/stdio.c user/lib/libk.h
	$(CC) $(USER_CFLAGS) -c -o user/lib/stdio.o user/lib/stdio.c

user/argtest.elf: user/argtest.c user/crt0.o $(USER_LIB_OBJ) user/link.ld user/syscall.h
	$(CC) $(USER_CFLAGS) -c -o user/argtest.o user/argtest.c
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 \
		-o user/argtest.elf user/crt0.o user/argtest.o $(USER_LIB_OBJ)

user/ptytest.elf: user/ptytest.c user/crt0.o $(USER_LIB_OBJ) user/link.ld user/syscall.h
	$(CC) $(USER_CFLAGS) -c -o user/ptytest.o user/ptytest.c
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 \
		-o user/ptytest.elf user/crt0.o user/ptytest.o $(USER_LIB_OBJ)

user/httpd.elf: user/httpd.c user/crt0.o $(USER_LIB_OBJ) user/link.ld user/syscall.h
	$(CC) $(USER_CFLAGS) -c -o user/httpd.o user/httpd.c
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 \
		-o user/httpd.elf user/crt0.o user/httpd.o $(USER_LIB_OBJ)

user/sh.elf: user/sh.c user/crt0.o $(USER_LIB_OBJ) user/link.ld user/syscall.h
	$(CC) $(USER_CFLAGS) -c -o user/sh.o user/sh.c
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 \
		-o user/sh.elf user/crt0.o user/sh.o $(USER_LIB_OBJ)

user/launcher.elf: $(USER_LAUNCHER_SRC) user/syscall.h user/link.ld
	$(CC) -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
		-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib -Iuser -c -o user/launcher.o $(USER_LAUNCHER_SRC)
	$(LD) -m elf_i386 -nostdlib -static -T user/link.ld -z noseparate-code -z max-page-size=0x1000 -o user/launcher.elf user/launcher.o

boot/user_demo.o: $(USER_DEMO_SRC) user/hello.elf user/demo2.elf user/demo3.elf user/launcher.elf user/argtest.elf user/ptytest.elf user/httpd.elf user/sh.elf
	$(ASM) $(ASMFLAGS) -i . -o boot/user_demo.o $(USER_DEMO_SRC)

kernel/elf.o: $(ELF_SRC) kernel/elf.h kernel/serial_log.h
	$(CC) $(CFLAGS) -c -o kernel/elf.o $(ELF_SRC)

kernel/sched/switch.o: $(SCHED_SWITCH_SRC)
	$(ASM) $(ASMFLAGS) -o kernel/sched/switch.o $(SCHED_SWITCH_SRC)

kernel/sched/task.o: $(SCHED_TASK_SRC) kernel/sched/task.h kernel/heap.h kernel/serial_log.h kernel/elf.h kernel/mm/paging.h
	$(CC) $(CFLAGS) -c -o kernel/sched/task.o $(SCHED_TASK_SRC)

kernel/kernel.o: $(KERNEL_SRC) kernel/kernel.h kernel/sched/task.h kernel/mm/paging.h
	$(CC) $(CFLAGS) -c -o kernel/kernel.o $(KERNEL_SRC)

kernel/idt.o: $(IDT_SRC) kernel/idt.h
	$(CC) $(CFLAGS) -c -o kernel/idt.o $(IDT_SRC)

kernel/serial_log.o: $(SERIAL_LOG_SRC) kernel/serial_log.h
	$(CC) $(CFLAGS) -c -o kernel/serial_log.o $(SERIAL_LOG_SRC)

kernel/heap.o: $(HEAP_SRC) kernel/heap.h
	$(CC) $(CFLAGS) -c -o kernel/heap.o $(HEAP_SRC)

kernel/mm/paging.o: kernel/mm/paging.cpp kernel/mm/paging.h kernel/idt.h kernel/serial_log.h
	$(CC) $(CFLAGS) -c -o kernel/mm/paging.o kernel/mm/paging.cpp

kernel/string.o: $(STRING_SRC)
	$(CC) $(CFLAGS) -c -o kernel/string.o $(STRING_SRC)

kernel/drivers/pic/pic.o: $(PIC_SRC) kernel/drivers/pic/pic.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/pic/pic.o $(PIC_SRC)

kernel/drivers/timer/pit.o: $(PIT_SRC) kernel/drivers/timer/pit.h kernel/drivers/pic/pic.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/timer/pit.o $(PIT_SRC)

kernel/drivers/power/acpi.o: $(ACPI_SRC) kernel/drivers/power/acpi.h kernel/serial_log.h kernel/mm/paging.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/power/acpi.o $(ACPI_SRC)

kernel/drivers/power/rtc.o: $(RTC_SRC) kernel/drivers/power/rtc.h kernel/serial_log.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/power/rtc.o $(RTC_SRC)

kernel/drivers/input/keyboard.o: $(KEYBOARD_SRC) kernel/drivers/input/keyboard.h kernel/kernel.h kernel/drivers/pic/pic.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/input/keyboard.o $(KEYBOARD_SRC)

kernel/drivers/video/terminal.o: $(TERMINAL_SRC) kernel/drivers/video/terminal.h kernel/drivers/video/fb.h kernel/kernel.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/video/terminal.o $(TERMINAL_SRC)

kernel/drivers/video/fb.o: kernel/drivers/video/fb.cpp kernel/drivers/video/fb.h kernel/mm/paging.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/video/fb.o kernel/drivers/video/fb.cpp

kernel/vga_autotest.o: kernel/vga_autotest.cpp kernel/vga_autotest.h kernel/drivers/video/terminal.h
	$(CC) $(CFLAGS) -c -o kernel/vga_autotest.o kernel/vga_autotest.cpp

kernel/keyboard_autotest.o: kernel/keyboard_autotest.cpp kernel/keyboard_autotest.h kernel/drivers/input/keyboard.h
	$(CC) $(CFLAGS) -c -o kernel/keyboard_autotest.o kernel/keyboard_autotest.cpp

kernel/user_autotest.o: kernel/user_autotest.cpp kernel/user_autotest.h kernel/sched/task.h kernel/mm/paging.h kernel/fs.h kernel/vfs.h kernel/ramfs.h
	$(CC) $(CFLAGS) -c -o kernel/user_autotest.o kernel/user_autotest.cpp

kernel/user_auth.o: kernel/user_auth.cpp kernel/user_auth.h kernel/fs.h kernel/string.h
	$(CC) $(CFLAGS) -c -o kernel/user_auth.o kernel/user_auth.cpp

kernel/pipe.o: kernel/pipe.cpp kernel/pipe.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/pipe.o kernel/pipe.cpp

kernel/pty.o: kernel/pty.cpp kernel/pty.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/pty.o kernel/pty.cpp

kernel/drivers/storage/ata.o: $(ATA_SRC) kernel/drivers/storage/ata.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/storage/ata.o $(ATA_SRC)

kernel/drivers/storage/ahci.o: $(AHCI_SRC) kernel/drivers/storage/ahci.h kernel/drivers/storage/ata.h kernel/drivers/pci/pci.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/storage/ahci.o $(AHCI_SRC)

kernel/drivers/storage/nvme.o: $(NVME_SRC) kernel/drivers/storage/nvme.h kernel/drivers/pci/pci.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/storage/nvme.o $(NVME_SRC)

kernel/drivers/pci/pci.o: $(PCI_SRC) kernel/drivers/pci/pci.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/pci/pci.o $(PCI_SRC)

kernel/fs.o: $(FS_SRC) kernel/fs.h kernel/fs_cache.h kernel/drivers/storage/ata.h kernel/drivers/power/rtc.h
	$(CC) $(CFLAGS) -c -o kernel/fs.o $(FS_SRC)

kernel/fs_cache.o: kernel/fs_cache.cpp kernel/fs_cache.h kernel/fs.h kernel/drivers/storage/ata.h
	$(CC) $(CFLAGS) -c -o kernel/fs_cache.o kernel/fs_cache.cpp

kernel/ramfs.o: kernel/ramfs.cpp kernel/ramfs.h kernel/fs.h kernel/mount.h
	$(CC) $(CFLAGS) -c -o kernel/ramfs.o kernel/ramfs.cpp

kernel/vfs.o: kernel/vfs.cpp kernel/vfs.h kernel/fs.h kernel/mount.h kernel/ramfs.h
	$(CC) $(CFLAGS) -c -o kernel/vfs.o kernel/vfs.cpp

kernel/fs_file.o: kernel/fs_file.cpp kernel/fs_file.h kernel/fs.h kernel/ramfs.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/fs_file.o kernel/fs_file.cpp

kernel/fs_autotest.o: $(FS_AUTOTEST_SRC) kernel/fs_autotest.h kernel/fs.h kernel/serial_log.h
	$(CC) $(CFLAGS) -c -o kernel/fs_autotest.o $(FS_AUTOTEST_SRC)

kernel/utils.o: $(UTILS_SRC) kernel/utils.h
	$(CC) $(CFLAGS) -c -o kernel/utils.o $(UTILS_SRC)

kernel/utils/ls.o: $(LS_SRC) kernel/utils.h kernel/fs.h kernel/drivers/video/terminal.h kernel/kernel.h
	$(CC) $(CFLAGS) -c -o kernel/utils/ls.o $(LS_SRC)

kernel/utils/find.o: $(FIND_SRC) kernel/utils.h kernel/fs.h kernel/drivers/video/terminal.h kernel/kernel.h
	$(CC) $(CFLAGS) -c -o kernel/utils/find.o $(FIND_SRC)

kernel/utils/nano.o: $(NANO_SRC) kernel/utils/nano.h kernel/fs.h kernel/drivers/video/terminal.h kernel/drivers/input/keyboard.h kernel/kernel.h
	$(CC) $(CFLAGS) -c -o kernel/utils/nano.o $(NANO_SRC)

kernel/drivers/storage/disk_manager.o: $(DISK_MANAGER_SRC) kernel/drivers/storage/disk_manager.h kernel/drivers/storage/ata.h kernel/drivers/storage/ahci.h kernel/drivers/storage/nvme.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/storage/disk_manager.o $(DISK_MANAGER_SRC)

kernel/mount.o: $(MOUNT_SRC) kernel/mount.h kernel/drivers/storage/disk_manager.h kernel/fs.h
	$(CC) $(CFLAGS) -c -o kernel/mount.o $(MOUNT_SRC)

kernel/dev.o: $(DEV_SRC) kernel/dev.h kernel/fs.h kernel/drivers/storage/disk_manager.h
	$(CC) $(CFLAGS) -c -o kernel/dev.o $(DEV_SRC)

kernel/driver_manager.o: $(DRIVER_MANAGER_SRC) kernel/driver_manager.h kernel/drivers/pci/pci.h kernel/drivers/storage/ahci.h kernel/drivers/storage/nvme.h kernel/drivers/storage/ata.h kernel/drivers/input/keyboard.h kernel/drivers/video/terminal.h
	$(CC) $(CFLAGS) -c -o kernel/driver_manager.o $(DRIVER_MANAGER_SRC)

kernel/syscall.o: $(SYSCALL_SRC) kernel/syscall.h kernel/driver_manager.h kernel/fs.h kernel/elf.h kernel/sched/task.h kernel/mm/paging.h kernel/drivers/video/terminal.h
	$(CC) $(CFLAGS) -c -o kernel/syscall.o $(SYSCALL_SRC)

kernel/kernel_api.o: $(KERNEL_API_SRC) kernel/kernel_api.h kernel/driver_manager.h
	$(CC) $(CFLAGS) -c -o kernel/kernel_api.o $(KERNEL_API_SRC)

kernel/drivers/network/nic.o: $(NIC_SRC) kernel/drivers/network/nic.h kernel/drivers/pci/pci.h kernel/driver_manager.h kernel/drivers/network/drivers/rtl8139/rtl8139.h kernel/drivers/network/drivers/pcnet/pcnet.h kernel/drivers/network/drivers/virtio_net/virtio_net.h kernel/drivers/network/core/netif.h kernel/drivers/network/core/net_rx.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/nic.o $(NIC_SRC)

kernel/drivers/network/core/skb.o: $(SKB_SRC) kernel/drivers/network/core/skb.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/core/skb.o $(SKB_SRC)

kernel/drivers/network/core/net_queue.o: $(NET_QUEUE_SRC) kernel/drivers/network/core/net_queue.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/core/net_queue.o $(NET_QUEUE_SRC)

kernel/drivers/network/core/netif.o: $(NETIF_SRC) kernel/drivers/network/core/netif.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/core/netif.o $(NETIF_SRC)

kernel/drivers/network/core/net_rx.o: $(NET_RX_SRC) kernel/drivers/network/core/net_rx.h kernel/drivers/network/core/netif.h kernel/drivers/network/protocols/ip.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/core/net_rx.o $(NET_RX_SRC)

kernel/drivers/network/core/net_wait.o: $(NET_WAIT_SRC) kernel/drivers/network/core/net_wait.h kernel/drivers/timer/pit.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/core/net_wait.o $(NET_WAIT_SRC)

kernel/drivers/network/core/net_ports.o: $(NET_PORTS_SRC) kernel/drivers/network/core/net_ports.h kernel/drivers/network/socket.h kernel/drivers/network/protocols/tcp_connection.h kernel/drivers/network/protocols/udp.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/core/net_ports.o $(NET_PORTS_SRC)

kernel/drivers/network/drivers/rtl8139/rtl8139.o: $(RTL8139_SRC) kernel/drivers/network/drivers/rtl8139/rtl8139.h kernel/drivers/network/nic.h kernel/drivers/pci/pci.h kernel/drivers/pic/pic.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/drivers/rtl8139/rtl8139.o $(RTL8139_SRC)

kernel/drivers/network/drivers/pcnet/pcnet.o: $(PCNET_SRC) kernel/drivers/network/drivers/pcnet/pcnet.h kernel/drivers/network/nic.h kernel/drivers/pci/pci.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/drivers/pcnet/pcnet.o $(PCNET_SRC)

kernel/drivers/network/drivers/virtio_net/virtio_net.o: $(VIRTIO_NET_SRC) kernel/drivers/network/drivers/virtio_net/virtio_net.h kernel/drivers/network/nic.h kernel/drivers/pci/pci.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/drivers/virtio_net/virtio_net.o $(VIRTIO_NET_SRC)

kernel/drivers/network/protocols/ethernet.o: $(ETHERNET_SRC) kernel/drivers/network/protocols/ethernet.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/ethernet.o $(ETHERNET_SRC)

kernel/drivers/network/protocols/arp.o: $(ARP_SRC) kernel/drivers/network/protocols/arp.h kernel/drivers/network/protocols/ethernet.h kernel/drivers/network/nic.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/arp.o $(ARP_SRC)

kernel/drivers/network/protocols/ip.o: $(IP_SRC) kernel/drivers/network/protocols/ip.h kernel/drivers/network/protocols/arp.h kernel/drivers/network/protocols/route.h kernel/drivers/network/dhcp/dhcp.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/ip.o $(IP_SRC)

kernel/drivers/network/protocols/route.o: $(ROUTE_SRC) kernel/drivers/network/protocols/route.h kernel/drivers/network/core/netif.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/route.o $(ROUTE_SRC)

kernel/drivers/network/protocols/udp.o: $(UDP_SRC) kernel/drivers/network/protocols/udp.h kernel/drivers/network/protocols/ip.h kernel/drivers/network/protocols/ethernet.h kernel/drivers/network/protocols/arp.h kernel/drivers/network/nic.h kernel/drivers/network/socket.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/udp.o $(UDP_SRC)

kernel/drivers/network/protocols/icmp.o: $(ICMP_SRC) kernel/drivers/network/protocols/icmp.h kernel/drivers/network/protocols/ip.h kernel/drivers/network/protocols/ethernet.h kernel/drivers/network/protocols/arp.h kernel/drivers/network/protocols/tcp_connection.h kernel/drivers/network/nic.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/icmp.o $(ICMP_SRC)

kernel/drivers/network/protocols/tcp.o: $(TCP_SRC) kernel/drivers/network/protocols/tcp.h kernel/drivers/network/protocols/tcp_connection.h kernel/drivers/network/protocols/ip.h kernel/drivers/network/protocols/ethernet.h kernel/drivers/network/protocols/arp.h kernel/drivers/network/nic.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/tcp.o $(TCP_SRC)

kernel/drivers/network/protocols/tcp_connection.o: $(TCP_CONNECTION_SRC) kernel/drivers/network/protocols/tcp_connection.h kernel/drivers/network/protocols/tcp.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/protocols/tcp_connection.o $(TCP_CONNECTION_SRC)

kernel/drivers/network/dns/dns.o: $(DNS_SRC) kernel/drivers/network/dns/dns.h kernel/drivers/network/protocols/udp.h kernel/drivers/network/protocols/ip.h kernel/drivers/network/protocols/tcp_connection.h kernel/serial_log.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/dns/dns.o $(DNS_SRC)

kernel/drivers/network/dhcp/dhcp.o: $(DHCP_SRC) kernel/drivers/network/dhcp/dhcp.h kernel/drivers/network/protocols/udp.h kernel/drivers/network/protocols/ip.h kernel/drivers/network/nic.h kernel/drivers/network/protocols/ethernet.h kernel/drivers/network/protocols/arp.h kernel/drivers/network/dns/dns.h kernel/drivers/network/network_config.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/dhcp/dhcp.o $(DHCP_SRC)

kernel/drivers/network/network_config.o: $(NETWORK_CONFIG_SRC) kernel/drivers/network/network_config.h kernel/drivers/network/dhcp/dhcp.h kernel/drivers/network/protocols/ip.h kernel/drivers/network/dns/dns.h kernel/fs.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/network_config.o $(NETWORK_CONFIG_SRC)

kernel/drivers/network/socket.o: $(SOCKET_SRC) kernel/drivers/network/socket.h kernel/drivers/network/core/net_ports.h kernel/drivers/network/protocols/tcp.h kernel/drivers/network/protocols/udp.h kernel/drivers/network/nic.h kernel/sched/task.h kernel/drivers/timer/pit.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/socket.o $(SOCKET_SRC)

kernel/drivers/network/http_server.o: $(HTTP_SERVER_SRC) kernel/drivers/network/http_server.h kernel/drivers/network/http_protocol.h kernel/drivers/network/socket.h kernel/fs.h kernel/serial_log.h kernel/drivers/timer/pit.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/http_server.o $(HTTP_SERVER_SRC)

kernel/drivers/network/remote_shell.o: kernel/drivers/network/remote_shell.cpp kernel/drivers/network/remote_shell.h kernel/drivers/network/socket.h kernel/fs.h kernel/vfs.h kernel/utils.h kernel/user_auth.h kernel/string.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/remote_shell.o kernel/drivers/network/remote_shell.cpp

kernel/drivers/network/ftp_server.o: kernel/drivers/network/ftp_server.cpp kernel/drivers/network/ftp_server.h kernel/drivers/network/socket.h kernel/fs.h kernel/fs_file.h kernel/vfs.h kernel/utils.h kernel/user_auth.h kernel/string.h kernel/sched/task.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/ftp_server.o kernel/drivers/network/ftp_server.cpp

kernel/crypto/sha256.o: kernel/crypto/sha256.cpp kernel/crypto/sha256.h
	$(CC) $(CFLAGS) -c -o kernel/crypto/sha256.o kernel/crypto/sha256.cpp

kernel/crypto/chacha20poly1305.o: kernel/crypto/chacha20poly1305.cpp kernel/crypto/chacha20poly1305.h
	$(CC) $(CFLAGS) -c -o kernel/crypto/chacha20poly1305.o kernel/crypto/chacha20poly1305.cpp

kernel/crypto/x25519.o: kernel/crypto/x25519.cpp kernel/crypto/x25519.h
	$(CC) $(CFLAGS) -c -o kernel/crypto/x25519.o kernel/crypto/x25519.cpp

kernel/drivers/network/http_protocol.o: $(HTTP_PROTOCOL_SRC) kernel/drivers/network/http_protocol.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/http_protocol.o $(HTTP_PROTOCOL_SRC)

kernel/drivers/network/http_gzip.o: $(HTTP_GZIP_SRC) kernel/drivers/network/http_gzip.h
	$(CC) $(CFLAGS) -c -o kernel/drivers/network/http_gzip.o $(HTTP_GZIP_SRC)

clean:
	rm -f $(KERNEL_OBJ) $(KERNEL_BIN) $(ISO) user/hello.o user/hello.elf user/demo2.o user/demo2.elf user/demo3.o user/demo3.elf user/launcher.o user/launcher.elf

.PHONY: all check clean

kernel/crypto/crypto_selftest.o: kernel/crypto/crypto_selftest.cpp kernel/crypto/sha256.h kernel/crypto/chacha20poly1305.h kernel/crypto/x25519.h
	$(CC) $(CFLAGS) -c -o kernel/crypto/crypto_selftest.o kernel/crypto/crypto_selftest.cpp
