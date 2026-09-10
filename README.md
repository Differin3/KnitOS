<div align="center">

# KnitOS

**A from-scratch 32-bit x86 hobby operating system** — GRUB Multiboot2 boot, a custom on-disk filesystem, storage & network drivers, user accounts with permissions, and an interactive multi-session shell.

[![CI](https://github.com/Differin3/KnitOS/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Differin3/KnitOS/actions/workflows/c-cpp.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-i686%20(x86)-lightgrey.svg)](#requirements)
[![Version](https://img.shields.io/badge/version-0.2.5-informational.svg)](#)

</div>

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Build](#build)
- [Run in QEMU](#run-in-qemu)
- [First boot & login](#first-boot--login)
- [Shell reference](#shell-reference)
- [Testing & CI](#testing--ci)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

KnitOS is a monolithic **32-bit x86** kernel that boots via **GRUB Multiboot2** and runs entirely from scratch — no libc, no external runtime. It ships its own bootloader glue, interrupt/IDT setup, paging, scheduler, VGA/framebuffer console, block-storage stack (ATA / AHCI / NVMe), a custom **MOS** filesystem with journaling, a full **TCP/IP** stack, and a POSIX-flavoured shell.

It targets both **VGA text mode** and **framebuffer** consoles, runs in QEMU, and can be exercised over a **serial console** (`COM1`) — which makes it easy to script and test.

```
KnitOS 0.2.5 (dev-disk-AHCI-PCI)
```

## Features

<table>
<tr><td valign="top" width="50%">

**Kernel & core**
- Multiboot2 boot, 32-bit protected mode
- IDT, PIC, PIT (100 Hz), ACPI (S5 + reset), RTC
- Paging, heap, kernel threads
- Round-robin scheduler with user (ring-3) tasks
- Ring-3 isolation + safe syscall buffers
- Freestanding string/memory library

**Storage & filesystem**
- Legacy ATA (PIO), AHCI (SATA), NVMe drivers
- `disk_manager` — probing + controller selection
- **MOS** filesystem: inodes, extents, dirents, journal
- Symlinks, xattrs, VFS layer, fd API
- RAMFS (`/tmp`), mount points

</td><td valign="top" width="50%">

**Networking**
- Ethernet, ARP, IPv4 (with reassembly), ICMP
- UDP, TCP (connections + retransmit timers)
- DHCP client, DNS resolver
- Sockets API + TCP/UDP echo servers
- HTTP/1.1 server (`/www`, Keep-Alive) & client
- `ping`, `traceroute`, `tcpdump`, `ifconfig`

**Users, security & shell**
- User accounts (`/etc/passwd`, `/etc/shadow`, `/etc/group`)
- Salted password hashing, login screen at boot
- POSIX-style permissions (owner/group/other)
- `chmod`, `chown`, `chgrp`, `su`, `useradd`, `userdel`
- Independent shell **sessions**
- Line editor: history, Tab-completion, cursor movement

</td></tr>
</table>

## Architecture

| Layer | Location | Notes |
|-------|----------|-------|
| Boot | `boot/` | Multiboot2 entry, IDT stubs, embedded user binaries |
| Core kernel | `kernel/` | Main, scheduler, syscalls, VFS, MOS FS |
| Drivers | `kernel/drivers/` | video, input, timer, power, PCI, storage, network |
| User programs | `user/` | Freestanding ELF binaries (`hello`, `demo2/3`, `launcher`) |
| Docs | `docs/` | Driver manager, kernel API, syscall API, network tests |

## Requirements

Build and run on **Linux or WSL**:

- `nasm`
- `gcc` / `g++` with 32-bit multilib (`gcc-multilib`, `g++-multilib`)
- `binutils` (`ld`)
- `grub-pc-bin` / `grub-common` (`grub-mkrescue`) and `xorriso`
- `qemu-system-i386` (for testing)

```bash
# Debian / Ubuntu
sudo apt install nasm gcc-multilib g++-multilib binutils grub-pc-bin xorriso qemu-system-x86
```

## Build

```bash
make            # build myos.iso
make check      # build + verify artifacts
make clean
```

On Windows, from the project folder:

```bat
build.bat
```

**Output:** `myos.iso` and `iso/boot/kernel.bin`.

## Run in QEMU

```bash
qemu-system-i386 -cdrom myos.iso
```

With user networking (RTL8139 — needed for DHCP / ping / DNS / HTTP):

```bash
mkdir -p logs
qemu-system-i386 -cdrom myos.iso \
  -netdev user,id=net0 -device rtl8139,netdev=net0 \
  -serial file:logs/qemu-serial.log
```

With an AHCI (SATA) disk for persistent storage:

```bash
qemu-system-i386 -cdrom myos.iso \
  -drive file=myos.img,if=none,format=raw,id=disk0 \
  -device ich9-ahci,id=ahci0 -device ide-hd,drive=disk0,bus=ahci0.0 \
  -netdev user,id=net0 -device rtl8139,netdev=net0 \
  -serial file:logs/qemu-serial.log
```

Legacy IDE instead of AHCI:

```bash
qemu-system-i386 -cdrom myos.iso -drive file=myos.img,if=ide,index=0,media=disk \
  -netdev user,id=net0 -device rtl8139,netdev=net0 -serial file:logs/qemu-serial.log
```

Serial output is mirrored to `logs/qemu-serial.log` (boot banner, shell commands, driver events, network traces).

> **Windows helpers:** `run-qemu.bat`, `run-qemu-ahci.bat`, `run-qemu-ide.bat`, `view-log.bat`.

## First boot & login

On startup KnitOS presents a login screen:

```
KnitOS login: _
```

| Account | UID | Password |
|---------|-----|----------|
| `root`  | 0   | *(empty — press Enter)* |
| `demo`  | 1000| `demo` |

Set a root password any time with `passwd root`. After login the prompt shows the current user:

```
root > _
demo > _
```

## Shell reference

### System & sessions

| Command | Description |
|---------|-------------|
| `help` / `?` | List all commands |
| `version` | Kernel name, version, build |
| `date` / `setdate` / `settime` | RTC time |
| `ps` / `kill <pid>` | Tasks |
| `reboot` / `shutdown` / `poweroff` | Power control |
| `acpi` | ACPI tables / S5 info |
| `sessions` | List console sessions |
| `newsession <name>` | Create an independent session |
| `session <n>` | Switch to session *n* |
| `clear` / `echo` / `log [off\|err\|info\|debug]` | Console & logging |

### Filesystem

| Command | Description |
|---------|-------------|
| `ls [-l] [-a] [path]` | List directory |
| `cd` / `pwd` | Change / print directory |
| `cat <file>` / `write <file> <text>` | Read / create file |
| `rm [-r] <path>` / `cp` / `mv` / `ln [-s]` | File operations |
| `mkdir [-p]` / `touch` / `stat` / `du` / `df` | Directory & metadata |
| `nano <file>` | Full-screen editor (`^O` save, `^X` exit) |
| `find [path] [-name P] [-type f\|d]` | Search |
| `disk` / `mount` / `fsck` / `sync` | Storage |

### Users & permissions

| Command | Description |
|---------|-------------|
| `login [user]` / `logout` | Session login / logout |
| `whoami` / `id` / `users` / `groups [user]` | Identity |
| `useradd <name> [uid]` | Create user (+ home dir) |
| `userdel <name>` | Delete user |
| `usermod <name> [newname] [uid] [gid]` | Modify user |
| `passwd [user]` | Set password (hidden input) |
| `groupadd <name> [gid]` | Create group |
| `su [user]` | Switch user |
| `chmod <mode> <path>` / `chown <uid>` / `chgrp <gid>` | Permissions |

### Networking

| Command | Description |
|---------|-------------|
| `network` / `ifconfig` | Interface status |
| `dhcp` / `network static <ip> [gw] [dns] [mask]` | Configure IP |
| `ping <host> [count]` | ICMP echo |
| `traceroute <host>` | ICMP TTL path trace |
| `tcpdump [count] [tcp\|udp\|icmp\|ip] [port N] [host IP]` | Capture frames |
| `dns` / `dns <host>` | DNS server / resolve |
| `arp` / `route [ip]` / `netstat` / `ports` | Tables |
| `udp` / `tcp` / `udplisten` / `tcp listen` | Send / listen |
| `httpserver [port] [max]` | HTTP/1.1 static server |
| `httpget <host> [path]` | HTTP client |
| `socktest tcp\|udp <port>` | Socket API echo test |

**Keyboard:** `Up`/`Down` history · `Tab` completion (2× list, 3× cycle) · `Left`/`Right`/`Home`/`End` cursor · `Ctrl+C` cancel · `Ctrl+L` clear.

## Testing & CI

Continuous integration builds the kernel and ISO on every push / pull request using the workflow in [`.github/workflows/c-cpp.yml`](.github/workflows/c-cpp.yml):

```bash
make clean && make -j"$(nproc)"     # clean build
make check                          # verify kernel.bin + myos.iso
```

The built `myos.iso` is uploaded as a workflow artifact.

On Windows there is a scripted end-to-end test (QEMU → serial → `autotest network` → HTTP):

```bat
tests\auto-test.bat
```

Logs: `logs/auto-test.log`, `logs/qemu-serial.log`. See [docs/NETWORK_TESTS.md](docs/NETWORK_TESTS.md).

## Documentation

- [Driver manager](docs/DRIVER_MANAGER.md)
- [Kernel API](docs/KERNEL_API.md)
- [Syscall API](docs/SYSCALL_API.md)
- [Network tests](docs/NETWORK_TESTS.md)

## License

Released under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).
