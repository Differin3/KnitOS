<div align="center">

# KnitOS

**Хобби-операционная система для 32-битного x86, написанная с нуля** — загрузка через GRUB Multiboot2, собственная файловая система на диске, драйверы хранения и сети, учётные записи пользователей с правами доступа и интерактивная многосессионная оболочка.

[![CI](https://github.com/Differin3/KnitOS/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Differin3/KnitOS/actions/workflows/c-cpp.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-i686%20(x86)-lightgrey.svg)](#требования)
[![Version](https://img.shields.io/badge/version-0.2.5-informational.svg)](#)

**[English](README.md) · Русский**

</div>

---

## Содержание

- [Обзор](#обзор)
- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Требования](#требования)
- [Сборка](#сборка)
- [Запуск в QEMU](#запуск-в-qemu)
- [Первый запуск и вход](#первый-запуск-и-вход)
- [Справочник команд](#справочник-команд)
- [Тестирование и CI](#тестирование-и-ci)
- [Документация](#документация)
- [Лицензия](#лицензия)

---

## Обзор

KnitOS — монолитное ядро для **32-битного x86**, загружаемое через **GRUB Multiboot2** и работающее полностью с нуля — без libc и внешнего рантайма. Включает собственный загрузчик-обвязку, настройку IDT/прерываний, страничную адресацию, планировщик, VGA/framebuffer-консоль, стек блочных устройств (ATA / AHCI / NVMe), собственную файловую систему **MOS** с журналированием, полноценный стек **TCP/IP** и POSIX-подобную оболочку.

Поддерживает как **текстовый режим VGA**, так и **framebuffer**-консоль, работает в QEMU и может управляться через **serial-консоль** (`COM1`) — что удобно для автоматизации и тестов.

```
KnitOS 0.2.5 (dev-disk-AHCI-PCI)
```

## Возможности

<table>
<tr><td valign="top" width="50%">

**Ядро и базовая часть**
- Загрузка Multiboot2, 32-битный защищённый режим
- IDT, PIC, PIT (100 Гц), ACPI (S5 + reset), RTC
- Страничная адресация, куча, потоки ядра
- Round-robin планировщик с пользовательскими задачами (ring-3)
- Изоляция ring-3 + безопасные буферы syscall
- Собственная библиотека string/memory (без libc)

**Хранение и файловая система**
- Драйверы legacy ATA (PIO), AHCI (SATA), NVMe
- `disk_manager` — опрос и выбор контроллера
- ФС **MOS**: inode, экстенты, dirent, журнал
- Симлинки, xattr, слой VFS, fd API
- RAMFS (`/tmp`), точки монтирования

</td><td valign="top" width="50%">

**Сеть**
- Ethernet, ARP, IPv4 (со сборкой фрагментов), ICMP
- UDP, TCP (соединения + таймеры ретрансмита)
- DHCP-клиент, DNS-резолвер
- Sockets API + TCP/UDP echo-серверы
- HTTP/1.1 сервер (`/www`, Keep-Alive) и клиент
- `ping`, `traceroute`, `tcpdump`, `ifconfig`

**Пользователи, безопасность и оболочка**
- Учётные записи (`/etc/passwd`, `/etc/shadow`, `/etc/group`)
- Хеширование паролей с солью, экран входа при загрузке
- Права в стиле POSIX (владелец/группа/прочие)
- `chmod`, `chown`, `chgrp`, `su`, `useradd`, `userdel`
- Независимые сессии оболочки
- Редактор строки: история, автодополнение Tab, перемещение курсора

</td></tr>
</table>

## Архитектура

| Слой | Расположение | Примечания |
|------|--------------|------------|
| Загрузка | `boot/` | Точка входа Multiboot2, заглушки IDT, встроенные user-бинарники |
| Ядро | `kernel/` | Main, планировщик, syscall, VFS, ФС MOS |
| Драйверы | `kernel/drivers/` | видео, ввод, таймер, питание, PCI, хранение, сеть |
| Пользовательские программы | `user/` | Freestanding ELF (`hello`, `demo2/3`, `launcher`) |
| Документация | `docs/` | Driver manager, kernel API, syscall API, тесты сети |

## Требования

Сборка и запуск — **Linux или WSL**:

- `nasm`
- `gcc` / `g++` с поддержкой 32-битного multilib (`gcc-multilib`, `g++-multilib`)
- `binutils` (`ld`)
- `grub-pc-bin` / `grub-common` (`grub-mkrescue`) и `xorriso`
- `qemu-system-i386` (для тестирования)

```bash
# Debian / Ubuntu
sudo apt install nasm gcc-multilib g++-multilib binutils grub-pc-bin xorriso qemu-system-x86
```

## Сборка

```bash
make            # собрать myos.iso
make check      # сборка + проверка артефактов
make clean
```

В Windows из папки проекта:

```bat
build.bat
```

**Результат:** `myos.iso` и `iso/boot/kernel.bin`.

## Запуск в QEMU

```bash
qemu-system-i386 -cdrom myos.iso
```

С пользовательской сетью (RTL8139 — нужна для DHCP / ping / DNS / HTTP):

```bash
mkdir -p logs
qemu-system-i386 -cdrom myos.iso \
  -netdev user,id=net0 -device rtl8139,netdev=net0 \
  -serial file:logs/qemu-serial.log
```

С AHCI (SATA)-диском для постоянного хранения:

```bash
qemu-system-i386 -cdrom myos.iso \
  -drive file=myos.img,if=none,format=raw,id=disk0 \
  -device ich9-ahci,id=ahci0 -device ide-hd,drive=disk0,bus=ahci0.0 \
  -netdev user,id=net0 -device rtl8139,netdev=net0 \
  -serial file:logs/qemu-serial.log
```

Legacy IDE вместо AHCI:

```bash
qemu-system-i386 -cdrom myos.iso -drive file=myos.img,if=ide,index=0,media=disk \
  -netdev user,id=net0 -device rtl8139,netdev=net0 -serial file:logs/qemu-serial.log
```

Serial-вывод зеркалируется в `logs/qemu-serial.log` (баннер загрузки, команды оболочки, события драйверов, трассировка сети).

> **Хелперы для Windows:** `run-qemu.bat`, `run-qemu-ahci.bat`, `run-qemu-ide.bat`, `view-log.bat`.

## Первый запуск и вход

При старте KnitOS показывает экран входа:

```
KnitOS login: _
```

| Учётка | UID | Пароль |
|--------|-----|--------|
| `root`  | 0    | *(пустой — нажать Enter)* |
| `demo`  | 1000 | `demo` |

Пароль root можно задать командой `passwd root`. После входа приглашение показывает текущего пользователя:

```
root > _
demo > _
```

## Справочник команд

### Система и сессии

| Команда | Описание |
|---------|----------|
| `help` / `?` | Список всех команд |
| `version` | Имя ядра, версия, сборка |
| `date` / `setdate` / `settime` | Время RTC |
| `ps` / `kill <pid>` | Задачи |
| `reboot` / `shutdown` / `poweroff` | Питание |
| `acpi` | Информация об ACPI / S5 |
| `sessions` | Список консольных сессий |
| `newsession <name>` | Создать независимую сессию |
| `session <n>` | Переключиться на сессию *n* |
| `clear` / `echo` / `log [off\|err\|info\|debug]` | Консоль и логирование |

### Файловая система

| Команда | Описание |
|---------|----------|
| `ls [-l] [-a] [path]` | Список каталога |
| `cd` / `pwd` | Сменить / показать каталог |
| `cat <file>` / `write <file> <text>` | Чтение / создание файла |
| `rm [-r] <path>` / `cp` / `mv` / `ln [-s]` | Операции с файлами |
| `mkdir [-p]` / `touch` / `stat` / `du` / `df` | Каталоги и метаданные |
| `nano <file>` | Полноэкранный редактор (`^O` — сохранить, `^X` — выход) |
| `find [path] [-name P] [-type f\|d]` | Поиск |
| `disk` / `mount` / `fsck` / `sync` | Хранение |

### Пользователи и права

| Команда | Описание |
|---------|----------|
| `login [user]` / `logout` | Вход / выход из сессии |
| `whoami` / `id` / `users` / `groups [user]` | Идентификация |
| `useradd <name> [uid]` | Создать пользователя (+ домашний каталог) |
| `userdel <name>` | Удалить пользователя |
| `usermod <name> [newname] [uid] [gid]` | Изменить пользователя |
| `passwd [user]` | Задать пароль (скрытый ввод) |
| `groupadd <name> [gid]` | Создать группу |
| `su [user]` | Сменить пользователя |
| `chmod <mode> <path>` / `chown <uid>` / `chgrp <gid>` | Права доступа |

### Сеть

| Команда | Описание |
|---------|----------|
| `network` / `ifconfig` | Состояние интерфейса |
| `dhcp` / `network static <ip> [gw] [dns] [mask]` | Настройка IP |
| `ping <host> [count]` | ICMP echo |
| `traceroute <host>` | Трассировка пути по TTL |
| `tcpdump [count] [tcp\|udp\|icmp\|ip] [port N] [host IP]` | Захват фреймов |
| `dns` / `dns <host>` | DNS-сервер / резолв |
| `arp` / `route [ip]` / `netstat` / `ports` | Таблицы |
| `udp` / `tcp` / `udplisten` / `tcp listen` | Отправка / прослушивание |
| `httpserver [port] [max]` | HTTP/1.1 статический сервер |
| `httpget <host> [path]` | HTTP-клиент |
| `socktest tcp\|udp <port>` | Тест Socket API |

**Клавиатура:** `Up`/`Down` — история · `Tab` — автодополнение (2× список, 3× перебор) · `Left`/`Right`/`Home`/`End` — курсор · `Ctrl+C` — отмена · `Ctrl+L` — очистка.

## Тестирование и CI

Непрерывная интеграция собирает ядро и ISO при каждом push / pull request через workflow в [`.github/workflows/c-cpp.yml`](.github/workflows/c-cpp.yml):

```bash
make clean && make -j"$(nproc)"     # чистая сборка
make check                          # проверка kernel.bin + myos.iso
```

Собранный `myos.iso` выгружается как артефакт workflow.

В Windows есть сквозной автотест (QEMU → serial → `autotest network` → HTTP):

```bat
tests\auto-test.bat
```

Логи: `logs/auto-test.log`, `logs/qemu-serial.log`. См. [docs/NETWORK_TESTS.md](docs/NETWORK_TESTS.md).

## Документация

- [Driver manager](docs/DRIVER_MANAGER.md)
- [Kernel API](docs/KERNEL_API.md)
- [Syscall API](docs/SYSCALL_API.md)
- [Network tests](docs/NETWORK_TESTS.md)

## Лицензия

Распространяется под лицензией **GNU General Public License v3.0** — см. [LICENSE](LICENSE).
