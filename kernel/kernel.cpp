#include "kernel.h"
#include "idt.h"
#include "drivers/input/keyboard.h"
#include "drivers/video/terminal.h"
#include "drivers/storage/ata.h"
#include "fs.h"
#include "vfs.h"
#include "fs_file.h"
#include "ramfs.h"
#include "mount.h"
#include "fs_file.h"
#include "fs_autotest.h"
#include "utils.h"
#include "utils/nano.h"
#include "drivers/storage/disk_manager.h"
#include "mount.h"
#include "dev.h"
#include "driver_manager.h"
#include "syscall.h"
#include "drivers/network/nic.h"
#include "drivers/network/protocols/tcp.h"
#include "drivers/network/dns/dns.h"
#include "drivers/network/protocols/tcp_connection.h"
#include "drivers/network/dhcp/dhcp.h"
#include "drivers/network/protocols/ip.h"
#include "drivers/network/protocols/icmp.h"
#include "drivers/network/protocols/arp.h"
#include "drivers/network/protocols/udp.h"
#include "drivers/network/network_config.h"
#include "drivers/network/socket.h"
#include "drivers/network/http_server.h"
#include "drivers/network/remote_shell.h"
#include "drivers/network/ftp_server.h"
#include "crypto/sha256.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/x25519.h"
#include "drivers/network/core/netif.h"
#include "drivers/network/core/net_ports.h"
#include "drivers/network/core/capture.h"
#include "drivers/network/protocols/ethernet.h"
#include "drivers/network/protocols/route.h"
#include "drivers/pic/pic.h"
#include "drivers/timer/pit.h"
#include "drivers/power/acpi.h"
#include "drivers/power/rtc.h"
#include "sched/task.h"
#include "pty.h"
#include "kcmd.h"
#include "serial_log.h"
#include "user_auth.h"
#include "mm/paging.h"
#include "vga_autotest.h"
#include "keyboard_autotest.h"
#include "user_autotest.h"
#include "heap.h"
#include "string.h"
#include <stddef.h>
#include <stdint.h>

/* Текущий логин (имя пользователя консольной сессии) хранится в struct shell_session
   (см. макрос g_login_user внутри kernel_main). Отдельного глобала нет. */

/* ---- Независимые консольные сессии (задел под SSH) ----
   Каждая сессия хранит собственное состояние интерактивного редактора:
   буфер строки, историю команд, таб-завершение, uid/gid, логин и cwd.
   Для одной физической консоли активна одна сессия (foreground); остальные
   сохраняют своё состояние и переключаются. */
#define SESS_MAX     8
#define SESS_HIST    24
#define SESS_LINE    128

struct shell_session {
    int      id;
    bool     used;
    char     name[16];
    uint16_t uid;
    uint16_t gid;
    char     login[UNAME_MAX];

    char     sbuf[SESS_LINE];      /* editor line buffer */
    size_t   blen;                 /* line length */
    size_t   cpos;                 /* cursor index within line (0..blen) */
    size_t   prow;                 /* prompt screen row */
    size_t   pcol;                 /* prompt screen col */
    char     cwd[SESS_LINE];

    size_t   tabll;                /* tab: last line len */
    size_t   tabls;                /* tab: last word start */
    int      tabci;                /* tab: cycle idx */

    char     hist[SESS_HIST][SESS_LINE];
    size_t   hlen[SESS_HIST];
    int      hcnt;
    int      hpos;
    char     hdraft[SESS_LINE];
    size_t   hdlen;
    bool     hhas;
};

static struct shell_session g_sessions[SESS_MAX];
static int g_session_count = 0;
static int g_current_session = 0;

static struct shell_session* cur_session(void) {
    return &g_sessions[g_current_session];
}

/* Из crypto/crypto_selftest.cpp */
int crypto_selftest_run(void);

static void shell_write_ip(uint32_t ip) {
    char buf[20];
    ip_format_address(ip, buf, sizeof(buf));
    terminal_writestring(buf);
}

/* Проверка, что name — отдельный токен в CSV-списке (members групп). */
static bool csv_has_token(const char* list, const char* name) {
    if (!list || !name || !name[0]) return false;
    size_t nlen = 0;
    while (name[nlen]) nlen++;
    const char* m = list;
    while (*m) {
        while (*m == ',' || *m == ' ') m++;
        const char* start = m;
        while (*m && *m != ',') m++;
        size_t tlen = (size_t)(m - start);
        while (tlen > 0 && (start[tlen - 1] == ' ' || start[tlen - 1] == '\t')) tlen--;
        if (tlen == nlen && strncmp(start, name, nlen) == 0) return true;
    }
    return false;
}

static bool shell_parse_u16_token(const char* s, size_t len, size_t* pos, uint16_t* out) {
    while (*pos < len && s[*pos] == ' ') (*pos)++;
    if (*pos >= len) return false;
    uint32_t v = 0;
    size_t start = *pos;
    while (*pos < len && s[*pos] >= '0' && s[*pos] <= '9') {
        v = v * 10 + (uint32_t)(s[*pos] - '0');
        if (v > 65535) return false;
        (*pos)++;
    }
    if (*pos == start || v == 0) return false;
    *out = (uint16_t)v;
    return true;
}

struct arp_print_ctx {
    int count;
};

static void arp_shell_print(uint32_t ip, const uint8_t* mac, void* userdata) {
    struct arp_print_ctx* ctx = (struct arp_print_ctx*)userdata;
    ctx->count++;
    terminal_writestring("\n");
    shell_write_ip(ip);
    terminal_writestring("  ");
    for (int i = 0; i < 6; i++) {
        if (i > 0) terminal_putchar(':');
        uint8_t b = mac[i];
        char hex[3];
        uint8_t hi = (b >> 4) & 0xF;
        uint8_t lo = b & 0xF;
        hex[0] = (char)(hi < 10 ? '0' + hi : 'A' + hi - 10);
        hex[1] = (char)(lo < 10 ? '0' + lo : 'A' + lo - 10);
        hex[2] = 0;
        terminal_writestring(hex);
    }
}

static const char* tcp_state_str(enum tcp_state s) {
    switch (s) {
        case TCP_CLOSED: return "CLOSED";
        case TCP_LISTEN: return "LISTEN";
        case TCP_SYN_SENT: return "SYN_SENT";
        case TCP_SYN_RECEIVED: return "SYN_RECV";
        case TCP_ESTABLISHED: return "ESTABLISHED";
        case TCP_FIN_WAIT_1: return "FIN_WAIT1";
        case TCP_FIN_WAIT_2: return "FIN_WAIT2";
        case TCP_CLOSE_WAIT: return "CLOSE_WAIT";
        case TCP_CLOSING: return "CLOSING";
        case TCP_TIME_WAIT: return "TIME_WAIT";
        case TCP_LAST_ACK: return "LAST_ACK";
        default: return "?";
    }
}

static void shell_write_u32(uint32_t v) {
    char tmp[12];
    int t = 0;
    if (v == 0) {
        terminal_putchar('0');
        return;
    }
    while (v > 0 && t < 11) {
        tmp[t++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (t > 0) {
        terminal_putchar(tmp[--t]);
    }
}

static void idle_kthread(void* arg) {
    (void)arg;
    while (1) {
        asm volatile ("hlt");
        sched_yield();
    }
}

static void ps_shell_print(const struct task* t, void* userdata) {
    int* count = (int*)userdata;
    if (count) (*count)++;
    terminal_writestring("\n");
    shell_write_u32((uint32_t)t->id);
    terminal_writestring("  ");
    terminal_writestring(t->name);
    terminal_writestring("  ");
    uint8_t old = terminal_getcolor();
    uint8_t stc = 0x07;
    if (t->state == TASK_RUNNING || t->state == TASK_READY) stc = 0x0A;
    else if (t->state == TASK_BLOCKED) stc = 0x0E;
    else if (t->state == TASK_ZOMBIE) stc = 0x0C;
    terminal_setcolor(stc);
    terminal_writestring(task_state_str(t->state));
    terminal_setcolor(old);
    terminal_writestring("  runs=");
    shell_write_u32(t->runs);
}

static void shell_write_port(uint16_t port) {
    shell_write_u32(port);
}

static void netstat_shell_print(struct tcp_connection* conn, void* userdata) {
    struct arp_print_ctx* ctx = (struct arp_print_ctx*)userdata;
    if (conn->state == TCP_CLOSED) return;
    ctx->count++;
    terminal_writestring("\n");
    shell_write_ip(conn->src_ip);
    terminal_putchar(':');
    shell_write_port(conn->src_port);
    terminal_writestring(" -> ");
    shell_write_ip(conn->dest_ip);
    terminal_putchar(':');
    shell_write_port(conn->dest_port);
    terminal_writestring(" ");
    terminal_writestring(tcp_state_str(conn->state));
    char owner[NET_OWNER_MAX];
    int pid = 0;
    net_ports_lookup_owner(NET_PROTO_TCP, conn->src_port, owner, sizeof(owner), &pid);
    terminal_writestring("  pid=");
    shell_write_u32((uint32_t)pid);
    terminal_writestring(" ");
    terminal_writestring(owner);
}

static void ports_shell_print(const struct net_port_info* info, void* userdata) {
    struct arp_print_ctx* ctx = (struct arp_print_ctx*)userdata;
    ctx->count++;
    terminal_writestring("\n");
    terminal_writestring(net_port_proto_str(info->proto));
    terminal_writestring("  ");
    shell_write_ip(info->local_ip);
    terminal_putchar(':');
    shell_write_port(info->local_port);
    terminal_writestring("  ");
    if (info->remote_port == 0 && info->remote_ip == 0) {
        terminal_writestring("0.0.0.0:*");
    } else {
        shell_write_ip(info->remote_ip);
        terminal_putchar(':');
        shell_write_port(info->remote_port);
    }
    terminal_writestring("  ");
    {
        uint8_t old = terminal_getcolor();
        uint8_t stc = 0x07;
        if (info->state == NETPORT_LISTEN) stc = 0x0B;
        else if (info->state == NETPORT_ESTABLISHED) stc = 0x0A;
        terminal_setcolor(stc);
        terminal_writestring(net_port_state_str(info->state));
        terminal_setcolor(old);
    }
    terminal_writestring("  pid=");
    shell_write_u32((uint32_t)info->pid);
    terminal_writestring("  ");
    terminal_writestring(info->owner);
    if (info->sock_fd >= 0) {
        terminal_writestring("  fd=");
        shell_write_u32((uint32_t)info->sock_fd);
    }
}

/* ---- tcpdump: простая перехват фреймов с фильтрами ---- */
static inline uint32_t net_to_host32(uint32_t v) {
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) | ((v >> 8) & 0xFF00u) | ((v >> 24) & 0xFFu);
}
static inline uint16_t net_to_host16(uint16_t v) {
    return (uint16_t)(((v & 0xFFu) << 8) | ((v >> 8) & 0xFFu));
}
static int  tcpdump_remaining = 0;   /* сколько пакетов ещё показать (0 = стоп) */
static uint16_t tcpdump_filter_etype = 0; /* ETH_TYPE_* или 0 (любой) */
static uint8_t  tcpdump_filter_proto = 0; /* IP_PROTOCOL_* или 0 (любой) */
static bool     tcpdump_filter_ipv4 = false; /* только IPv4 (фильтр "ip") */
static uint16_t tcpdump_filter_port = 0;  /* 0 = любой порт */
static uint32_t tcpdump_filter_ip = 0;    /* 0 = любой IP (src или dst) */

static void tcpdump_write_mac(const uint8_t* mac) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 6; i++) {
        if (i > 0) terminal_putchar(':');
        terminal_putchar(hx[mac[i] >> 4]);
        terminal_putchar(hx[mac[i] & 0xF]);
    }
}

static const char* tcpdump_proto_name(uint8_t p) {
    switch (p) {
        case IP_PROTOCOL_TCP:  return "TCP";
        case IP_PROTOCOL_UDP:  return "UDP";
        case IP_PROTOCOL_ICMP: return "ICMP";
        default:               return "IP";
    }
}

static void tcpdump_capture(struct netif* nif, int dir, const void* frame, size_t len) {
    (void)nif;
    if (tcpdump_remaining <= 0) return;

    struct ethernet_header eth;
    const void* pl;
    size_t plen;
    if (ethernet_parse_header(frame, len, &eth, &pl, &plen) != 0) return;
    uint16_t etype = (uint16_t)(((eth.type & 0xFF) << 8) | ((eth.type >> 8) & 0xFF));

    /* Протокольный фильтр (tcp/udp/icmp) относится только к IPv4. */
    if (tcpdump_filter_proto && etype != ETH_TYPE_IPV4) return;
    if (tcpdump_filter_ipv4 && etype != ETH_TYPE_IPV4) return;

    if (etype == ETH_TYPE_ARP) {
        if (tcpdump_filter_etype && tcpdump_filter_etype != ETH_TYPE_ARP) return;
        terminal_writestring("\n");
        terminal_writestring(dir ? "out " : "in  ");
        terminal_writestring("ARP ");
        tcpdump_write_mac(eth.src_mac);
        terminal_writestring(" > ");
        tcpdump_write_mac(eth.dest_mac);
        if (plen >= sizeof(struct arp_packet)) {
            const struct arp_packet* arp = (const struct arp_packet*)pl;
            uint16_t op = (uint16_t)(((arp->operation & 0xFF) << 8) | ((arp->operation >> 8) & 0xFF));
            terminal_writestring(op == ARP_OP_REQUEST ? " request " : " reply   ");
            shell_write_ip(net_to_host32(arp->target_ip));
            terminal_writestring(" ? ");
            shell_write_ip(net_to_host32(arp->sender_ip));
        }
        if (tcpdump_remaining > 0) tcpdump_remaining--;
        return;
    }

    if (etype == ETH_TYPE_IPV4) {
        struct ip_header iph;
        const void* ippl;
        size_t ippl_len;
        if (plen < sizeof(struct ip_header)) return;
        const struct ip_header* rawh = (const struct ip_header*)pl;
        uint8_t ihl = (uint8_t)((rawh->version_ihl & 0x0F) * 4);
        if (ihl < sizeof(struct ip_header)) ihl = sizeof(struct ip_header);
        if (ihl > plen) return;
        iph.src_ip = net_to_host32(rawh->src_ip);
        iph.dest_ip = net_to_host32(rawh->dest_ip);
        iph.protocol = rawh->protocol;
        ippl = (const uint8_t*)pl + ihl;
        ippl_len = plen - ihl;
        if (tcpdump_filter_etype && tcpdump_filter_etype != ETH_TYPE_IPV4) return;
        if (tcpdump_filter_proto && tcpdump_filter_proto != iph.protocol) return;
        if (tcpdump_filter_ip && tcpdump_filter_ip != iph.src_ip && tcpdump_filter_ip != iph.dest_ip) return;

        /* Порт-фильтр проверяем ДО вывода, иначе печатается обрубок строки. */
        uint16_t sport = 0, dport = 0;
        bool has_ports = false;
        if (iph.protocol == IP_PROTOCOL_TCP && ippl_len >= 20) {
            const struct tcp_header* t = (const struct tcp_header*)ippl;
            sport = net_to_host16(t->src_port);
            dport = net_to_host16(t->dest_port);
            has_ports = true;
        } else if (iph.protocol == IP_PROTOCOL_UDP && ippl_len >= 8) {
            const struct udp_header* u = (const struct udp_header*)ippl;
            sport = net_to_host16(u->src_port);
            dport = net_to_host16(u->dest_port);
            has_ports = true;
        }
        if (tcpdump_filter_port) {
            if (!has_ports) return;
            if (tcpdump_filter_port != sport && tcpdump_filter_port != dport) return;
        }

        terminal_writestring("\n");
        terminal_writestring(dir ? "out " : "in  ");
        terminal_writestring("IP ");
        terminal_writestring(tcpdump_proto_name(iph.protocol));
        terminal_writestring("  ");

        if (iph.protocol == IP_PROTOCOL_TCP && has_ports) {
            const struct tcp_header* t = (const struct tcp_header*)ippl;
            shell_write_ip(iph.src_ip);
            terminal_putchar('.');
            shell_write_port(sport);
            terminal_writestring(" > ");
            shell_write_ip(iph.dest_ip);
            terminal_putchar('.');
            shell_write_port(dport);
            terminal_writestring(" [");
            uint8_t fl = t->flags;
            if (fl & TCP_FLAG_SYN) terminal_writestring("S");
            if (fl & TCP_FLAG_ACK) terminal_writestring("A");
            if (fl & TCP_FLAG_PSH) terminal_writestring("P");
            if (fl & TCP_FLAG_FIN) terminal_writestring("F");
            if (fl & TCP_FLAG_RST) terminal_writestring("R");
            terminal_writestring("]");
        } else if (iph.protocol == IP_PROTOCOL_UDP && has_ports) {
            shell_write_ip(iph.src_ip);
            terminal_putchar('.');
            shell_write_port(sport);
            terminal_writestring(" > ");
            shell_write_ip(iph.dest_ip);
            terminal_putchar('.');
            shell_write_port(dport);
        } else if (iph.protocol == IP_PROTOCOL_ICMP && ippl_len >= 8) {
            const uint8_t* ic = (const uint8_t*)ippl;
            shell_write_ip(iph.src_ip);
            terminal_writestring(" > ");
            shell_write_ip(iph.dest_ip);
            terminal_writestring(" type=");
            shell_write_u32(ic[0]);
        } else {
            shell_write_ip(iph.src_ip);
            terminal_writestring(" > ");
            shell_write_ip(iph.dest_ip);
        }
        terminal_writestring("  len=");
        shell_write_u32((uint32_t)len);
        if (tcpdump_remaining > 0) tcpdump_remaining--;
        return;
    }

    /* Другие ethertype (IPv6 и т.п.) */
    if (tcpdump_filter_etype && tcpdump_filter_etype != etype) return;
    static const char hx[] = "0123456789abcdef";
    terminal_writestring("\n");
    terminal_writestring(dir ? "out " : "in  ");
    terminal_writestring("ETH 0x");
    terminal_putchar(hx[(etype >> 12) & 0xF]);
    terminal_putchar(hx[(etype >> 8) & 0xF]);
    terminal_putchar(hx[(etype >> 4) & 0xF]);
    terminal_putchar(hx[etype & 0xF]);
    terminal_writestring("  len=");
    shell_write_u32((uint32_t)len);
    if (tcpdump_remaining > 0) tcpdump_remaining--;
}

// Порты для системных операций
static inline void outb(uint16_t port, uint8_t val) { asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port)); }
static inline void outw(uint16_t port, uint16_t val) { asm volatile ("outw %0, %1" : : "a"(val), "Nd"(port)); }
static inline uint8_t inb(uint16_t port) { uint8_t ret; asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port)); return ret; }

// Вспомогательная функция для цветного вывода
static inline uint8_t vga_entry_color(enum vga_color fg, enum vga_color bg) {
    return fg | bg << 4;
}

/* Кладём вшитые user-бинари в /tmp (ramfs): exec читает их как файлы из ФС. */
static void boot_populate_user_bins(void) {
    extern char user_demo_start[], user_demo_end[];
    extern char user_demo2_start[], user_demo2_end[];
    extern char user_demo3_start[], user_demo3_end[];
    extern char user_launcher_start[], user_launcher_end[];
    extern char user_argtest_start[], user_argtest_end[];
    extern char user_ptytest_start[], user_ptytest_end[];
    extern char user_sh_start[], user_sh_end[];
    extern char user_ksshd_start[], user_ksshd_end[];
    extern char user_sshd_start[], user_sshd_end[];
    static const struct {
        const char* path;
        char* start;
        char* end;
    } bins[] = {
        { "/tmp/hello.elf",     user_demo_start,    user_demo_end },
        { "/tmp/demo2.elf",     user_demo2_start,   user_demo2_end },
        { "/tmp/demo3.elf",     user_demo3_start,   user_demo3_end },
        { "/tmp/launcher.elf",  user_launcher_start, user_launcher_end },
        { "/tmp/argtest.elf",   user_argtest_start, user_argtest_end },
        { "/tmp/ptytest.elf",   user_ptytest_start, user_ptytest_end },
        { "/tmp/sh.elf",        user_sh_start,      user_sh_end },
        { "/tmp/ksshd.elf",     user_ksshd_start,   user_ksshd_end },
        { "/tmp/sshd.elf",      user_sshd_start,    user_sshd_end },
    };
    for (unsigned i = 0; i < sizeof(bins) / sizeof(bins[0]); i++) {
        size_t sz = (size_t)(bins[i].end - bins[i].start);
        if (sz == 0) continue;
        if (ramfs_write(bins[i].path, bins[i].start, sz) != 0) {
            log_fmt3(LOG_ERR, "boot", "populate_bin_failed", "i", i, "ok", 0u, "x", 0u);
        }
    }
    log_msg(LOG_INFO, "boot", "user bins installed to /tmp");
}

// Точка входа ядра (multiboot2 info pointer; 0 if unavailable)
extern "C" void kernel_main(uint32_t multiboot_info) {
    terminal_initialize();
    serial_init();
    log_msg(LOG_INFO, "kernel", "boot " KERNEL_VERSION " (" KERNEL_BUILD ")");
    
    auto print_status = [](const char* status, const char* message, uint8_t color) {
        uint8_t old_color = terminal_getcolor();
        terminal_setcolor(color);
        terminal_writestring("[");
        /* Align tag to 4 chars: OK/FAIL/WARN */
        const char* tag = status ? status : "";
        char padded[5] = {' ', ' ', ' ', ' ', 0};
        size_t n = 0;
        while (tag[n] && n < 4) { padded[n] = tag[n]; n++; }
        terminal_writestring(padded);
        terminal_writestring("] ");
        terminal_setcolor(old_color);
        terminal_writestring(message);
        log_msg(LOG_INFO, "boot", message);
    };
    
    terminal_set_cursor(0, 0);
    print_status("OK", "KnitOS VGA console", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    
    terminal_set_cursor(1, 0);
    print_status("OK", "Kernel " KERNEL_VERSION " (" KERNEL_BUILD ")",
                 vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    
    terminal_set_cursor(2, 0);
    print_status("OK", "Mode: 32-bit", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    
    terminal_set_cursor(3, 0);
    if (driver_manager_init() == 0) {
        print_status("OK", "Driver manager", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        print_status("FAIL", "Driver manager", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    int current_row = 4;
    
    terminal_set_cursor(current_row, 0);
    idt_init();
    print_status("OK", "IDT", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    current_row++;

    paging_init();
    terminal_init_graphics(multiboot_info);
    terminal_set_cursor(current_row, 0);
    if (terminal_using_framebuffer()) {
        char fbmsg[48];
        size_t n = 0;
        auto putc = [&](char ch) { if (n + 1 < sizeof(fbmsg)) fbmsg[n++] = ch; };
        auto put_u = [&](uint32_t v) {
            char tmp[12]; int t = 0;
            if (v == 0) tmp[t++] = '0';
            else while (v && t < 11) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
            while (t > 0) putc(tmp[--t]);
        };
        const char* pfx = "Paging + FB ";
        while (*pfx) putc(*pfx++);
        put_u(terminal_fb_width());
        putc('x');
        put_u(terminal_fb_height());
        if (terminal_fb_scale() > 1) {
            putc(' ');
            putc('x');
            put_u(terminal_fb_scale());
        }
        fbmsg[n] = 0;
        print_status("OK", fbmsg, vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        print_status("OK", "Paging (VGA text 80x25)", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    }
    current_row++;

    pic_remap();
    pit_init();
    terminal_set_cursor(current_row, 0);
    print_status("OK", "PIT 100Hz", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    current_row++;

    rtc_init();
    char rtc_boot_msg[21];
    rtc_format_timestamp(rtc_boot_msg, sizeof(rtc_boot_msg));
    terminal_set_cursor(current_row, 0);
    if (rtc_valid()) {
        print_status("OK", rtc_boot_msg, vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        print_status("WARN", "RTC time unavailable", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    current_row++;
    
    terminal_set_cursor(current_row, 0);
    syscall_init();
    print_status("OK", "Syscalls", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    current_row++;

    paging_setup_user_mode();
    terminal_set_cursor(current_row, 0);
    print_status("OK", "User mode (ring3) + ELF", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    current_row++;
    
    driver_scan_devices();
    
    disk_manager_init();
    
    bool acpi_ok = acpi_init();
    terminal_set_cursor(current_row, 0);
    if (acpi_ok) {
        print_status("OK", "ACPI S5 + reset", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        print_status("WARN", "ACPI not found (fallback ports)", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    current_row++;
    
    // Начинаем вывод статусов сразу под последней строкой отладочного вывода
    current_row = (int)terminal_get_row();
    
    // Проверяем статус контроллеров с учетом флага initialized
    bool nvme_initialized = false;
    bool ahci_initialized = false;
    bool ahci_found_but_failed = false;
    bool ide_initialized = false;
    
    // Проверяем диски в списке
    int disk_count_check = disk_manager_count();
    for (int j = 0; j < disk_count_check; j++) {
        const struct disk_info* d = disk_manager_get_disk(j);
        if (d) {
            if (d->controller_type == DISK_CONTROLLER_NVME && d->initialized) {
                nvme_initialized = true;
            } else if (d->controller_type == DISK_CONTROLLER_AHCI) {
                if (d->initialized) {
                    ahci_initialized = true;
                } else {
                    ahci_found_but_failed = true;
                }
            } else if (d->controller_type == DISK_CONTROLLER_ATA && d->initialized) {
                ide_initialized = true;
            }
        }
    }
    
    // Проверяем, был ли найден AHCI через PCI, но не добавлен в список (например, если инициализация не удалась до добавления)
    if (!ahci_initialized && !ahci_found_but_failed) {
        if (disk_manager_ahci_pci_found() && disk_manager_ahci_init_attempted()) {
            // AHCI найден через PCI, но инициализация не удалась и диск не добавлен
            ahci_found_but_failed = true;
        }
    }
    
    // Выводим статус NVMe контроллера
    if (nvme_initialized) {
        terminal_set_cursor(current_row, 0);
        print_status("OK", "Controller: NVMe", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
        current_row++;
    }
    
    // Выводим статус AHCI контроллера
    if (ahci_initialized) {
        terminal_set_cursor(current_row, 0);
        print_status("OK", "Controller: AHCI", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
        current_row++;
    } else if (ahci_found_but_failed) {
        terminal_set_cursor(current_row, 0);
        print_status("FAIL", "Controller: AHCI", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
        current_row++;
    }
    
    // Выводим статус IDE контроллера
    if (ide_initialized) {
        terminal_set_cursor(current_row, 0);
        print_status("OK", "Controller: IDE", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
        current_row++;
    }
    
    // Если дисков не найдено вообще
    int total_disk_count = disk_manager_count();
    if (total_disk_count == 0) {
        terminal_set_cursor(current_row, 0);
        print_status("FAIL", "No disks found", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
        current_row++;
    }
    
    // Инициализация базового диска для обратной совместимости
    bool disk_init_success = false;
    if (total_disk_count > 0) {
        int disk_init_result = disk_init(); // Инициализируем первый диск для старых функций
        disk_init_success = (disk_init_result == 0);
        
        // Обновляем информацию об активном диске в списке
        enum disk_controller_type active_ctrl = disk_get_controller_type();
        int active_disk_idx = -1;
        
        // Сначала деактивируем все диски
        for (int i = 0; i < total_disk_count; i++) {
            struct disk_info* disk = disk_manager_get_disk_mutable(i);
            if (disk) {
                disk->active = false;
            }
        }
        
        // Находим и активируем диск с активным контроллером
        for (int i = 0; i < total_disk_count; i++) {
            struct disk_info* disk = disk_manager_get_disk_mutable(i);
            if (disk && disk->controller_type == active_ctrl && !disk->is_atapi && disk->initialized) {
                uint32_t actual_size = disk_get_size_sectors();
                if (actual_size > 0) {
                    disk->size_sectors = actual_size;
                }
                disk->active = true;
                active_disk_idx = i;
                break;
            }
        }

        if (active_disk_idx < 0 && total_disk_count > 0) {
            for (int i = 0; i < total_disk_count; i++) {
                struct disk_info* disk = disk_manager_get_disk_mutable(i);
                if (disk && disk->initialized && !disk->is_atapi) {
                    disk->active = true;
                    active_disk_idx = i;
                    break;
                }
            }
        }
        if (active_disk_idx < 0 && total_disk_count > 0) {
            log_msg(LOG_ERR, "boot", "no block device (ATAPI only?)");
        }
    }
    
    // Инициализация системы монтирования
    terminal_set_cursor(current_row, 0);
    int mount_init_result = mount_init();
    if (mount_init_result > 0) {
        print_status("OK", "Mount system initialized", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        print_status("FAIL", "Mount system init failed", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    current_row++;
    
    // Инициализация файловой системы
    terminal_set_cursor(current_row, 0);
    if (total_disk_count == 0) {
        log_msg(LOG_ERR, "boot", "fs skip: no disks");
        print_status("FAIL", "Filesystem init failed", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    } else if (!disk_init_success) {
        log_msg(LOG_ERR, "boot", "fs skip: disk_init failed");
        print_status("FAIL", "Filesystem init failed", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    } else if (fs_init(0) == 0) {
        vfs_init();
        ramfs_mount_tmp();
        print_status("OK", "Filesystem initialized", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        log_msg(LOG_ERR, "boot", "fs_init sector I/O failed");
        print_status("FAIL", "Filesystem init failed", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    current_row++;

    auto boot_advance_row = [&]() {
        current_row = (int)terminal_get_row() + 1;
        if (current_row >= 25) current_row = 24;
        terminal_set_cursor((size_t)current_row, 0);
    };

    /* IRQ до сети/FS write: иначе net_wait_ms и AHCI ждут вечно (jiffies=0). */
    keyboard_init();
    interrupts_enable();

    boot_populate_user_bins();

    boot_advance_row();
    if (network_config_apply_boot() == 0 && ip_get_our_ip() != 0) {
        char netmsg[40];
        netmsg[0] = 'N'; netmsg[1] = 'e'; netmsg[2] = 't'; netmsg[3] = ' ';
        netmsg[4] = 'O'; netmsg[5] = 'K'; netmsg[6] = ','; netmsg[7] = ' ';
        netmsg[8] = 'I'; netmsg[9] = 'P'; netmsg[10] = ' ';
        int np = 11;
        char ipbuf[20];
        ip_format_address(ip_get_our_ip(), ipbuf, sizeof(ipbuf));
        for (int i = 0; ipbuf[i] && np < 38; i++) netmsg[np++] = ipbuf[i];
        netmsg[np] = 0;
        print_status("OK", netmsg, vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
        log_ip(LOG_INFO, "boot", "network", ip_get_our_ip());
    } else {
        print_status("WARN", "Network not configured", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    boot_advance_row();
    
    // Инициализация /dev
    terminal_set_cursor(current_row, 0);
    int dev_init_result = dev_init();
    if (dev_init_result == 0) {
        print_status("OK", "Device system initialized", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    } else {
        print_status("FAIL", "Device system init failed", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
    }
    boot_advance_row();
    
    // Инициализация системы утилит
    utils_init();

    sched_init();
    {
        int idle_id = task_create(idle_kthread, 0, "idle");
        if (idle_id < 0 || task_set_idle(idle_id) != 0) {
            print_status("WARN", "sched: idle create failed", vga_entry_color(VGA_COLOR_LIGHT_RED, VGA_COLOR_BLACK));
            boot_advance_row();
        } else {
            print_status("OK", "Scheduler (systemd+idle)", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
            boot_advance_row();
        }
        if (dhcp_start_service() >= 0) {
            print_status("OK", "dhcpd kthread", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
            boot_advance_row();
        }
    }
    
    boot_advance_row();
    print_status("OK", "Keyboard ready", vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
    boot_advance_row();

    /* Clear boot spam from viewport; keep details on serial */
    terminal_clear_viewport();

    {
        char hdr_left[48];
        size_t hl = 0;
        auto hput = [&](const char* s) {
            while (*s && hl + 1 < sizeof(hdr_left)) hdr_left[hl++] = *s++;
        };
        hput(KERNEL_NAME);
        hput(" ");
        hput(KERNEL_VERSION);
        hdr_left[hl] = 0;

        char hdr_right[40];
        size_t hr = 0;
        auto rput = [&](const char* s) {
            while (*s && hr + 1 < sizeof(hdr_right)) hdr_right[hr++] = *s++;
        };
        auto rput_u = [&](uint32_t v) {
            char tmp[12]; int t = 0;
            if (v == 0) tmp[t++] = '0';
            else while (v && t < 11) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
            while (t > 0 && hr + 1 < sizeof(hdr_right)) hdr_right[hr++] = tmp[--t];
        };
        if (terminal_using_framebuffer()) {
            rput("fb ");
            rput_u(terminal_fb_width());
            rput("x");
            rput_u(terminal_fb_height());
        } else {
            rput("text 80x25");
        }
        hdr_right[hr] = 0;
        terminal_header_set(hdr_left, hdr_right);
    }

    terminal_set_cursor(terminal_content_origin(), 0);
    terminal_setcolor(vga_entry_color(VGA_COLOR_LIGHT_GREY, VGA_COLOR_BLACK));
    terminal_writestring("modular hobby kernel");
    terminal_putchar('\n');
    terminal_setcolor(vga_entry_color(VGA_COLOR_DARK_GREY, VGA_COLOR_BLACK));
    for (int i = 0; i < 36; i++) terminal_putchar('-');
    terminal_putchar('\n');
    terminal_setcolor(vga_entry_color(VGA_COLOR_LIGHT_GREY, VGA_COLOR_BLACK));
    terminal_writestring("Net ");
    {
        char ipbuf[20];
        ip_format_address(ip_get_our_ip(), ipbuf, sizeof(ipbuf));
        terminal_writestring(ipbuf[0] ? ipbuf : "0.0.0.0");
    }
    terminal_writestring("   tasks ");
    shell_write_u32((uint32_t)sched_task_count());
    terminal_writestring("   disk ready");
    terminal_putchar('\n');
    terminal_putchar('\n');

    /* Инициализация базы пользователей (пароли/права). */
    if (fs_ready()) {
        int n = users_init();
        if (n > 0) {
            terminal_writestring("Users: ");
            shell_write_u32((uint32_t)n);
            terminal_writestring(" loaded\n");
        }
        groups_init();
    }

    /* ==== Консольная сессия 0 (foreground) ==== */
    g_sessions[0].id = 0;
    g_sessions[0].used = true;
    g_sessions[0].uid = 0;
    g_sessions[0].gid = 0;
    g_sessions[0].login[0] = 0;
    g_sessions[0].blen = 0;
    g_sessions[0].cpos = 0;
    g_sessions[0].prow = terminal_get_row();
    g_sessions[0].pcol = 0;
    strncpy(g_sessions[0].cwd, utils_get_current_directory(), sizeof(g_sessions[0].cwd) - 1);
    g_sessions[0].tabll = (size_t)-1;
    g_sessions[0].tabls = (size_t)-1;
    g_sessions[0].tabci = -1;
    g_sessions[0].hcnt = 0;
    g_sessions[0].hpos = -1;
    g_sessions[0].hhas = false;
    g_sessions[0].hdlen = 0;
    strncpy(g_sessions[0].name, "tty0", sizeof(g_sessions[0].name) - 1);
    g_session_count = 1;
    g_current_session = 0;

    /* Привязка имени/линий к «текущей сессии» — весь интерактивный код ниже
       автоматически работает с выбранной сессией (своя история/uid/cwd). */
    #define line                cur_session()->sbuf
    #define line_len            cur_session()->blen
    #define cur_pos             cur_session()->cpos
    #define prompt_row          cur_session()->prow
    #define prompt_col          cur_session()->pcol
    #define tab_last_line_len   cur_session()->tabll
    #define tab_last_word_start cur_session()->tabls
    #define tab_cycle_idx       cur_session()->tabci
    #define shell_history       cur_session()->hist
    #define shell_history_len   cur_session()->hlen
    #define shell_history_count cur_session()->hcnt
    #define shell_history_pos   cur_session()->hpos
    #define shell_history_draft cur_session()->hdraft
    #define shell_history_draft_len cur_session()->hdlen
    #define shell_history_has_draft cur_session()->hhas
    #define g_login_user        cur_session()->login

    auto refresh_status_line = [&]() {
        char mid[96];
        size_t m = 0;
        auto mput = [&](const char* s) {
            while (*s && m + 1 < sizeof(mid)) mid[m++] = *s++;
        };
        char ts[24];
        rtc_format_timestamp(ts, sizeof(ts));
        mput(rtc_valid() ? ts : "--");
        mput(" | ");
        const char* cwd = utils_get_current_directory();
        mput(cwd ? cwd : "/");
        mput(" | ");
        char ipb[20];
        ip_format_address(ip_get_our_ip(), ipb, sizeof(ipb));
        mput(ipb[0] ? ipb : "0.0.0.0");
        mid[m] = 0;

        char right[48];
        size_t r = 0;
        auto rput = [&](const char* s) {
            while (*s && r + 1 < sizeof(right)) right[r++] = *s++;
        };
        auto rput_u = [&](uint32_t v) {
            char tmp[12]; int t = 0;
            if (v == 0) tmp[t++] = '0';
            else while (v && t < 11) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
            while (t > 0 && r + 1 < sizeof(right)) right[r++] = tmp[--t];
        };
        rput("up ");
        rput_u(timer_ms() / 1000);
        rput("s | t=");
        rput_u((uint32_t)sched_task_count());
        int httpd = http_server_pid();
        int dhcpd = dhcp_service_pid();
        if (httpd >= 0) {
            rput(" httpd=");
            rput_u((uint32_t)httpd);
        }
        if (dhcpd >= 0) {
            rput(" dhcpd=");
            rput_u((uint32_t)dhcpd);
        }
        right[r] = 0;
        terminal_status_set_zones(KERNEL_NAME, mid, right);
    };

    auto prompt_print = [&]() {
        if (terminal_is_capturing()) return;
        refresh_status_line();
        terminal_set_cursor(prompt_row, 0);
        uint8_t old = terminal_getcolor();
        terminal_setcolor(vga_entry_color(VGA_COLOR_LIGHT_GREEN, VGA_COLOR_BLACK));
        const char* uname = g_login_user[0] ? g_login_user : "root";
        terminal_writestring(uname);
        terminal_setcolor(vga_entry_color(VGA_COLOR_DARK_GREY, VGA_COLOR_BLACK));
        terminal_writestring(" > ");
        terminal_setcolor(old);
        prompt_col = terminal_get_column();
    };

    auto flush_line = [&]() {
        terminal_putchar('\n');
        line_len = 0;
        prompt_row = terminal_get_row();
        prompt_print();
    };

    auto cmd_clear = [&]() {
        terminal_clear_viewport();
        terminal_set_cursor(terminal_content_origin(), 0);
        prompt_row = terminal_get_row();
        prompt_print();
    };

    /* Переключение на консольную сессию n: применяем её uid/gid/cwd/логин,
       печатаем свежий промпт (буфер строки не переносим — общий экран). */
    auto switch_session = [&](int n) -> int {
        if (n < 0 || n >= g_session_count || !g_sessions[n].used) return -1;
        const char* cur_cwd = utils_get_current_directory();
        if (cur_cwd) strncpy(cur_session()->cwd, cur_cwd, sizeof(cur_session()->cwd) - 1);
        g_current_session = n;
        struct shell_session* s = cur_session();
        task_setuid_force(s->uid);
        fs_set_current_uid(s->uid);
        task_setgid_force(s->gid);
        fs_set_current_gid(s->gid);
        utils_set_current_directory(s->cwd[0] ? s->cwd : "/");
        terminal_writestring("\n");
        prompt_row = terminal_get_row();
        line_len = 0;
        prompt_print();
        return 0;
    };
    
    /* Keys from IRQ software buffer (KEY_* / ASCII). Never read port 0x60 here. */
    auto poll_key = [&]() -> char {
        char c = keyboard_poll();
        if (c != 0) return c;
        return serial_poll_char();
    };
    
    // Функция подтверждения действия
    auto confirm_action = [&](const char* action_name) -> bool {
        terminal_writestring("\nAre you sure you want to ");
        terminal_writestring(action_name);
        terminal_writestring("? (yes/no): ");
        char confirm_line[16];
        size_t confirm_len = 0;
        while (confirm_len < sizeof(confirm_line) - 1) {
            char c = poll_key();
            if (c == '\n') {
                confirm_line[confirm_len] = 0;
                break;
            } else if (c == '\b') {
                if (confirm_len > 0) {
                    confirm_len--;
                    terminal_putchar('\b');
                    terminal_putchar(' ');
                    terminal_putchar('\b');
                }
            } else if (c != 0) {
                confirm_line[confirm_len++] = c;
                terminal_putchar(c);
            }
            // Небольшая пауза
            for (volatile int i = 0; i < 1000; i++);
        }
        // Проверяем на "yes" или "y"
        if (confirm_len == 3 && confirm_line[0]=='y' && confirm_line[1]=='e' && confirm_line[2]=='s') return true;
        if (confirm_len == 1 && confirm_line[0]=='y') return true;
        return false;
    };

    // Чтение строки с эхом (имя пользователя и т.п.)
    auto read_line = [&](char* out, size_t cap) -> bool {
        size_t len = 0;
        out[0] = 0;
        bool full = false;
        for (;;) {
            char c = poll_key();
            if (c == '\n') break;
            else if (c == '\b') {
                if (len > 0) {
                    len--;
                    terminal_putchar('\b');
                    terminal_putchar(' ');
                    terminal_putchar('\b');
                }
            } else if (c == 3) { /* Ctrl+C */
                terminal_writestring("^C\n");
                return false;
            } else if (c != 0) {
                if (len + 1 < cap) {
                    out[len++] = c;
                    terminal_putchar(c);
                } else {
                    full = true; /* буфер полон — дочитываем строку, отбрасывая лишнее */
                }
            }
        }
        (void)full;
        out[len] = 0;
        terminal_putchar('\n');
        return true;
    };

    // Чтение пароля без эха.
    auto read_password = [&](char* out, size_t cap) -> bool {
        size_t len = 0;
        out[0] = 0;
        for (;;) {
            char c = poll_key();
            if (c == '\n') break;
            else if (c == '\b') {
                if (len > 0) len--;
            } else if (c == 3) { /* Ctrl+C */
                terminal_writestring("^C\n");
                return false;
            } else if (c != 0) {
                if (len + 1 < cap) out[len++] = c; /* не эхо; лишнее отбрасываем */
            }
        }
        out[len] = 0;
        terminal_putchar('\n');
        return true;
    };

    /* Экран авторизации: запрашивает пользователя и пароль, проверяет через
       /etc/passwd + /etc/shadow. Циклится, пока не успешно. */
    auto do_login_prompt = [&]() -> bool {
        for (;;) {
            terminal_writestring("\nKnitOS login: ");
            char uname[UNAME_MAX];
            if (!read_line(uname, sizeof(uname))) { /* Ctrl+C — показать снова */ }
            if (uname[0] == 0) continue;
            const struct user_record* u = user_by_name(uname);
            if (!u) { terminal_writestring("\nLogin incorrect"); continue; }
            terminal_writestring("Password: ");
            char pw[64];
            if (!read_password(pw, sizeof(pw))) { terminal_writestring("\nLogin incorrect"); continue; }
            if (!user_check_password(uname, pw)) { terminal_writestring("\nLogin incorrect"); continue; }
            task_setuid_force(u->uid);
            fs_set_current_uid(u->uid);
            task_setgid_force(u->gid);
            fs_set_current_gid(u->gid);
            strncpy(g_login_user, u->name, UNAME_MAX - 1);
            g_login_user[UNAME_MAX - 1] = 0;
            cur_session()->uid = u->uid;
            cur_session()->gid = u->gid;
            struct fs_stat hst;
            if (fs_stat(u->home, &hst) == 0 && (hst.flags & FS_FLAG_DIRECTORY)) {
                utils_set_current_directory(u->home);
            }
            strncpy(cur_session()->cwd, utils_get_current_directory(), sizeof(cur_session()->cwd) - 1);
            return true;
        }
    };

    // Перезагрузка через keyboard controller
    auto reboot = [&]() {
        if (!confirm_action("reboot")) {
            terminal_writestring("\nReboot cancelled.");
            flush_line();
            return;
        }
        terminal_writestring("\nRebooting...");
        // Ожидание готовности контроллера
        for (volatile int i = 0; i < 10000; i++);
        // Сначала ACPI Reset register (если есть)
        acpi_reboot();
        for (volatile int i = 0; i < 10000; i++);
        while ((inb(0x64) & 0x02) != 0) {}
        outb(0x64, 0xFE); // Reset через keyboard controller
        // Если не сработало, пробуем через порт 0xCF9
        for (volatile int i = 0; i < 10000; i++);
        outb(0xCF9, 0x06);
        // Бесконечный цикл на случай если ничего не сработало
        while(1) asm volatile ("hlt");
    };
    
    // Выключение через ACPI/QEMU порт
    auto shutdown = [&]() {
        if (!confirm_action("shutdown")) {
            terminal_writestring("\nShutdown cancelled.");
            flush_line();
            return;
        }
        terminal_writestring("\nShutting down...");
        // ACPI S5 (из FADT/DSDT)
        acpi_power_off();
        // QEMU/VirtualBox shutdown через порт 0x604 (16-bit)
        for (volatile int i = 0; i < 10000; i++);
        outw(0x604, 0x2000);
        // ACPI shutdown (если поддерживается)
        for (volatile int i = 0; i < 10000; i++);
        outw(0xB004, 0x2000); // Bochs
        outw(0x4004, 0x3400); // VirtualBox
        // Пробуем через ACPI (если доступно)
        for (volatile int i = 0; i < 10000; i++);
        // Пробуем через порт 0x8900 (ACPI)
        outw(0x8900, 0x2000);
        // Бесконечный цикл на случай если ничего не сработало
        while(1) asm volatile ("hlt");
    };
    
    auto process_command = [&](const char* cmd, size_t len) {
        while (len && cmd[len-1]==' ') len--;
        const char* cwd = utils_get_current_directory();
        if (len > 0) {
            log_shell_cmd(cwd, cmd, len);
        }
        if (len==0) { flush_line(); return; }
        
        // Парсинг аргументов. Копируем в отдельный буфер с NUL-терминацией:
        // иначе argv[i] тянул бы за собой остаток строки (баг «useradd a 1001»).
        char argbuf[160];
        const char* argv[32];
        int argc = 0;
        size_t i = 0;
        size_t ab = 0;
        while (i < len && argc < 31 && ab + 1 < sizeof(argbuf)) {
            while (i < len && cmd[i] == ' ') i++;
            if (i >= len) break;
            argv[argc++] = argbuf + ab;
            while (i < len && cmd[i] != ' ' && ab + 1 < sizeof(argbuf))
                argbuf[ab++] = cmd[i++];
            argbuf[ab++] = 0;
        }
        argv[argc] = 0;
        
        if (argc == 0) { flush_line(); return; }
        
        // Извлекаем имя команды
        const char* cmd_name = argv[0];
        size_t cmd_name_len = 0;
        while (cmd_name[cmd_name_len]) cmd_name_len++;
        
        // Команда help (и ?)
        if ((cmd_name_len==4 && cmd_name[0]=='h'&&cmd_name[1]=='e'&&cmd_name[2]=='l'&&cmd_name[3]=='p') ||
            (cmd_name_len==1 && cmd_name[0]=='?')) {
            terminal_writestring("\n=== Commands (help / ?) ===");
            terminal_writestring("\nFiles:");
            terminal_writestring("\n  ls [path] [-l] [-a]     list directory");
            terminal_writestring("\n  find [path] [-name P] [-type f|d]  search files");
            terminal_writestring("\n  cd <path>   pwd   cat <file>   rm [-r] <path>");
            terminal_writestring("\n  write <file> <text>   nano <file>  mkdir [-p] <path>");
            terminal_writestring("\n  mv <a> <b>   cp <a> <b>   ln [-s] <a> <b>   stat <path>");
            terminal_writestring("\n  chmod <mode> <path>   chown <uid> <path>   touch <path>");
            terminal_writestring("\n  df   du <path>   sync   mount   fsck");
            terminal_writestring("\nSystem:");
            terminal_writestring("\n  login [user]  logout  whoami  id  users");
            terminal_writestring("\n  useradd <name> [uid]  userdel <name>  usermod <name> [newname uid gid]");
            terminal_writestring("\n  groupadd <name> [gid]  groups [user]  passwd [user]  su [user]");
            terminal_writestring("\n  chmod <mode> <path>  chown <uid> <path>  chgrp <gid> <path>");
            terminal_writestring("\n  sessions  session <n>  newsession <name>  (independent terminals)");
            terminal_writestring("\n  clear   echo   version   date   setdate YYYY-MM-DD   settime HH:MM:SS");
            terminal_writestring("\n  runelf hello   disk   reboot   shutdown  poweroff");
            terminal_writestring("\n  ptyrun argtest|ptytest   (interactive program over a PTY)");
            terminal_writestring("\n  acpi                  show ACPI tables info (S5, reset)");
            terminal_writestring("\n  ps                     tasks (systemd=0, idle, ...)");
            terminal_writestring("\n  kill [-9] <pid>         terminate kthread (not systemd/idle)");
            terminal_writestring("\n  resolution <H>   log [off|err|info|debug]");
            terminal_writestring("\nNetwork:");
            terminal_writestring("\n  network   ifconfig   dhcp   ping <host>   traceroute <host>   tcpdump [filters]");
            terminal_writestring("\n  hostname [name]        show/set DHCP hostname");
            terminal_writestring("\n  network save|reload|static <ip> [gw] [dns] [mask]");
            terminal_writestring("\n  udp/tcp/udplisten/tcp listen   dns   arp   route   netstat");
            terminal_writestring("\n  ports                 TCP/UDP table (port, state, pid, process)");
            terminal_writestring("\n  port close tcp|udp <n>  close listening port");
            terminal_writestring("\n  socktest tcp|udp <port>  socket API echo test");
            terminal_writestring("\n  httpserver [port] [max]  HTTP/1.1 server (/www, Keep-Alive)");
            terminal_writestring("\n  rshd [port] [max]      raw remote shell over TCP (login) ");
            terminal_writestring("\n  ftpd [port]            FTP server (PASV, login via /etc/passwd)");
            terminal_writestring("\n  autotest fs             FS create/write/read/delete test");
            terminal_writestring("\n  autotest vga            VGA/FB console smoke test");
            terminal_writestring("\n  autotest user           ring3 isolation + uid + demos");
            terminal_writestring("\n  autotest network [port] [max]  CI network + FS + HTTP");
            terminal_writestring("\nKeyboard:");
            terminal_writestring("\n  Tab          autocomplete (2x=list, 3x=cycle)");
            terminal_writestring("\n  Shift+key    special chars: ? ! @ * ( ) - _ + etc.");
            terminal_writestring("\n  Up/Down      command history   PgUp/PgDn scroll");
            terminal_writestring("\nNano editor:");
            terminal_writestring("\nNano (^G help): ^O save ^X exit ^W search ^K cut ^U paste ^_ goto");
            terminal_writestring("\nExamples:");
            terminal_writestring("\n  find / -name \"*.conf\"   ls /etc   cat /etc/resolv.conf");
            terminal_writestring("\n  nano test.txt   network save");
            flush_line(); return;
        }
        
        // Команда cd
        if (cmd_name_len==2 && cmd_name[0]=='c'&&cmd_name[1]=='d') {
            if (argc < 2) {
                terminal_writestring("\nUsage: cd <path>");
                flush_line(); return;
            }
            const char* path = argv[1];
            char resolved[128];
            if (utils_resolve_path(path, resolved, sizeof(resolved)) != 0) {
                terminal_writestring("\ncd: invalid path");
                flush_line(); return;
            }
            char test_buf[64];
            if (vfs_list(resolved, test_buf, sizeof(test_buf)) >= 0) {
                utils_set_current_directory(resolved);
            } else {
                terminal_writestring("\ncd: ");
                terminal_writestring(path);
                terminal_writestring(": No such file or directory");
            }
            flush_line(); return;
        }
        
        // Команда pwd (показать текущую директорию)
        if (cmd_name_len==3 && cmd_name[0]=='p'&&cmd_name[1]=='w'&&cmd_name[2]=='d') {
            terminal_writestring("\n");
            terminal_writestring(utils_get_current_directory());
            flush_line(); return;
        }

        // Команда login - авторизация на консоли
        if (cmd_name_len==5 && cmd_name[0]=='l'&&cmd_name[1]=='o'&&cmd_name[2]=='g'&&cmd_name[3]=='i'&&cmd_name[4]=='n') {
            char uname[UNAME_MAX];
            const char* target = 0;
            if (argc >= 2) {
                target = argv[1];
            } else {
                terminal_writestring("\nlogin: ");
                if (!read_line(uname, sizeof(uname))) { flush_line(); return; }
                target = uname;
            }
            const struct user_record* u = user_by_name(target);
            if (!u) {
                terminal_writestring("\nlogin: unknown user: ");
                terminal_writestring(target);
            } else {
                terminal_writestring("\nPassword: ");
                char pw[64];
                if (!read_password(pw, sizeof(pw))) { flush_line(); return; }
                if (user_check_password(target, pw)) {
                    task_setuid_force(u->uid);
                    fs_set_current_uid(u->uid);
                    task_setgid_force(u->gid);
                    fs_set_current_gid(u->gid);
                    strncpy(g_login_user, u->name, UNAME_MAX - 1);
                    g_login_user[UNAME_MAX - 1] = 0;
                    cur_session()->uid = u->uid;
                    cur_session()->gid = u->gid;
                    /* Переходим в домашнюю директорию, если она существует. */
                    struct fs_stat hst;
                    if (fs_stat(u->home, &hst) == 0 && (hst.flags & FS_FLAG_DIRECTORY)) {
                        utils_set_current_directory(u->home);
                    }
                    strncpy(cur_session()->cwd, utils_get_current_directory(), sizeof(cur_session()->cwd) - 1);
                    terminal_writestring("\nWelcome, ");
                    terminal_writestring(u->name);
                } else {
                    terminal_writestring("\nlogin: incorrect password");
                }
            }
            flush_line(); return;
        }

        // Команда logout - завершение сессии
        if (cmd_name_len==6 && cmd_name[0]=='l'&&cmd_name[1]=='o'&&cmd_name[2]=='g'&&cmd_name[3]=='o'&&cmd_name[4]=='u'&&cmd_name[5]=='t') {
            task_setuid_force(0);
            fs_set_current_uid(0);
            task_setgid_force(0);
            fs_set_current_gid(0);
            g_login_user[0] = 0;
            cur_session()->uid = 0;
            cur_session()->gid = 0;
            utils_set_current_directory("/");
            strncpy(cur_session()->cwd, "/", sizeof(cur_session()->cwd) - 1);
            terminal_writestring("\nLogged out");
            do_login_prompt();
            prompt_row = terminal_get_row();
            line_len = 0;
            prompt_print();
            return;
        }

        // Команда whoami
        if (cmd_name_len==6 && cmd_name[0]=='w'&&cmd_name[1]=='h'&&cmd_name[2]=='o'&&cmd_name[3]=='a'&&cmd_name[4]=='m'&&cmd_name[5]=='i') {
            uint16_t uid = fs_current_uid();
            terminal_writestring("\n");
            if (g_login_user[0]) terminal_writestring(g_login_user);
            else if (uid == 0) terminal_writestring("root");
            else terminal_writestring("?");
            terminal_writestring(" uid="); shell_write_u32((uint32_t)uid);
            terminal_writestring(" gid="); shell_write_u32((uint32_t)fs_current_gid());
            flush_line(); return;
        }

        // Команда id - uid/gid/группа
        if (cmd_name_len==2 && cmd_name[0]=='i'&&cmd_name[1]=='d') {
            uint16_t uid = fs_current_uid();
            uint16_t gid = fs_current_gid();
            terminal_writestring("\nuid=");
            shell_write_u32((uint32_t)uid);
            terminal_writestring(" gid=");
            shell_write_u32((uint32_t)gid);
            if (g_login_user[0]) { terminal_writestring(" ("); terminal_writestring(g_login_user); terminal_writestring(")"); }
            terminal_writestring(" groups=");
            shell_write_u32((uint32_t)gid);
            flush_line(); return;
        }

        // Команда users - список пользователей
        if (cmd_name_len==5 && cmd_name[0]=='u'&&cmd_name[1]=='s'&&cmd_name[2]=='e'&&cmd_name[3]=='r'&&cmd_name[4]=='s') {
            user_auth_dump();
            flush_line(); return;
        }

        // Команда sessions - список консольных сессий
        if (cmd_name_len==8 && strncmp(cmd_name, "sessions", 8) == 0) {
            terminal_writestring("\n=== Sessions ===");
            for (int i = 0; i < SESS_MAX; i++) {
                struct shell_session* s = &g_sessions[i];
                if (!s->used) continue;
                terminal_writestring("\n  [");
                if (i == g_current_session) terminal_writestring("*");
                else terminal_writestring(" ");
                { char num[8]; int np=0; int v=i; if(v==0)num[np++]='0'; else {char tmp[8];int t=0;while(v>0){tmp[t++]='0'+(v%10);v/=10;}while(t>0)num[np++]=tmp[--t];} num[np]=0; terminal_writestring(num); }
                terminal_writestring("] ");
                terminal_writestring(s->name);
                terminal_writestring("  uid=");
                shell_write_u32(s->uid);
                terminal_writestring(" user=");
                terminal_writestring(s->login[0] ? s->login : "root");
                terminal_writestring(" cwd=");
                terminal_writestring(s->cwd[0] ? s->cwd : "/");
                terminal_writestring(" hist=");
                shell_write_u32((uint32_t)s->hcnt);
            }
            terminal_writestring("\nUsage: session <n> | newsession <name>");
            flush_line(); return;
        }

        // Команда newsession - создать новую независимую сессию (только root)
        if (cmd_name_len==10 && strncmp(cmd_name, "newsession", 10) == 0) {
            if (fs_current_uid() != 0) { terminal_writestring("\nnewsession: permission denied"); flush_line(); return; }
            int slot = -1;
            for (int i = 0; i < SESS_MAX; i++) if (!g_sessions[i].used) { slot = i; break; }
            if (slot < 0) { terminal_writestring("\nnewsession: no free slots"); flush_line(); return; }
            struct shell_session* s = &g_sessions[slot];
            memset(s, 0, sizeof(*s));
            s->id = slot;
            s->used = true;
            s->uid = 0;
            s->gid = 0;
            s->login[0] = 0;
            s->hcnt = 0;
            s->hpos = -1;
            s->tabll = (size_t)-1;
            s->tabci = -1;
            char nm[16];
            if (argc >= 2) strncpy(nm, argv[1], sizeof(nm) - 1);
            else { size_t k = 0; const char* base = "tty"; while (base[k] && k < 10) { nm[k] = base[k]; k++; } char dn[4]; int t=0; int v=slot; if(v==0)dn[t++]='0'; else {char tb[4];int tc=0;while(v>0){tb[tc++]='0'+(v%10);v/=10;}while(tc>0)dn[t++]=tb[--tc];} dn[t]=0; size_t j=0; while(dn[j] && k < 15) nm[k++] = dn[j++]; nm[k]=0; }
            strncpy(s->name, nm, sizeof(s->name) - 1);
            strncpy(s->cwd, "/", sizeof(s->cwd) - 1);
            g_session_count++;
            terminal_writestring("\nSession created ");
            terminal_writestring(s->name);
            terminal_writestring(" (");
            { char num[8]; int np=0; int v=slot; if(v==0)num[np++]='0'; else {char tmp[8];int t=0;while(v>0){tmp[t++]='0'+(v%10);v/=10;}while(t>0)num[np++]=tmp[--t];} num[np]=0; terminal_writestring(num); }
            terminal_writestring(")");
            flush_line(); return;
        }

        // Команда session - переключение на сессию
        if (cmd_name_len==7 && strncmp(cmd_name, "session", 7) == 0) {
            if (argc < 2) { terminal_writestring("\nUsage: session <n>"); flush_line(); return; }
            int n = 0;
            const char* us = argv[1];
            while (*us >= '0' && *us <= '9') { n = n * 10 + (*us - '0'); us++; }
            if (switch_session(n) != 0) { terminal_writestring("\nsession: invalid slot"); flush_line(); return; }
            return; /* switch_session уже напечатал промпт — без flush_line */
        }

        // Команда groupadd - создать группу (только root)
        if (cmd_name_len==8 && strncmp(cmd_name, "groupadd", 8) == 0) {
            if (fs_current_uid() != 0) { terminal_writestring("\ngroupadd: permission denied"); flush_line(); return; }
            if (argc < 2) { terminal_writestring("\nUsage: groupadd <name> [gid]"); flush_line(); return; }
            uint16_t gid = 0;
            if (argc >= 3) { const char* gs = argv[2]; while (*gs >= '0' && *gs <= '9') { gid = (uint16_t)(gid * 10 + (*gs - '0')); gs++; } }
            if (group_add(argv[1], gid) != 0) { terminal_writestring("\ngroupadd: failed (exists/full)"); flush_line(); return; }
            const struct group_record* g = group_by_name(argv[1]);
            terminal_writestring("\nGroup ");
            terminal_writestring(argv[1]);
            terminal_writestring(" added, gid=");
            shell_write_u32(g ? g->gid : 0);
            flush_line(); return;
        }

        // Команда userdel - удалить пользователя (только root)
        if (cmd_name_len==7 && strncmp(cmd_name, "userdel", 7) == 0) {
            if (fs_current_uid() != 0) { terminal_writestring("\nuserdel: permission denied"); flush_line(); return; }
            if (argc < 2) { terminal_writestring("\nUsage: userdel <name>"); flush_line(); return; }
            if (user_del(argv[1]) != 0) { terminal_writestring("\nuserdel: failed (root or not found)"); flush_line(); return; }
            terminal_writestring("\nUser ");
            terminal_writestring(argv[1]);
            terminal_writestring(" deleted");
            flush_line(); return;
        }

        // Команда usermod - изменить пользователя (только root)
        if (cmd_name_len==7 && strncmp(cmd_name, "usermod", 7) == 0) {
            if (fs_current_uid() != 0) { terminal_writestring("\nusermod: permission denied"); flush_line(); return; }
            if (argc < 2) { terminal_writestring("\nUsage: usermod <name> [newname] [uid] [gid]"); flush_line(); return; }
            const char* nn = (argc >= 3) ? argv[2] : 0;
            uint16_t nuid = 0, ngid = 0;
            if (argc >= 4) { const char* us = argv[3]; while (*us >= '0' && *us <= '9') { nuid = (uint16_t)(nuid * 10 + (*us - '0')); us++; } }
            if (argc >= 5) { const char* gs = argv[4]; while (*gs >= '0' && *gs <= '9') { ngid = (uint16_t)(ngid * 10 + (*gs - '0')); gs++; } }
            if (user_mod(argv[1], nn, nuid, ngid, 0) != 0) { terminal_writestring("\nusermod: failed"); flush_line(); return; }
            terminal_writestring("\nUser modified");
            flush_line(); return;
        }

        // Команда groups - список групп пользователя
        if (cmd_name_len==6 && strncmp(cmd_name, "groups", 6) == 0) {
            const char* user = (argc >= 2) ? argv[1] : (g_login_user[0] ? g_login_user : "root");
            const struct user_record* u = user_by_name(user);
            terminal_writestring("\n");
            terminal_writestring(user);
            terminal_writestring(" : ");
            const struct group_record* pg = u ? group_by_gid(u->gid) : 0;
            if (pg) terminal_writestring(pg->name);
            /* + членства из group's members (кроме основной группы) */
            for (int i = 0; i < groups_count(); i++) {
                const struct group_record* g = groups_get(i);
                if (!g || !g->valid) continue;
                if (u && g->gid != u->gid && csv_has_token(g->members, user)) {
                    terminal_writestring(" ");
                    terminal_writestring(g->name);
                }
            }
            flush_line(); return;
        }

        // Команда su - временный root/su (с паролем)
        if (cmd_name_len==2 && cmd_name[0]=='s'&&cmd_name[1]=='u') {
            const char* target = (argc >= 2) ? argv[1] : "root";
            const struct user_record* u = user_by_name(target);
            if (!u) { terminal_writestring("\nsu: unknown user"); flush_line(); return; }
            terminal_writestring("\nPassword: ");
            char pw[64];
            if (!read_password(pw, sizeof(pw))) { flush_line(); return; }
            if (!user_check_password(target, pw)) { terminal_writestring("\nsu: incorrect password"); flush_line(); return; }
            task_setuid_force(u->uid);
            fs_set_current_uid(u->uid);
            task_setgid_force(u->gid);
            fs_set_current_gid(u->gid);
            strncpy(g_login_user, u->name, UNAME_MAX - 1);
            g_login_user[UNAME_MAX - 1] = 0;
            cur_session()->uid = u->uid;
            cur_session()->gid = u->gid;
            struct fs_stat hst;
            if (fs_stat(u->home, &hst) == 0 && (hst.flags & FS_FLAG_DIRECTORY)) utils_set_current_directory(u->home);
            strncpy(cur_session()->cwd, utils_get_current_directory(), sizeof(cur_session()->cwd) - 1);
            terminal_writestring("\n");
            terminal_writestring(target);
            terminal_writestring(" shell");
            flush_line(); return;
        }

        // Команда useradd - создать пользователя (только root)
        if (cmd_name_len==7 && (strncmp(cmd_name, "useradd", 7) == 0)) {
            if (fs_current_uid() != 0) { terminal_writestring("\nuseradd: permission denied"); flush_line(); return; }
            if (argc < 2) { terminal_writestring("\nUsage: useradd <name> [uid]"); flush_line(); return; }
            uint16_t uid = 0;
            if (argc >= 3) {
                const char* us = argv[2];
                while (*us >= '0' && *us <= '9') { uid = (uint16_t)(uid * 10 + (*us - '0')); us++; }
            }
            char full_home[UHOME_MAX + 16];
            size_t k = 0;
            const char* h = "/home/";
            size_t hi = 0;
            while (h[hi] && k + 1 < sizeof(full_home)) full_home[k++] = h[hi++];
            size_t j = 0;
            while (argv[1][j] && k + 1 < sizeof(full_home)) full_home[k++] = argv[1][j++];
            full_home[k] = 0;
            fs_create_dir(full_home);
            int nuid = user_add(argv[1], uid, uid, full_home);
            if (nuid < 0) { terminal_writestring("\nuseradd: failed (exists or full)"); flush_line(); return; }
            /* Отдаём home новому пользователю сразу (иначе он не сможет писать до ребута). */
            fs_chown(full_home, (uint16_t)nuid, (uint16_t)nuid);
            terminal_writestring("\nUser ");
            terminal_writestring(argv[1]);
            terminal_writestring(" added, uid=");
            shell_write_u32((uint32_t)nuid);
            terminal_writestring("\nNext: passwd <name> to set password");
            flush_line(); return;
        }

        // Команда passwd - сменить пароль
        if (cmd_name_len==6 && strncmp(cmd_name, "passwd", 6) == 0) {
            const char* target = g_login_user[0] ? g_login_user : "root";
            if (argc >= 2) {
                if (fs_current_uid() != 0 && strcmp(argv[1], target) != 0) {
                    terminal_writestring("\npasswd: permission denied"); flush_line(); return;
                }
                target = argv[1];
            }
            if (!user_by_name(target)) { terminal_writestring("\npasswd: unknown user"); flush_line(); return; }
            terminal_writestring("\nNew password: ");
            char pw[64], pw2[64];
            if (!read_password(pw, sizeof(pw))) { flush_line(); return; }
            terminal_writestring("Confirm password: ");
            if (!read_password(pw2, sizeof(pw2))) { flush_line(); return; }
            if (strcmp(pw, pw2) != 0) { terminal_writestring("\npasswd: passwords do not match"); flush_line(); return; }
            if (user_set_password(target, pw) != 0) { terminal_writestring("\npasswd: failed"); flush_line(); return; }
            terminal_writestring("\nPassword updated for ");
            terminal_writestring(target);
            flush_line(); return;
        }
        
        // Пытаемся найти встроенную команду
        char cmd_name_buf[64];
        int j = 0;
        while (j < (int)cmd_name_len && j < 63) {
            cmd_name_buf[j] = cmd_name[j];
            j++;
        }
        cmd_name_buf[j] = 0;
        
        const struct builtin_command* builtin = find_builtin(cmd_name_buf);
        if (builtin) {
            execute_builtin(cmd_name_buf, argc, argv);
            flush_line(); return;
        }
        
        // Старые команды для обратной совместимости
        if (len==4 && cmd[0]=='d'&&cmd[1]=='i'&&cmd[2]=='s'&&cmd[3]=='k') {
            int disk_count = disk_manager_count();
            terminal_writestring("\n=== Disk Information ===");
            terminal_writestring("\nTotal disks detected: ");
            char count_buf[4];
            int p = 0;
            int n = disk_count;
            if (n == 0) count_buf[p++] = '0';
            else {
                char tmp[12]; int t = 0;
                while (n > 0 && t < 11) { tmp[t++] = '0' + (n % 10); n /= 10; }
                while (t > 0) count_buf[p++] = tmp[--t];
            }
            count_buf[p] = 0;
            terminal_writestring(count_buf);
            terminal_writestring("\n");
            
            // Показываем информацию о каждом диске
            for (int i = 0; i < disk_count; i++) {
                const struct disk_info* disk = disk_manager_get_disk(i);
                if (!disk) continue;
                
                terminal_writestring("\n--- ");
                if (disk->is_atapi) {
                    terminal_writestring("Optical Drive ");
                } else {
                    terminal_writestring("Disk ");
                }
                char disk_num[4];
                p = 0;
                n = i;
                if (n == 0) disk_num[p++] = '0';
                else {
                    char tmp[12]; int t = 0;
                    while (n > 0 && t < 11) { tmp[t++] = '0' + (n % 10); n /= 10; }
                    while (t > 0) disk_num[p++] = tmp[--t];
                }
                disk_num[p] = 0;
                terminal_writestring(disk_num);
                terminal_writestring(" (");
                terminal_writestring(disk->name);
                if (disk->is_atapi) {
                    terminal_writestring(") - CD/DVD Drive ---\n");
                } else {
                terminal_writestring(") ---\n");
                }
                
                terminal_writestring("Controller Type: ");
                if (disk->controller_type == DISK_CONTROLLER_NVME) {
                    terminal_writestring("NVMe");
                } else if (disk->controller_type == DISK_CONTROLLER_ATA) {
                    terminal_writestring("ATA/IDE");
                } else if (disk->controller_type == DISK_CONTROLLER_AHCI) {
                    terminal_writestring("AHCI (SATA)");
                } else {
                    terminal_writestring("Unknown");
                }
                terminal_writestring("\nStatus: ");
                terminal_writestring(disk->active ? "Active" : "Inactive");
                terminal_writestring("\n");
                
                if (disk->controller_type == DISK_CONTROLLER_NVME) {
                    terminal_writestring("Interface: NVMe (PCIe)\n");
                    terminal_writestring("Mode: Native Command Queuing supported\n");
                } else if (disk->controller_type == DISK_CONTROLLER_ATA) {
                    terminal_writestring("Interface: Legacy ATA/IDE (PIO mode)\n");
                    if (disk->ata_channel != DISK_LOC_NA) {
                        terminal_writestring("Channel: ");
                        terminal_writestring(disk->ata_channel == 0 ? "primary" : "secondary");
                        terminal_writestring(disk->ata_select == ATA_SELECT_MASTER ? " master\n" : " slave\n");
                        terminal_writestring("Port: 0x");
                        char hex[5];
                        uint16_t port = disk->ata_channel == 0 ? ATA_PRIMARY_DATA : ATA_SECONDARY_DATA;
                        hex[0] = "0123456789ABCDEF"[(port >> 12) & 0xF];
                        hex[1] = "0123456789ABCDEF"[(port >> 8) & 0xF];
                        hex[2] = "0123456789ABCDEF"[(port >> 4) & 0xF];
                        hex[3] = "0123456789ABCDEF"[port & 0xF];
                        hex[4] = 0;
                        terminal_writestring(hex);
                        terminal_writestring("\n");
                    }
                } else if (disk->controller_type == DISK_CONTROLLER_AHCI) {
                    terminal_writestring("Interface: AHCI (SATA)\n");
                    if (disk->ahci_port != DISK_LOC_NA) {
                        terminal_writestring("SATA port: ");
                        char port_buf[4];
                        int p = 0;
                        int n = disk->ahci_port;
                        if (n == 0) port_buf[p++] = '0';
                        else {
                            char tmp[4]; int t = 0;
                            while (n > 0 && t < 3) { tmp[t++] = '0' + (n % 10); n /= 10; }
                            while (t > 0) port_buf[p++] = tmp[--t];
                        }
                        port_buf[p] = 0;
                        terminal_writestring(port_buf);
                        terminal_writestring("\n");
                    }
                }
                
                // Показываем размер диска (только для обычных дисков, не для дисководов)
                if (disk->is_atapi) {
                    terminal_writestring("Type: CD/DVD Drive\n");
                    terminal_writestring("Size: Variable (depends on media)\n");
                } else if (disk->size_sectors > 0) {
                    uint32_t total_mb = (disk->size_sectors * 512) / (1024 * 1024);
                    char size_buf[16];
                    p = 0;
                    n = total_mb;
                    if (n == 0) size_buf[p++] = '0';
                    else {
                        char tmp[12]; int t = 0;
                        while (n > 0 && t < 11) { tmp[t++] = '0' + (n % 10); n /= 10; }
                        while (t > 0) size_buf[p++] = tmp[--t];
                    }
                    size_buf[p++] = ' ';
                    size_buf[p++] = 'M';
                    size_buf[p++] = 'B';
                    size_buf[p] = 0;
                    terminal_writestring("Size: ");
                    terminal_writestring(size_buf);
                    terminal_writestring("\n");
                } else {
                    terminal_writestring("Size: Unknown\n");
                }
            }
            
            // Показываем информацию о емкости активного диска (для файловой системы)
            enum disk_controller_type ctrl_type = disk_get_controller_type();
            if (ctrl_type != DISK_CONTROLLER_NONE) {
                terminal_writestring("\n--- Active Disk Usage ---\n");
                uint32_t total_bytes, used_bytes, free_bytes;
                if (fs_get_disk_usage(&total_bytes, &used_bytes, &free_bytes) == 0) {
                    // Функция для форматирования байт в читаемый формат
                    auto format_bytes = [](uint32_t bytes, char* buf) {
                        if (bytes < 1024) {
                            int p = 0;
                            uint32_t n = bytes;
                            if (n == 0) buf[p++] = '0';
                            else {
                                char tmp[12]; int t = 0;
                                while (n > 0 && t < 11) { tmp[t++] = '0' + (n % 10); n /= 10; }
                                while (t > 0) buf[p++] = tmp[--t];
                            }
                            buf[p++] = ' ';
                            buf[p++] = 'B';
                            buf[p] = 0;
                        } else if (bytes < 1024 * 1024) {
                            uint32_t kb = bytes / 1024;
                            int p = 0;
                            if (kb == 0) buf[p++] = '0';
                            else {
                                char tmp[12]; int t = 0;
                                while (kb > 0 && t < 11) { tmp[t++] = '0' + (kb % 10); kb /= 10; }
                                while (t > 0) buf[p++] = tmp[--t];
                            }
                            buf[p++] = ' ';
                            buf[p++] = 'K';
                            buf[p++] = 'B';
                            buf[p] = 0;
                        } else {
                            uint32_t mb = bytes / (1024 * 1024);
                            int p = 0;
                            if (mb == 0) buf[p++] = '0';
                            else {
                                char tmp[12]; int t = 0;
                                while (mb > 0 && t < 11) { tmp[t++] = '0' + (mb % 10); mb /= 10; }
                                while (t > 0) buf[p++] = tmp[--t];
                            }
                            buf[p++] = ' ';
                            buf[p++] = 'M';
                            buf[p++] = 'B';
                            buf[p] = 0;
                        }
                    };
                    
                    char total_buf[32], used_buf[32], free_buf[32];
                    format_bytes(total_bytes, total_buf);
                    format_bytes(used_bytes, used_buf);
                    format_bytes(free_bytes, free_buf);
                    
                    terminal_writestring("\n--- Disk Capacity ---");
                    terminal_writestring("\nTotal: ");
                    terminal_writestring(total_buf);
                    terminal_writestring("\nUsed:  ");
                    terminal_writestring(used_buf);
                    terminal_writestring("\nFree:  ");
                    terminal_writestring(free_buf);
                    
                    // Процент использования
                    if (total_bytes > 0) {
                        uint32_t percent = (used_bytes * 100) / total_bytes;
                        terminal_writestring("\nUsage: ");
                        char pct_buf[8];
                        int p = 0;
                        if (percent == 0) pct_buf[p++] = '0';
                        else {
                            char tmp[8]; int t = 0;
                            uint32_t n = percent;
                            while (n > 0 && t < 7) { tmp[t++] = '0' + (n % 10); n /= 10; }
                            while (t > 0) pct_buf[p++] = tmp[--t];
                        }
                        pct_buf[p++] = '%';
                        pct_buf[p] = 0;
                        terminal_writestring(pct_buf);
                    }
                } else {
                    terminal_writestring("\nFilesystem: Not initialized");
                }
            }
            flush_line(); return;
        }
        
        // Команда write
        const char pref_write[]="write ";
        if (len>=6) {
            bool ok=true; for(int i=0;i<6;i++) if(cmd[i]!=pref_write[i]) {ok=false; break;}
            if (ok) {
                // Ищем имя файла (после "write ")
                size_t i=6;
                while(i<len && cmd[i]==' ') i++;
                if(i>=len) {
                    terminal_writestring("\nUsage: write <file> <text>");
                    terminal_writestring("\nExample: write test.txt Hello World");
                    flush_line(); return;
                }
                char filename[64]; int fn_len=0;
                while(i<len && cmd[i]!=' ' && fn_len<63) filename[fn_len++]=cmd[i++];
                filename[fn_len]=0;
                
                // Пропускаем пробелы после имени файла
                while(i<len && cmd[i]==' ') i++;
                
                if(i<len) {
                    // Есть текст для записи
                    // Если путь относительный, преобразуем в абсолютный
                    char full_path[128];
                    if (filename[0] != '/') {
                        const char* cwd = utils_get_current_directory();
                        int p = 0;
                        // Копируем текущую директорию
                        while (cwd[p] && p < 127) {
                            full_path[p] = cwd[p];
                            p++;
                        }
                        // Добавляем / если его нет в конце
                        if (p > 0 && full_path[p-1] != '/') {
                            full_path[p++] = '/';
                        }
                        // Добавляем имя файла
                        int j = 0;
                        while (filename[j] && p < 127) {
                            full_path[p++] = filename[j++];
                        }
                        full_path[p] = 0;
                    } else {
                        // Абсолютный путь - используем как есть
                        int j = 0;
                        while (filename[j] && j < 127) {
                            full_path[j] = filename[j];
                            j++;
                        }
                        full_path[j] = 0;
                    }
                    
                    if (fs_write(full_path, cmd+i, len-i) == 0) {
                        terminal_writestring("\nFile created");
                    } else {
                        terminal_writestring("\nError writing file");
                        terminal_writestring("\nCheck disk status with 'disk' command");
                    }
                } else {
                    terminal_writestring("\nUsage: write <file> <text>");
                    terminal_writestring("\nExample: write test.txt Hello World");
                }
                flush_line(); return;
            }
        }
        
        // Команда cat
        const char pref_cat[]="cat ";
        static char file_read_buf[4096];
        if (len>=5) {
            bool ok=true; for(int i=0;i<4;i++) if(cmd[i]!=pref_cat[i]) {ok=false; break;}
            if (ok) {
                char filename[64]; int fn_len=0;
                for(size_t i=4;i<len && fn_len<63;i++) filename[fn_len++]=cmd[i];
                filename[fn_len]=0;
                char fullpath[128];
                if (utils_resolve_path(filename, fullpath, sizeof(fullpath)) != 0) {
                    terminal_writestring("\nInvalid path");
                    flush_line(); return;
                }
                uint32_t file_size;
                char dir_test[4];
                if (fs_list_dir(fullpath, dir_test, sizeof(dir_test)) >= 0) {
                    terminal_writestring("\n");
                    terminal_writestring(fullpath);
                    terminal_writestring(": Is a directory");
                } else if (fs_open(fullpath, &file_size) == 0) {
                    terminal_writestring("\n");
                    if (file_size == 0) {
                        terminal_writestring("(empty file)");
                    } else if (file_size < sizeof(file_read_buf)) {
                        if (fs_read(fullpath, file_read_buf, file_size) >= 0) {
                            file_read_buf[file_size] = 0;
                            terminal_writestring(file_read_buf);
                        } else {
                            terminal_writestring("Error reading file");
                        }
                    } else {
                        terminal_writestring("File too large (max 4KB)");
                    }
                } else {
                    terminal_writestring("\nFile not found: ");
                    terminal_writestring(fullpath);
                }
                flush_line(); return;
            }
        }

        // Команда nano
        const char pref_nano[] = "nano ";
        if (len >= 6) {
            bool ok = true;
            for (int i = 0; i < 5; i++) if (cmd[i] != pref_nano[i]) { ok = false; break; }
            if (ok) {
                char filename[64];
                int fn_len = 0;
                for (size_t i = 5; i < len && fn_len < 63; i++) filename[fn_len++] = cmd[i];
                filename[fn_len] = 0;
                char fullpath[128];
                if (utils_resolve_path(filename, fullpath, sizeof(fullpath)) != 0) {
                    terminal_writestring("\nInvalid path");
                    flush_line(); return;
                }
                nano_edit(fullpath);
                line_len = 0;
                flush_line(); return;
            }
        }
        
        if (len>=2 && cmd[0]=='r'&&cmd[1]=='m'&&(len==2 || cmd[2]==' ')) {
            bool recursive = false;
            size_t i = 2;
            while (i < len && cmd[i]==' ') i++;
            if (i + 2 < len && cmd[i]=='-' && cmd[i+1]=='r') {
                recursive = true;
                i += 2;
                while (i < len && cmd[i]==' ') i++;
            }
            char filename[64]; int fn_len=0;
            for (; i < len && fn_len < 63; i++) filename[fn_len++]=cmd[i];
            filename[fn_len]=0;
            if (fn_len == 0) {
                terminal_writestring("\nUsage: rm [-r] <path>");
                flush_line(); return;
            }
            char fullpath[128];
            if (utils_resolve_path(filename, fullpath, sizeof(fullpath)) != 0) {
                terminal_writestring("\nInvalid path");
                flush_line(); return;
            }
            if (fullpath[0]=='/' && fullpath[1]==0) {
                terminal_writestring("\nrm: refuse to remove /");
                flush_line(); return;
            }
            int rc = recursive ? fs_rm_rf(fullpath) : fs_delete(fullpath);
            terminal_writestring(rc == 0 ? "\nDeleted" : "\nError deleting");
            flush_line(); return;
        }
        if (len>=3 && cmd[0]=='m'&&cmd[1]=='v'&&cmd[2]==' ') {
            char a[64], b[64]; int an=0, bn=0; size_t i=3;
            while (i<len && cmd[i]!=' ' && an<63) a[an++]=cmd[i++];
            a[an]=0;
            while (i<len && cmd[i]==' ') i++;
            while (i<len && bn<63) b[bn++]=cmd[i++];
            b[bn]=0;
            char pa[128], pb[128];
            if (!an || !bn || utils_resolve_path(a,pa,sizeof(pa)) || utils_resolve_path(b,pb,sizeof(pb))) {
                terminal_writestring("\nUsage: mv <src> <dst>");
                flush_line(); return;
            }
            terminal_writestring(fs_rename(pa,pb)==0 ? "\nMoved" : "\nmv failed");
            flush_line(); return;
        }
        if (len>=3 && cmd[0]=='c'&&cmd[1]=='p'&&cmd[2]==' ') {
            char a[64], b[64]; int an=0, bn=0; size_t i=3;
            while (i<len && cmd[i]!=' ' && an<63) a[an++]=cmd[i++];
            a[an]=0;
            while (i<len && cmd[i]==' ') i++;
            while (i<len && bn<63) b[bn++]=cmd[i++];
            b[bn]=0;
            char pa[128], pb[128];
            if (!an || !bn || utils_resolve_path(a,pa,sizeof(pa)) || utils_resolve_path(b,pb,sizeof(pb))) {
                terminal_writestring("\nUsage: cp <src> <dst>");
                flush_line(); return;
            }
            uint32_t sz=0;
            if (fs_open(pa,&sz)!=0) { terminal_writestring("\ncp: src missing"); flush_line(); return; }
            char* buf = (char*)malloc(sz ? sz : 1);
            if (!buf) { terminal_writestring("\ncp: oom"); flush_line(); return; }
            if (sz && fs_read(pa, buf, sz) < 0) { free(buf); terminal_writestring("\ncp: read fail"); flush_line(); return; }
            int w = fs_write(pb, buf, sz);
            free(buf);
            terminal_writestring(w==0 ? "\nCopied" : "\ncp failed");
            flush_line(); return;
        }
        if (len>=3 && cmd[0]=='l'&&cmd[1]=='n'&&cmd[2]==' ') {
            bool soft = false;
            size_t i = 3;
            if (i+2 < len && cmd[i]=='-' && cmd[i+1]=='s' && (cmd[i+2]==' ' || cmd[i+2]==0)) {
                soft = true;
                i += 2;
                while (i < len && cmd[i]==' ') i++;
            }
            char a[64], b[64]; int an=0, bn=0;
            while (i<len && cmd[i]!=' ' && an<63) a[an++]=cmd[i++];
            a[an]=0;
            while (i<len && cmd[i]==' ') i++;
            while (i<len && bn<63) b[bn++]=cmd[i++];
            b[bn]=0;
            char pa[128], pb[128];
            if (!an || !bn || utils_resolve_path(b,pb,sizeof(pb))) {
                terminal_writestring("\nUsage: ln [-s] <target> <link>");
                flush_line(); return;
            }
            if (soft) {
                terminal_writestring(fs_symlink(a,pb)==0 ? "\nSymlink created" : "\nln failed");
            } else {
                if (utils_resolve_path(a,pa,sizeof(pa))) {
                    terminal_writestring("\nln: bad target"); flush_line(); return;
                }
                terminal_writestring(fs_link(pa,pb)==0 ? "\nHard link created" : "\nln failed");
            }
            flush_line(); return;
        }
        if (len>=6 && cmd[0]=='c'&&cmd[1]=='h'&&cmd[2]=='m'&&cmd[3]=='o'&&cmd[4]=='d'&&cmd[5]==' ') {
            char mode_s[16]; int mn=0; size_t i=6;
            while (i<len && cmd[i]!=' ' && mn<15) mode_s[mn++]=cmd[i++];
            mode_s[mn]=0;
            while (i<len && cmd[i]==' ') i++;
            char filename[64]; int fn=0;
            while (i<len && fn<63) filename[fn++]=cmd[i++];
            filename[fn]=0;
            char fullpath[128];
            uint16_t mode = 0;
            for (int k=0; mode_s[k]; k++) {
                if (mode_s[k] < '0' || mode_s[k] > '7') { mode = 0; break; }
                mode = (uint16_t)((mode << 3) | (mode_s[k] - '0'));
            }
            if (!fn || !mode || utils_resolve_path(filename, fullpath, sizeof(fullpath))) {
                terminal_writestring("\nUsage: chmod <octal> <path>"); flush_line(); return;
            }
            terminal_writestring(fs_chmod(fullpath, mode)==0 ? "\nOK" : "\nchmod failed");
            flush_line(); return;
        }
        if (len>=6 && cmd[0]=='c'&&cmd[1]=='h'&&cmd[2]=='o'&&cmd[3]=='w'&&cmd[4]=='n'&&cmd[5]==' ') {
            char uid_s[16]; int un=0; size_t i=6;
            while (i<len && cmd[i]!=' ' && un<15) uid_s[un++]=cmd[i++];
            uid_s[un]=0;
            while (i<len && cmd[i]==' ') i++;
            char filename[64]; int fn=0;
            while (i<len && fn<63) filename[fn++]=cmd[i++];
            filename[fn]=0;
            char fullpath[128];
            uint16_t uid = 0;
            for (int k=0; uid_s[k]; k++) {
                if (uid_s[k] < '0' || uid_s[k] > '9') { uid = 0xFFFF; break; }
                uid = (uint16_t)(uid * 10 + (uid_s[k] - '0'));
            }
            if (!fn || uid == 0xFFFF || utils_resolve_path(filename, fullpath, sizeof(fullpath))) {
                terminal_writestring("\nUsage: chown <uid> <path>"); flush_line(); return;
            }
            /* Сохраняем существующий gid (chown меняет только владельца). */
            uint16_t keep_gid = 0;
            struct fs_stat cst;
            if (fs_stat(fullpath, &cst) == 0) keep_gid = cst.gid;
            terminal_writestring(fs_chown(fullpath, uid, keep_gid)==0 ? "\nOK" : "\nchown failed");
            flush_line(); return;
        }
        if (len>=6 && cmd[0]=='c'&&cmd[1]=='h'&&cmd[2]=='g'&&cmd[3]=='r'&&cmd[4]=='p'&&cmd[5]==' ') {
            char gid_s[16]; int gn=0; size_t i=6;
            while (i<len && cmd[i]!=' ' && gn<15) gid_s[gn++]=cmd[i++];
            gid_s[gn]=0;
            while (i<len && cmd[i]==' ') i++;
            char filename[64]; int fn=0;
            while (i<len && fn<63) filename[fn++]=cmd[i++];
            filename[fn]=0;
            char fullpath[128];
            uint16_t gid = 0;
            bool bad=false;
            for (int k=0; gid_s[k]; k++) {
                if (gid_s[k] < '0' || gid_s[k] > '9') { bad=true; break; }
                gid = (uint16_t)(gid * 10 + (gid_s[k] - '0'));
            }
            if (!fn || bad || utils_resolve_path(filename, fullpath, sizeof(fullpath))) {
                terminal_writestring("\nUsage: chgrp <gid> <path>"); flush_line(); return;
            }
            terminal_writestring(fs_chgrp(fullpath, gid)==0 ? "\nOK" : "\nchgrp failed (root/owner)");
            flush_line(); return;
        }
        if (len>=6 && cmd[0]=='t'&&cmd[1]=='o'&&cmd[2]=='u'&&cmd[3]=='c'&&cmd[4]=='h'&&cmd[5]==' ') {
            char filename[64]; int fn=0;
            for (size_t i=6;i<len&&fn<63;i++) filename[fn++]=cmd[i];
            filename[fn]=0;
            char fullpath[128];
            if (!fn || utils_resolve_path(filename, fullpath, sizeof(fullpath))) {
                terminal_writestring("\nUsage: touch <path>"); flush_line(); return;
            }
            terminal_writestring(fs_touch(fullpath)==0 ? "\nOK" : "\ntouch failed");
            flush_line(); return;
        }
        if (len==2 && cmd[0]=='d'&&cmd[1]=='f') {
            uint32_t t=0,u=0,f=0;
            if (fs_get_disk_usage(&t,&u,&f)!=0) { terminal_writestring("\ndf failed"); flush_line(); return; }
            terminal_writestring("\nFilesystem MOS");
            terminal_writestring("\n  total: "); shell_write_u32(t);
            terminal_writestring("\n  used:  "); shell_write_u32(u);
            terminal_writestring("\n  free:  "); shell_write_u32(f);
            flush_line(); return;
        }
        if (len>=3 && cmd[0]=='d'&&cmd[1]=='u'&&cmd[2]==' ') {
            char filename[64]; int fn=0;
            for (size_t i=3;i<len&&fn<63;i++) filename[fn++]=cmd[i];
            filename[fn]=0;
            char fullpath[128];
            if (!fn || utils_resolve_path(filename, fullpath, sizeof(fullpath))) {
                terminal_writestring("\nUsage: du <path>"); flush_line(); return;
            }
            struct fs_stat st;
            if (fs_stat(fullpath, &st) != 0) { terminal_writestring("\ndu: not found"); flush_line(); return; }
            terminal_writestring("\n"); shell_write_u32(st.size); terminal_writestring("\t"); terminal_writestring(fullpath);
            flush_line(); return;
        }
        if (len==4 && cmd[0]=='s'&&cmd[1]=='y'&&cmd[2]=='n'&&cmd[3]=='c') {
            terminal_writestring(fs_sync()==0 ? "\nsync ok" : "\nsync failed");
            flush_line(); return;
        }
        if (len==5 && cmd[0]=='m'&&cmd[1]=='o'&&cmd[2]=='u'&&cmd[3]=='n'&&cmd[4]=='t') {
            terminal_writestring("\nMounts:");
            for (int mi = 0; ; mi++) {
                const struct mount_point* mp = mount_get(mi);
                if (!mp) break;
                terminal_writestring("\n  ");
                terminal_writestring(mp->path);
                terminal_writestring(mp->fs_type == FS_TYPE_RAMFS ? " ramfs" : " mos");
            }
            flush_line(); return;
        }
        if (len==4 && cmd[0]=='f'&&cmd[1]=='s'&&cmd[2]=='c'&&cmd[3]=='k') {
            int r = fs_fsck(true);
            terminal_writestring(r >= 0 ? "\nfsck done" : "\nfsck failed");
            flush_line(); return;
        }
        if (len>=5 && cmd[0]=='s'&&cmd[1]=='t'&&cmd[2]=='a'&&cmd[3]=='t'&&cmd[4]==' ') {
            char filename[64]; int fn=0;
            for (size_t i=5;i<len&&fn<63;i++) filename[fn++]=cmd[i];
            filename[fn]=0;
            char fullpath[128];
            if (utils_resolve_path(filename, fullpath, sizeof(fullpath)) != 0) {
                terminal_writestring("\nInvalid path"); flush_line(); return;
            }
            struct fs_stat st;
            if (fs_stat(fullpath, &st) != 0) {
                terminal_writestring("\nstat: not found"); flush_line(); return;
            }
            terminal_writestring("\n  path: "); terminal_writestring(fullpath);
            terminal_writestring("\n  size: "); shell_write_u32(st.size);
            terminal_writestring("\n  mode: "); shell_write_u32(st.mode);
            terminal_writestring("\n  mtime: "); shell_write_u32(st.mtime);
            if (st.flags & FS_FLAG_DIRECTORY) terminal_writestring("\n  type: dir");
            else if (st.flags & FS_FLAG_SYMLINK) terminal_writestring("\n  type: symlink");
            else terminal_writestring("\n  type: file");
            flush_line(); return;
        }
        if (len>=6 && cmd[0]=='m'&&cmd[1]=='k'&&cmd[2]=='d'&&cmd[3]=='i'&&cmd[4]=='r'&&cmd[5]==' ') {
            char filename[64]; int fn=0; size_t i=6;
            bool parents = false;
            if (i+2 < len && cmd[i]=='-' && cmd[i+1]=='p') {
                parents = true; i += 2;
                while (i < len && cmd[i]==' ') i++;
            }
            (void)parents; /* create_dir always makes parents */
            for (; i<len&&fn<63;i++) filename[fn++]=cmd[i];
            filename[fn]=0;
            char fullpath[128];
            if (!fn || utils_resolve_path(filename, fullpath, sizeof(fullpath))) {
                terminal_writestring("\nUsage: mkdir [-p] <path>"); flush_line(); return;
            }
            terminal_writestring(vfs_mkdir(fullpath)==0 ? "\nDirectory created" : "\nmkdir failed");
            flush_line(); return;
        }
        if (len==4 && cmd[0]=='t'&&cmd[1]=='e'&&cmd[2]=='s'&&cmd[3]=='t') {
            terminal_writestring("\nTesting scroll - printing 100 lines...");
            for (int i = 1; i <= 100; i++) {
                terminal_writestring("\nLine ");
                char num[12]; int p = 0;
                int n = i;
                if (n == 0) num[p++] = '0';
                else {
                    char tmp[12]; int t = 0;
                    while (n > 0 && t < 11) { tmp[t++] = '0' + (n % 10); n /= 10; }
                    while (t > 0) num[p++] = tmp[--t];
                }
                num[p] = 0;
                terminal_writestring(num);
                terminal_writestring(" of 100");
            }
            terminal_writestring("\nTest complete. If you see this, scroll works!");
            flush_line(); return;
        }
        if (len==5 && cmd[0]=='c'&&cmd[1]=='l'&&cmd[2]=='e'&&cmd[3]=='a'&&cmd[4]=='r') {
            cmd_clear(); return;
        }
        if (len==7 && cmd[0]=='v'&&cmd[1]=='e'&&cmd[2]=='r'&&cmd[3]=='s'&&cmd[4]=='i'&&cmd[5]=='o'&&cmd[6]=='n') {
            terminal_writestring("\n");
            terminal_writestring(KERNEL_NAME);
            terminal_writestring(" ");
            terminal_writestring(KERNEL_VERSION);
            terminal_writestring(" (");
            terminal_writestring(KERNEL_BUILD);
            terminal_writestring(")");
            flush_line(); return;
        }
        if (len==4 && cmd[0]=='d'&&cmd[1]=='a'&&cmd[2]=='t'&&cmd[3]=='e') {
            char dtbuf[21];
            rtc_format_timestamp(dtbuf, sizeof(dtbuf));
            terminal_writestring("\n");
            if (rtc_valid()) {
                terminal_writestring(dtbuf);
            } else {
                terminal_writestring("RTC time unavailable");
            }
            terminal_writestring("\nUsage: setdate YYYY-MM-DD | settime HH:MM:SS");
            flush_line(); return;
        }
        /* Установка даты/времени RTC (CMOS). */
        if (cmd_name_len==7 && cmd_name[0]=='s'&&cmd_name[1]=='e'&&cmd_name[2]=='t'&&
            cmd_name[3]=='d'&&cmd_name[4]=='a'&&cmd_name[5]=='t'&&cmd_name[6]=='e') {
            if (argc < 2) {
                terminal_writestring("\nUsage: setdate YYYY-MM-DD");
                flush_line(); return;
            }
            const char* a = argv[1];
            int n;
            int y = 0, mo = 0, d = 0;
            n = 0;
            while (*a >= '0' && *a <= '9' && n < 4) { y = y * 10 + (*a - '0'); a++; n++; }
            if (n != 4 || *a != '-') { terminal_writestring("\nsetdate: bad format (YYYY-MM-DD)"); flush_line(); return; }
            a++;
            n = 0;
            while (*a >= '0' && *a <= '9' && n < 2) { mo = mo * 10 + (*a - '0'); a++; n++; }
            if (n != 2 || *a != '-') { terminal_writestring("\nsetdate: bad format (YYYY-MM-DD)"); flush_line(); return; }
            a++;
            n = 0;
            while (*a >= '0' && *a <= '9' && n < 2) { d = d * 10 + (*a - '0'); a++; n++; }
            if (n != 2 || *a != 0) { terminal_writestring("\nsetdate: bad format (YYYY-MM-DD)"); flush_line(); return; }
            struct rtc_time t = rtc_read();
            t.year = (uint16_t)y;
            t.month = (uint8_t)mo;
            t.day = (uint8_t)d;
            if (!rtc_write(t)) {
                terminal_writestring("\nsetdate: invalid value");
            } else {
                terminal_writestring("\nDate set to ");
                char dbuf[11];
                rtc_format_date(dbuf, sizeof(dbuf));
                terminal_writestring(dbuf);
            }
            refresh_status_line();
            flush_line(); return;
        }
        if (cmd_name_len==7 && cmd_name[0]=='s'&&cmd_name[1]=='e'&&cmd_name[2]=='t'&&
            cmd_name[3]=='t'&&cmd_name[4]=='i'&&cmd_name[5]=='m'&&cmd_name[6]=='e') {
            if (argc < 2) {
                terminal_writestring("\nUsage: settime HH:MM:SS");
                flush_line(); return;
            }
            const char* a = argv[1];
            int n;
            int h = 0, mi = 0, s = 0;
            n = 0;
            while (*a >= '0' && *a <= '9' && n < 2) { h = h * 10 + (*a - '0'); a++; n++; }
            if (n != 2 || *a != ':') { terminal_writestring("\nsettime: bad format (HH:MM:SS)"); flush_line(); return; }
            a++;
            n = 0;
            while (*a >= '0' && *a <= '9' && n < 2) { mi = mi * 10 + (*a - '0'); a++; n++; }
            if (n != 2 || *a != ':') { terminal_writestring("\nsettime: bad format (HH:MM:SS)"); flush_line(); return; }
            a++;
            n = 0;
            while (*a >= '0' && *a <= '9' && n < 2) { s = s * 10 + (*a - '0'); a++; n++; }
            if (n != 2 || *a != 0) { terminal_writestring("\nsettime: bad format (HH:MM:SS)"); flush_line(); return; }
            struct rtc_time t = rtc_read();
            t.hour = (uint8_t)h;
            t.minute = (uint8_t)mi;
            t.second = (uint8_t)s;
            if (!rtc_write(t)) {
                terminal_writestring("\nsettime: invalid value");
            } else {
                terminal_writestring("\nTime set to ");
                char tbuf[9];
                rtc_format_time(tbuf, sizeof(tbuf));
                terminal_writestring(tbuf);
            }
            refresh_status_line();
            flush_line(); return;
        }
        if (len >= 8 && cmd[0]=='r'&&cmd[1]=='u'&&cmd[2]=='n'&&cmd[3]=='e'&&cmd[4]=='l'&&cmd[5]=='f'&&cmd[6]==' ') {
            extern char user_demo_start[], user_demo_end[];
            extern char user_demo2_start[], user_demo2_end[];
            extern char user_demo3_start[], user_demo3_end[];
            extern char user_launcher_start[], user_launcher_end[];
            extern char user_argtest_start[], user_argtest_end[];
            extern char user_httpd_start[], user_httpd_end[];
            extern char user_ksshd_start[], user_ksshd_end[];
            extern char user_sshd_start[], user_sshd_end[];
            const char* arg = cmd + 7;
            const char* which = 0;
            char* start = 0;
            char* end = 0;
            const char* name = "hello";
            size_t alen = len - 7;
            if (alen >= 5 && arg[0]=='h'&&arg[1]=='e'&&arg[2]=='l'&&arg[3]=='l'&&arg[4]=='o') {
                which = "hello";
                start = user_demo_start; end = user_demo_end; name = "hello";
            } else if (alen >= 5 && arg[0]=='d'&&arg[1]=='e'&&arg[2]=='m'&&arg[3]=='o'&&arg[4]=='2') {
                which = "demo2";
                start = user_demo2_start; end = user_demo2_end; name = "demo2";
            } else if (alen >= 5 && arg[0]=='d'&&arg[1]=='e'&&arg[2]=='m'&&arg[3]=='o'&&arg[4]=='3') {
                which = "demo3";
                start = user_demo3_start; end = user_demo3_end; name = "demo3";
            } else if (alen >= 8 && arg[0]=='l'&&arg[1]=='a'&&arg[2]=='u'&&arg[3]=='n'&&arg[4]=='c'&&arg[5]=='h'&&arg[6]=='e'&&arg[7]=='r') {
                which = "launcher";
                start = user_launcher_start; end = user_launcher_end; name = "launcher";
            } else if (alen >= 7 && arg[0]=='a'&&arg[1]=='r'&&arg[2]=='g'&&arg[3]=='t'&&arg[4]=='e'&&arg[5]=='s'&&arg[6]=='t') {
                which = "argtest";
                start = user_argtest_start; end = user_argtest_end; name = "argtest";
            } else if (alen >= 5 && arg[0]=='h'&&arg[1]=='t'&&arg[2]=='t'&&arg[3]=='p'&&arg[4]=='d') {
                which = "httpd";
                start = user_httpd_start; end = user_httpd_end; name = "httpd";
            } else if (alen >= 5 && arg[0]=='k'&&arg[1]=='s'&&arg[2]=='s'&&arg[3]=='h'&&arg[4]=='d') {
                which = "ksshd";
                start = user_ksshd_start; end = user_ksshd_end; name = "ksshd";
            } else if (alen >= 4 && arg[0]=='s'&&arg[1]=='s'&&arg[2]=='h'&&arg[3]=='d') {
                which = "sshd";
                start = user_sshd_start; end = user_sshd_end; name = "sshd";
            }
            if (!which) {
                terminal_writestring("\nUsage: runelf hello|demo2|demo3|launcher|argtest|httpd|ksshd|sshd");
                flush_line(); return;
            }
            size_t sz = (size_t)(end - start);
            if (sz == 0) {
                terminal_writestring("\nNo embedded user program");
                flush_line(); return;
            }
            /* Серверные приложения запускаем от root (uid 0). */
            uint16_t spawn_uid = 1000;
            if ((which[0]=='s'&&which[1]=='s'&&which[2]=='h'&&which[3]=='d') ||
                (which[0]=='k'&&which[1]=='s'&&which[2]=='s'&&which[3]=='h'&&which[4]=='d'))
                spawn_uid = 0;
            int tid = task_spawn_user_uid((const uint8_t*)start, sz, name, spawn_uid);
            terminal_writestring("\nSpawned user task");
            if (tid >= 0) {
                char tbuf[12]; int tp = 0;
                uint32_t t = (uint32_t)tid;
                if (t == 0) { tbuf[tp++] = '0'; }
                else { char tmp[12]; int tt = 0; while (t > 0 && tt < 11) { tmp[tt++] = (char)('0' + (t % 10)); t /= 10; } while (tt > 0) tbuf[tp++] = tmp[--tt]; }
                tbuf[tp] = 0;
                terminal_writestring(" tid=");
                terminal_writestring(tbuf);
            } else {
                terminal_writestring(" (failed)");
            }
            flush_line(); return;
        }
        if (len >= 7 && cmd[0]=='p'&&cmd[1]=='t'&&cmd[2]=='y'&&cmd[3]=='r'&&cmd[4]=='u'&&cmd[5]=='n'&&cmd[6]==' ') {
            extern char user_argtest_start[], user_argtest_end[];
            extern char user_ptytest_start[], user_ptytest_end[];
            extern char user_sh_start[], user_sh_end[];
            const char* arg = cmd + 7;
            size_t alen = len - 7;
            char* start = 0;
            char* end = 0;
            const char* name = 0;
            if (alen >= 7 && arg[0]=='a'&&arg[1]=='r'&&arg[2]=='g'&&arg[3]=='t'&&arg[4]=='e'&&arg[5]=='s'&&arg[6]=='t') {
                start = user_argtest_start; end = user_argtest_end; name = "argtest";
            } else if (alen >= 7 && arg[0]=='p'&&arg[1]=='t'&&arg[2]=='y'&&arg[3]=='t'&&arg[4]=='e'&&arg[5]=='s'&&arg[6]=='t') {
                start = user_ptytest_start; end = user_ptytest_end; name = "ptytest";
            } else if (alen >= 2 && arg[0]=='s'&&arg[1]=='h') {
                start = user_sh_start; end = user_sh_end; name = "sh";
            }
            if (!start) {
                terminal_writestring("\nUsage: ptyrun argtest|ptytest|sh");
                flush_line(); return;
            }
            int pidx = pty_create();
            if (pidx < 0) { terminal_writestring("\npty: no free pty"); flush_line(); return; }
            pty_ref(pidx, 1); /* мастер держит шелл */
            int ctid = task_spawn_user((const uint8_t*)start, (size_t)(end - start), name);
            if (ctid < 0) {
                pty_unref(pidx, 1);
                terminal_writestring("\npty: spawn failed");
                flush_line(); return;
            }
            task_attach_pty_slave(ctid, pidx);
            terminal_writestring("\n[pty] started; Ctrl+C to interrupt");
            while (task_alive(ctid)) {
                int progressed = 0;
                for (int kdrain = 0; kdrain < 8; kdrain++) {
                    char c = poll_key();
                    if (!c) break;
                    if (c == 0x03) {
                        pty_master_write(pidx, "\x03", 1);
                        progressed = 1;
                        break;
                    }
                    if (c == '\r') c = '\n';
                    pty_master_write(pidx, &c, 1);
                    progressed = 1;
                }
                char ob[256];
                int r = pty_master_read_nb(pidx, ob, sizeof(ob));
                if (r > 0) {
                    for (int i = 0; i < r; i++) terminal_putchar(ob[i]);
                    progressed = 1;
                }
                if (pty_take_signal(pidx)) task_kill(ctid);
                if (!progressed) task_sleep_ms(10);
            }
            for (;;) {
                char ob[256];
                int r = pty_master_read(pidx, ob, sizeof(ob));
                if (r <= 0) break;
                for (int i = 0; i < r; i++) terminal_putchar(ob[i]);
            }
            pty_unref(pidx, 1);
            terminal_writestring("\n[pty] program exited");
            flush_line(); return;
        }
        if (len==3 && cmd[0]=='i'&&cmd[1]=='r'&&cmd[2]=='q') {
            terminal_writestring("\nIRQ keyboard hits: ");
            uint32_t n = keyboard_irq_count();
            char buf[12]; int p=0;
            if (n==0) buf[p++]='0';
            else {
                char tmp[12]; int t=0;
                while(n>0 && t<11){ tmp[t++]= '0'+(n%10); n/=10; }
                while(t>0) buf[p++]=tmp[--t];
            }
            buf[p]=0;
            terminal_writestring(buf);
            flush_line(); return;
        }
        if (len==6 && cmd[0]=='r'&&cmd[1]=='e'&&cmd[2]=='b'&&cmd[3]=='o'&&cmd[4]=='o'&&cmd[5]=='t') {
            reboot(); return;
        }
        if (len==8 && cmd[0]=='s'&&cmd[1]=='h'&&cmd[2]=='u'&&cmd[3]=='t'&&cmd[4]=='d'&&cmd[5]=='o'&&cmd[6]=='w'&&cmd[7]=='n') {
            shutdown(); return;
        }
        if (len==8 && cmd[0]=='p'&&cmd[1]=='o'&&cmd[2]=='w'&&cmd[3]=='e'&&cmd[4]=='r'&&cmd[5]=='o'&&cmd[6]=='f'&&cmd[7]=='f') {
            shutdown(); return;
        }
        if (len==4 && cmd[0]=='a'&&cmd[1]=='c'&&cmd[2]=='p'&&cmd[3]=='i') {
            terminal_writestring("\nACPI: ");
            if (!acpi_available()) {
                terminal_writestring("not available");
            } else {
                terminal_writestring("available");
            }
            terminal_writestring("\n  Power off (S5): ");
            if (acpi_pm1_supported()) {
                terminal_writestring("PM1a_CNT_BLK=0x");
                shell_write_u32(acpi_pm1a_cnt_blk());
                terminal_writestring(" SLP_TYPa=");
                shell_write_u32(acpi_s5_slp_typa());
            } else {
                terminal_writestring("no");
            }
            terminal_writestring("\n  Reset register: ");
            if (acpi_reset_supported()) {
                terminal_writestring(acpi_reset_is_memory() ? "mem 0x" : "io 0x");
                shell_write_u32(acpi_reset_address());
                terminal_writestring(" value=");
                shell_write_u32(acpi_reset_value());
            } else {
                terminal_writestring("no");
            }
            flush_line(); return;
        }
        const char pref_res[]="resolution ";
        if (len >= 12) {
            bool ok=true; for(int i=0;i<11;i++) if(cmd[i]!=pref_res[i]) {ok=false; break;}
            if (ok) {
                size_t num_start = 11;
                uint32_t width = 0;
                uint32_t height = 0;
                size_t i = num_start;
                // Парсим ширину
                while (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                    width = width * 10 + (cmd[i] - '0');
                    i++;
                }
                // Ищем 'x' или '/'
                if (i < len && (cmd[i] == 'x' || cmd[i] == '/')) {
                    i++; // Пропускаем разделитель
                    // Парсим высоту
                    while (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                        height = height * 10 + (cmd[i] - '0');
                        i++;
                    }
                } else if (width > 0) {
                    // Если только одно число - это высота, ширина остается 80
                    height = width;
                    width = 80;
                }
                
                // VGA контроллер поддерживает только ширину 80 символов
                if (width != 80) {
                    terminal_writestring("\nWarning: VGA supports only 80 columns width.");
                    terminal_writestring("\nWidth will be set to 80.");
                    width = 80;
                }
                
                if (height >= 25 && height <= 60) {
                    terminal_writestring("\nSetting resolution to 80x");
                    char buf[4]; int p=0;
                    // Высота
                    uint32_t nh = height;
                    if (nh == 0) buf[p++]='0';
                    else {
                        char tmp[12]; int t=0;
                        while (nh > 0 && t < 11) { tmp[t++] = '0' + (nh % 10); nh /= 10; }
                        while (t > 0) buf[p++] = tmp[--t];
                    }
                    buf[p]=0;
                    terminal_writestring(buf);
                    terminal_writestring("...");
                    terminal_set_mode(width, height);
                    terminal_set_cursor(terminal_content_origin(), 0);
                    terminal_writestring("\n[OK ] Resolution set to 80x");
                    terminal_writestring(buf);
                    flush_line();
                    return;
                } else {
                    terminal_writestring("\nInvalid resolution. Use: resolution <HEIGHT> or resolution 80x<HEIGHT>");
                    terminal_writestring("\nWidth: fixed at 80 (VGA limitation)");
                    terminal_writestring("\nHeight: 25-60");
                    terminal_writestring("\nExample: resolution 50 or resolution 80x60");
                    flush_line();
                    return;
                }
            }
        }
        const char pref[]="echo ";
        if (len>=5) {
            bool ok=true; for(int i=0;i<5;i++) if(cmd[i]!=pref[i]) {ok=false; break;}
            if (ok) {
                terminal_writestring("\n");
                for (size_t i=5;i<len;i++) terminal_putchar(cmd[i]);
                flush_line(); return;
            }
        }
        
        // Команда network - показать статус сети
        if (len==7 && cmd[0]=='n'&&cmd[1]=='e'&&cmd[2]=='t'&&cmd[3]=='w'&&cmd[4]=='o'&&cmd[5]=='r'&&cmd[6]=='k') {
            terminal_writestring("\n=== Network Status ===");
            uint8_t mac[6];
            nic_get_mac(mac);
            terminal_writestring("\nMAC Address: ");
            char mac_buf[32];
            int p = 0;
            for (int i = 0; i < 6; i++) {
                if (i > 0) mac_buf[p++] = ':';
                uint8_t b = mac[i];
                uint8_t high = (b >> 4) & 0xF;
                uint8_t low = b & 0xF;
                mac_buf[p++] = (high < 10) ? ('0' + high) : ('A' + high - 10);
                mac_buf[p++] = (low < 10) ? ('0' + low) : ('A' + low - 10);
            }
            mac_buf[p] = 0;
            terminal_writestring(mac_buf);
            
            // Получаем IP
            uint32_t ip = ip_get_our_ip();
            terminal_writestring("\nIP Address: ");
            if (ip != 0) {
                shell_write_ip(ip);
            } else {
                terminal_writestring("Not set");
            }

            uint32_t mask = ip_get_subnet_mask();
            terminal_writestring("\nSubnet Mask: ");
            if (mask != 0) {
                shell_write_ip(mask);
            } else {
                terminal_writestring("Not set");
            }

            // Шлюз
            uint32_t gateway = ip_get_gateway();
            terminal_writestring("\nGateway: ");
            if (gateway != 0) {
                shell_write_ip(gateway);
            } else {
                terminal_writestring("Not set");
            }

            // DNS сервер
            uint32_t dns = dns_get_server();
            terminal_writestring("\nDNS Server: ");
            if (dns != 0) {
                shell_write_ip(dns);
            } else {
                terminal_writestring("Not set");
            }
            
            struct driver* net_drv = driver_find_by_type(DRIVER_NETWORK, 0);
            if (net_drv && net_drv->initialized) {
                terminal_writestring("\nStatus: Active");
            } else {
                terminal_writestring("\nStatus: Not initialized");
            }

            struct netif* nif = netif_default();
            if (nif) {
                terminal_writestring("\nInterface: ");
                terminal_writestring(nif->name);
                terminal_writestring(" hw=");
                if (nif->hw_type == NETIF_HW_VIRTIO) terminal_writestring("virtio");
                else if (nif->hw_type == NETIF_HW_PCNET) terminal_writestring("pcnet");
                else if (nif->hw_type == NETIF_HW_RTL8139) terminal_writestring("rtl8139");
                else terminal_writestring("?");
                terminal_writestring("\nStats RX/TX/drop/irq: ");
                shell_write_u32(nif->stats.rx_packets);
                terminal_writestring("/");
                shell_write_u32(nif->stats.tx_packets);
                terminal_writestring("/");
                shell_write_u32(nif->stats.rx_dropped);
                terminal_writestring("/");
                shell_write_u32(nif->stats.irq_count);
            }
            flush_line(); return;
        }

        // Команда ifconfig - показ интерфейсов (Linux-like, per-interface)
        if (len >= 8 && cmd_name_len == 8 &&
            cmd_name[0]=='i'&&cmd_name[1]=='f'&&cmd_name[2]=='c'&&cmd_name[3]=='o'&&
            cmd_name[4]=='n'&&cmd_name[5]=='f'&&cmd_name[6]=='i'&&cmd_name[7]=='g') {
            int n = netif_count();
            if (n == 0) {
                terminal_writestring("\nNo network interfaces");
                flush_line(); return;
            }
            uint32_t g_ip = ip_get_our_ip();
            uint32_t g_mask = ip_get_subnet_mask();
            uint32_t g_gw = ip_get_gateway();

            for (int idx = 0; idx < n; idx++) {
                struct netif* nif = netif_get(idx);
                if (!nif) continue;
                uint32_t ip = nif->ip ? nif->ip : g_ip;
                uint32_t mask = nif->netmask ? nif->netmask : g_mask;
                uint32_t gw = nif->gateway ? nif->gateway : g_gw;

                terminal_writestring("\n");
                terminal_writestring(nif->name);
                terminal_writestring(": flags=");
                terminal_writestring(nif->up ? "UP" : "DOWN");
                terminal_writestring(",BROADCAST,RUNNING,MULTICAST");
                terminal_writestring("  mtu ");
                shell_write_u32(nif->mtu);
                terminal_writestring("  hwtype ");
                switch (nif->hw_type) {
                    case NETIF_HW_VIRTIO: terminal_writestring("virtio"); break;
                    case NETIF_HW_PCNET:  terminal_writestring("pcnet");  break;
                    case NETIF_HW_RTL8139: terminal_writestring("rtl8139"); break;
                    default: terminal_writestring("unknown"); break;
                }

                terminal_writestring("\n        inet ");
                if (ip) shell_write_ip(ip); else terminal_writestring("unset");
                terminal_writestring("  netmask ");
                if (mask) shell_write_ip(mask); else terminal_writestring("unset");
                terminal_writestring("\n        inet6 ::1/128  scope host");
                terminal_writestring("\n        ether ");
                for (int i = 0; i < 6; i++) {
                    if (i > 0) terminal_putchar(':');
                    uint8_t b = nif->mac[i];
                    char hex[3];
                    uint8_t hi = (b >> 4) & 0xF, lo = b & 0xF;
                    hex[0] = (char)(hi < 10 ? '0' + hi : 'A' + hi - 10);
                    hex[1] = (char)(lo < 10 ? '0' + lo : 'A' + lo - 10);
                    hex[2] = 0;
                    terminal_writestring(hex);
                }
                if (gw) {
                    terminal_writestring("  gateway ");
                    shell_write_ip(gw);
                }
                terminal_writestring("\n        RX packets ");
                shell_write_u32(nif->stats.rx_packets);
                terminal_writestring("  bytes ");
                shell_write_u32(nif->stats.rx_bytes);
                terminal_writestring("  dropped ");
                shell_write_u32(nif->stats.rx_dropped);
                terminal_writestring("\n        TX packets ");
                shell_write_u32(nif->stats.tx_packets);
                terminal_writestring("  bytes ");
                shell_write_u32(nif->stats.tx_bytes);
                terminal_writestring("  errors ");
                shell_write_u32(nif->stats.tx_errors);
                terminal_writestring("  irq ");
                shell_write_u32(nif->stats.irq_count);
            }
            terminal_writestring("\n");
            flush_line(); return;
        }

        // Команда log - уровень serial-лога (COM1 -> logs/qemu-serial.log на хосте)
        if (len == 3 && cmd[0] == 'l' && cmd[1] == 'o' && cmd[2] == 'g') {
            terminal_writestring("\nSerial log level: ");
            int lv = log_get_level();
            if (lv == LOG_OFF) terminal_writestring("off");
            else if (lv == LOG_ERR) terminal_writestring("err (errors)");
            else if (lv == LOG_INFO) terminal_writestring("info");
            else if (lv == LOG_DBG) terminal_writestring("debug (default)");
            else terminal_writestring("?");
            terminal_writestring("\nHost file: logs\\qemu-serial.log (use run-qemu.bat)");
            terminal_writestring("\nTerminal mirror: ");
            terminal_writestring(log_mirror_get() ? "on" : "off");
            terminal_writestring("\nUsage: log [off|err|info|debug|test|mirror on|mirror off]");
            flush_line(); return;
        }
        const char pref_log[] = "log ";
        if (len >= 4) {
            bool ok = true;
            for (int i = 0; i < 4; i++) {
                if (cmd[i] != pref_log[i]) { ok = false; break; }
            }
            if (ok) {
                size_t pos = 4;
                while (pos < len && cmd[pos] == ' ') pos++;
                if (pos >= len) {
                    terminal_writestring("\nUsage: log [off|err|info|debug|test|mirror on|mirror off]");
                    flush_line(); return;
                }
                if (pos + 6 <= len && cmd[pos] == 'm' && cmd[pos + 1] == 'i' && cmd[pos + 2] == 'r' &&
                    cmd[pos + 3] == 'r' && cmd[pos + 4] == 'o' && cmd[pos + 5] == 'r') {
                    pos += 6;
                    while (pos < len && cmd[pos] == ' ') pos++;
                    if (pos + 2 <= len && cmd[pos] == 'o' && cmd[pos + 1] == 'n') {
                        log_mirror_set(true);
                        terminal_writestring("\nTerminal mirror: on");
                    } else if (pos + 3 <= len && cmd[pos] == 'o' && cmd[pos + 1] == 'f' && cmd[pos + 2] == 'f') {
                        log_mirror_set(false);
                        terminal_writestring("\nTerminal mirror: off");
                    } else {
                        terminal_writestring("\nUsage: log mirror on|off");
                    }
                    flush_line(); return;
                }
                if (pos + 3 <= len && cmd[pos] == 'o' && cmd[pos + 1] == 'f' && cmd[pos + 2] == 'f') {
                    log_set_level(LOG_OFF);
                    terminal_writestring("\nLog: off");
                } else if (pos + 3 <= len && cmd[pos] == 'e' && cmd[pos + 1] == 'r' && cmd[pos + 2] == 'r') {
                    log_set_level(LOG_ERR);
                    terminal_writestring("\nLog: err (errors only)");
                } else if (pos + 4 <= len && cmd[pos] == 'i' && cmd[pos + 1] == 'n' && cmd[pos + 2] == 'f' && cmd[pos + 3] == 'o') {
                    log_set_level(LOG_INFO);
                    terminal_writestring("\nLog: info");
                } else if (pos + 5 <= len && cmd[pos] == 'd' && cmd[pos + 1] == 'e' && cmd[pos + 2] == 'b' &&
                           cmd[pos + 3] == 'u' && cmd[pos + 4] == 'g') {
                    log_set_level(LOG_DBG);
                    terminal_writestring("\nLog: debug");
                } else if (pos + 4 <= len && cmd[pos] == 't' && cmd[pos + 1] == 'e' && cmd[pos + 2] == 's' && cmd[pos + 3] == 't') {
                    log_msg(LOG_INFO, "shell", "log test line");
                    log_u32(LOG_DBG, "shell", "log test values", 0xDEADBEEFu, 1, 2);
                    terminal_writestring("\nTest lines written to serial log");
                } else {
                    terminal_writestring("\nUnknown: log off|err|info|debug|test");
                }
                flush_line(); return;
            }
        }
        
        // Команда network static - ручная настройка сети
        const char pref_net_static[] = "network static ";
        const char pref_net_save[] = "network save";
        const char pref_net_reload[] = "network reload";

        if (len == 12) {
            bool ok = true;
            for (int i = 0; i < 12; i++) if (cmd[i] != pref_net_save[i]) { ok = false; break; }
            if (ok) {
                if (network_config_save() == 0) {
                    terminal_writestring("\nSaved to ");
                    terminal_writestring(NETWORK_CONFIG_PATH);
                    terminal_writestring(" and ");
                    terminal_writestring(NETWORK_RESOLV_PATH);
                } else {
                    terminal_writestring("\nSave failed (no IP or no disk)");
                }
                flush_line(); return;
            }
        }

        if (len == 14) {
            bool ok = true;
            for (int i = 0; i < 14; i++) if (cmd[i] != pref_net_reload[i]) { ok = false; break; }
            if (ok) {
                if (network_config_reload() == 0) {
                    terminal_writestring("\nNetwork reloaded. IP: ");
                    shell_write_ip(ip_get_our_ip());
                } else {
                    terminal_writestring("\nReload failed (missing or invalid config)");
                }
                flush_line(); return;
            }
        }

        if (len >= 15) {
            bool ok = true;
            for (int i = 0; i < 15; i++) {
                if (cmd[i] != pref_net_static[i]) { ok = false; break; }
            }
            if (ok) {
                size_t pos = 15;
                uint32_t ip = 0, gateway = 0, dns = 0, mask = 0;
                bool valid = ip_parse_address_token(cmd, len, &pos, &ip) == 0;

                if (valid) {
                    uint32_t tmp = 0;
                    if (ip_parse_address_token(cmd, len, &pos, &tmp) == 0) {
                        gateway = tmp;
                        if (ip_parse_address_token(cmd, len, &pos, &tmp) == 0) {
                            dns = tmp;
                            if (ip_parse_address_token(cmd, len, &pos, &tmp) == 0) {
                                mask = tmp;
                            }
                        }
                    }
                }

                if (valid && ip != 0) {
                    network_apply_config(ip, mask, gateway, dns);
                    network_config_save();
                    terminal_writestring("\nNetwork configuration set (saved to ");
                    terminal_writestring(NETWORK_CONFIG_PATH);
                    terminal_writestring(")");
                } else {
                    terminal_writestring("\nInvalid format");
                    terminal_writestring("\nUsage: network static <ip> [gateway] [dns] [mask]");
                    terminal_writestring("\nExample: network static 10.0.2.15 10.0.2.2 10.0.2.3 255.255.255.0");
                }
                flush_line(); return;
            }
        }
        
        // Команда dhcp - получить IP через DHCP
        if (len == 4 && cmd[0] == 'd' && cmd[1] == 'h' && cmd[2] == 'c' && cmd[3] == 'p') {
            terminal_writestring("\n[DHCP] Acquiring IP address...");
            if (dhcp_acquire() == 0) {
                network_config_save();
                terminal_writestring("\n[DHCP] IP address acquired successfully");
                terminal_writestring("\nIP: ");
                shell_write_ip(ip_get_our_ip());
            } else {
                terminal_writestring("\n[DHCP] Failed to acquire IP address");
            }
            flush_line(); return;
        }
        
        // Команда hostname [name] - показать/сменить имя устройства (DHCP option 12)
        if (len >= 8 && cmd[0]=='h'&&cmd[1]=='o'&&cmd[2]=='s'&&cmd[3]=='t'&&cmd[4]=='n'&&cmd[5]=='a'&&cmd[6]=='m'&&cmd[7]=='e') {
            if (len == 8) {
                // hostname — показать текущий
                terminal_writestring("\nHostname: ");
                terminal_writestring(dhcp_get_hostname());
            } else if (cmd[8] == ' ' && len > 9) {
                // hostname <name> — установить
                char new_name[32];
                size_t nlen = len - 9;
                if (nlen >= sizeof(new_name)) nlen = sizeof(new_name) - 1;
                for (size_t i = 0; i < nlen; i++) new_name[i] = cmd[9 + i];
                new_name[nlen] = 0;
                dhcp_set_hostname(new_name);
                terminal_writestring("\nHostname set to: ");
                terminal_writestring(new_name);
                terminal_writestring("\nDHCP release + renew...");
                dhcp_release();
                if (dhcp_acquire() == 0) {
                    network_config_save();
                    terminal_writestring(" OK (IP: ");
                    shell_write_ip(ip_get_our_ip());
                    terminal_writestring(")");
                } else {
                    terminal_writestring(" failed");
                }
            } else {
                terminal_writestring("\nUsage: hostname [name]");
            }
            flush_line(); return;
        }
        
        // Команда ip - установить IP адрес
        if (len == 2 && cmd[0] == 'i' && cmd[1] == 'p') {
            uint32_t ip = ip_get_our_ip();
            if (ip != 0) {
                char ip_buf[20];
                ip_format_address(ip, ip_buf, sizeof(ip_buf));
                terminal_writestring("\nIP: ");
                terminal_writestring(ip_buf);
            } else {
                terminal_writestring("\nIP: Not set (use dhcp or ip <address>)");
            }
            flush_line(); return;
        }
        const char pref_ip[]="ip ";
        if (len>=3) {
            bool ok=true; for(int i=0;i<3;i++) if(cmd[i]!=pref_ip[i]) {ok=false; break;}
            if (ok) {
                size_t pos = 3;
                uint32_t ip = 0;
                if (ip_parse_address_token(cmd, len, &pos, &ip) == 0) {
                    struct driver* net_drv = driver_find_by_type(DRIVER_NETWORK, 0);
                    if (net_drv && net_drv->initialized && net_drv->ops.ioctl) {
                        if (net_drv->ops.ioctl(net_drv->device_data, NIC_IOCTL_SET_IP, &ip) == 0) {
                            terminal_writestring("\nIP address set successfully");
                        } else {
                            terminal_writestring("\nFailed to set IP address");
                        }
                    } else {
                        terminal_writestring("\nNetwork driver not initialized");
                    }
                } else {
                    terminal_writestring("\nInvalid IP address format");
                    terminal_writestring("\nUsage: ip <address>");
                    terminal_writestring("\nExample: ip 192.168.1.100");
                }
                flush_line(); return;
            }
        }
        
        // Команда udp - отправить UDP пакет
        const char pref_udp[]="udp ";
        if (len>=4) {
            bool ok=true; for(int i=0;i<4;i++) if(cmd[i]!=pref_udp[i]) {ok=false; break;}
            if (ok) {
                size_t pos = 4;
                uint32_t dest_ip = 0;
                if (ip_parse_address_token(cmd, len, &pos, &dest_ip) != 0) {
                    terminal_writestring("\nInvalid IP address");
                    terminal_writestring("\nUsage: udp <ip> <port> <data>");
                    flush_line(); return;
                }

                uint16_t dest_port = 0;
                while (pos < len && cmd[pos] == ' ') pos++;
                while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                    dest_port = (uint16_t)(dest_port * 10 + (cmd[pos] - '0'));
                    pos++;
                }

                if (dest_port == 0) {
                    terminal_writestring("\nInvalid port");
                    terminal_writestring("\nUsage: udp <ip> <port> <data>");
                    flush_line(); return;
                }
                
                while (pos < len && cmd[pos] == ' ') pos++;

                if (pos >= len) {
                    terminal_writestring("\nNo data specified");
                    terminal_writestring("\nUsage: udp <ip> <port> <data>");
                    flush_line(); return;
                }
                
                const char* data = cmd + pos;
                size_t data_len = len - pos;
                
                // Отправляем через syscall
                struct driver* net_drv = driver_find_by_type(DRIVER_NETWORK, 0);
                if (net_drv && net_drv->initialized && net_drv->ops.ioctl) {
                    struct {
                        uint32_t dest_ip;
                        uint16_t src_port;
                        uint16_t dest_port;
                        void* data;
                        size_t len;
                    } udp_args;
                    udp_args.dest_ip = dest_ip;
                    udp_args.src_port = 12345; // Произвольный порт
                    udp_args.dest_port = dest_port;
                    udp_args.data = (void*)data;
                    udp_args.len = data_len;
                    
                    if (net_drv->ops.ioctl(net_drv->device_data, NIC_IOCTL_UDP_SEND, &udp_args) == 0) {
                        terminal_writestring("\nUDP packet sent");
                    } else {
                        terminal_writestring("\nFailed to send UDP packet");
                        terminal_writestring("\n(Check IP address and ARP table)");
                    }
                } else {
                    terminal_writestring("\nNetwork driver not initialized");
                }
                flush_line(); return;
            }
        }
        
        // Команда tcp listen - echo-сервер
        const char pref_tcp_listen[] = "tcp listen ";
        if (len >= 11) {
            bool ok = true;
            for (int i = 0; i < 11; i++) {
                if (cmd[i] != pref_tcp_listen[i]) { ok = false; break; }
            }
            if (ok) {
                size_t pos = 11;
                uint16_t port = 0;
                if (!shell_parse_u16_token(cmd, len, &pos, &port)) {
                    terminal_writestring("\nInvalid port");
                    terminal_writestring("\nUsage: tcp listen <port>");
                    flush_line(); return;
                }

                struct tcp_connection* listen_conn = tcp_listen(port);
                if (!listen_conn) {
                    terminal_writestring("\nFailed to listen (port busy or no IP)");
                    flush_line(); return;
                }
                net_ports_register(NET_PROTO_TCP, NETPORT_LISTEN,
                                   ip_get_our_ip(), port, 0, 0,
                                   -1, -1, "tcplisten");

                terminal_writestring("\nTCP echo on port ");
                shell_write_port(port);
                terminal_writestring(" (one connection, 30s timeout)");

                struct tcp_connection* accepted = tcp_accept(listen_conn, 30000);
                if (accepted) {
                    uint8_t buf[512];
                    int received = 0;
                    for (int w = 0; w < 200 && received == 0; w++) {
                        nic_process_packets();
                        tcp_process_timers();
                        received = tcp_recv_data(accepted, buf, sizeof(buf));
                        for (volatile int d = 0; d < 50000; d++);
                    }
                    if (received > 0) {
                        tcp_send_data(accepted, buf, (size_t)received);
                        terminal_writestring("\nEchoed ");
                        shell_write_port((uint16_t)received);
                        terminal_writestring(" bytes");
                    } else {
                        terminal_writestring("\nNo data received");
                    }
                    tcp_close(accepted);
                } else {
                    terminal_writestring("\nAccept timeout");
                }

                tcp_connection_close(listen_conn);
                net_ports_release_listen(NET_PROTO_TCP, port);
                flush_line(); return;
            }
        }

        // Команда tcp - отправить TCP пакет
        const char pref_tcp[]="tcp ";
        if (len>=4) {
            bool ok=true; for(int i=0;i<4;i++) if(cmd[i]!=pref_tcp[i]) {ok=false; break;}
            if (ok) {
                size_t pos = 4;
                uint32_t dest_ip = 0;
                if (ip_parse_address_token(cmd, len, &pos, &dest_ip) != 0) {
                    terminal_writestring("\nInvalid IP address");
                    terminal_writestring("\nUsage: tcp <ip> <port> <data>");
                    flush_line(); return;
                }

                uint16_t dest_port = 0;
                while (pos < len && cmd[pos] == ' ') pos++;
                while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                    dest_port = (uint16_t)(dest_port * 10 + (cmd[pos] - '0'));
                    pos++;
                }

                if (dest_port == 0) {
                    terminal_writestring("\nInvalid port");
                    terminal_writestring("\nUsage: tcp <ip> <port> <data>");
                    flush_line(); return;
                }

                while (pos < len && cmd[pos] == ' ') pos++;

                if (pos >= len) {
                    terminal_writestring("\nNo data specified");
                    terminal_writestring("\nUsage: tcp <ip> <port> <data>");
                    flush_line(); return;
                }

                const char* data = cmd + pos;
                size_t data_len = len - pos;

                struct tcp_connection* conn = tcp_connect(dest_ip, dest_port);
                if (conn) {
                    if (tcp_connect_wait(conn, 5000) == 0) {
                        if (tcp_send_data(conn, data, data_len) >= 0) {
                            terminal_writestring("\nTCP packet sent");
                        } else {
                            terminal_writestring("\nFailed to send TCP packet");
                        }
                    } else {
                        terminal_writestring("\nFailed to connect (timeout)");
                    }
                    tcp_close(conn);
                } else {
                    terminal_writestring("\nFailed to connect");
                }
                flush_line(); return;
            }
        }

        // Команда udplisten - UDP echo-сервер
        const char pref_udplisten[] = "udplisten ";
        if (len >= 10) {
            bool ok = true;
            for (int i = 0; i < 10; i++) {
                if (cmd[i] != pref_udplisten[i]) { ok = false; break; }
            }
            if (ok) {
                size_t pos = 10;
                uint16_t port = 0;
                if (!shell_parse_u16_token(cmd, len, &pos, &port)) {
                    terminal_writestring("\nInvalid port");
                    terminal_writestring("\nUsage: udplisten <port>");
                    flush_line(); return;
                }

                if (udp_listen_port(port) != 0) {
                    terminal_writestring("\nFailed to listen (too many ports)");
                    flush_line(); return;
                }

                terminal_writestring("\nUDP echo on port ");
                shell_write_port(port);
                terminal_writestring(" (waiting 30s)");

                for (int t = 0; t < 3000; t++) {
                    nic_process_packets();
                    tcp_process_timers();
                    for (volatile int d = 0; d < 50000; d++);
                }

                udp_unlisten_port(port);
                terminal_writestring("\nDone");
                flush_line(); return;
            }
        }
        
        // Команда ping
        const char pref_ping[]="ping ";
        if (len>=5) {
            bool ok=true; for(int i=0;i<5;i++) if(cmd[i]!=pref_ping[i]) {ok=false; break;}
            if (ok) {
                size_t i = 5;
                while (i < len && cmd[i] == ' ') i++;

                size_t ip_start = i;
                while (i < len && cmd[i] != ' ') i++;
                size_t ip_len = i - ip_start;

                uint32_t dest_ip = 0;
                const char* host_str = cmd + ip_start;
                if (ip_len == 0 || net_resolve_host(host_str, ip_len, &dest_ip) != 0) {
                    terminal_writestring("\nInvalid host or DNS resolution failed");
                    terminal_writestring("\nUsage: ping <ip|hostname> [count]");
                    flush_line(); return;
                }

                while (i < len && cmd[i] == ' ') i++;

                int count = 4;
                if (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                    count = 0;
                    while (i < len && cmd[i] >= '0' && cmd[i] <= '9') {
                        count = count * 10 + (cmd[i] - '0');
                        i++;
                    }
                    if (count < 1) count = 1;
                    if (count > 10) count = 10;
                }

                if (ip_get_our_ip() == 0) {
                    terminal_writestring("\nNo IP address configured (run dhcp first)");
                    flush_line(); return;
                }

                terminal_writestring("\nPinging ");
                for (size_t j = ip_start; j < ip_start + ip_len; j++) {
                    terminal_putchar(cmd[j]);
                }
                terminal_writestring(" (");
                char ip_buf[20];
                ip_format_address(dest_ip, ip_buf, sizeof(ip_buf));
                terminal_writestring(ip_buf);
                terminal_writestring(")...");

                int received = icmp_ping(dest_ip, count);
                if (received < 0) {
                    terminal_writestring("\nPing failed (ARP or send error)");
                } else {
                    terminal_writestring("\n");
                    char num[8];
                    int np = 0;
                    int val = received;
                    if (val == 0) num[np++] = '0';
                    else {
                        char tmp[8];
                        int t = 0;
                        while (val > 0) { tmp[t++] = '0' + (val % 10); val /= 10; }
                        while (t > 0) num[np++] = tmp[--t];
                    }
                    num[np] = 0;
                    terminal_writestring(num);
                    terminal_writestring(" packets received, ");
                    np = 0;
                    val = count - received;
                    if (val == 0) num[np++] = '0';
                    else {
                        char tmp[8];
                        int t = 0;
                        while (val > 0) { tmp[t++] = '0' + (val % 10); val /= 10; }
                        while (t > 0) num[np++] = tmp[--t];
                    }
                    num[np] = 0;
                    terminal_writestring(num);
                    terminal_writestring(" lost");
                }
                flush_line(); return;
            }
        }

        // autotest fs — CI: create/write/read/list/delete + fsck
        if (len >= 11 && cmd[0]=='a'&&cmd[1]=='u'&&cmd[2]=='t'&&cmd[3]=='o'&&
            cmd[4]=='t'&&cmd[5]=='e'&&cmd[6]=='s'&&cmd[7]=='t'&&cmd[8]==' '&&
            cmd[9]=='f'&&cmd[10]=='s' && (len == 11 || cmd[11] == ' ' || cmd[11] == 0)) {
            if (fs_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] fs failed");
                log_msg(LOG_ERR, "autotest", "fs_failed");
            }
            flush_line(); return;
        }

        // Команда traceroute - путь до хоста через ICMP с растущим TTL
        const char pref_traceroute[]="traceroute ";
        if (len>=12) {
            bool ok=true; for(int i=0;i<11;i++) if(cmd[i]!=pref_traceroute[i]) {ok=false; break;}
            if (ok) {
                size_t i = 11;
                while (i < len && cmd[i] == ' ') i++;
                const char* host_str = cmd + i;
                size_t host_len = 0;
                while (i + host_len < len && cmd[i + host_len] != ' ') host_len++;

                if (ip_get_our_ip() == 0) {
                    terminal_writestring("\nNo IP address configured (run dhcp first)");
                    flush_line(); return;
                }

                uint32_t dest_ip = 0;
                if (host_len == 0 || net_resolve_host(host_str, host_len, &dest_ip) != 0) {
                    terminal_writestring("\nInvalid host or DNS resolution failed");
                    terminal_writestring("\nUsage: traceroute <ip|hostname>");
                    flush_line(); return;
                }

                char ip_buf[20];
                terminal_writestring("\ntraceroute to ");
                for (size_t j = 0; j < host_len; j++) terminal_putchar(host_str[j]);
                terminal_writestring(" (");
                ip_format_address(dest_ip, ip_buf, sizeof(ip_buf));
                terminal_writestring(ip_buf);
                terminal_writestring("), max 30 hops");

                for (int ttl = 1; ttl <= 30; ttl++) {
                    terminal_writestring("\n ");
                    char num[8]; int np = 0;
                    int v = ttl;
                    if (v < 10) num[np++] = ' ';
                    if (v == 0) num[np++] = '0';
                    else {
                        char tmp[8]; int t = 0;
                        while (v > 0) { tmp[t++] = '0' + (v % 10); v /= 10; }
                        while (t > 0) num[np++] = tmp[--t];
                    }
                    num[np] = 0;
                    terminal_writestring(num);
                    terminal_writestring("  ");

                    int kind = 0;
                    uint32_t from = 0;
                    uint32_t rtt = 0;
                    int rc = icmp_probe_to(dest_ip, ttl, 1000, &kind, &from, &rtt);
                    if (rc < 0) {
                        if (rc == -1) {
                            terminal_writestring("(send error)");
                            flush_line(); return;
                        }
                        terminal_writestring("*");
                        continue;
                    }

                    ip_format_address(from, ip_buf, sizeof(ip_buf));
                    terminal_writestring(ip_buf);
                    terminal_writestring("  ");
                    np = 0;
                    v = (int)rtt;
                    if (v == 0) num[np++] = '0';
                    else {
                        char tmp[8]; int t = 0;
                        while (v > 0) { tmp[t++] = '0' + (v % 10); v /= 10; }
                        while (t > 0) num[np++] = tmp[--t];
                    }
                    num[np] = 0;
                    terminal_writestring(num);
                    terminal_writestring("ms");

                    if (kind == ICMP_TYPE_ECHO_REPLY) {
                        terminal_writestring("  [destination reached]");
                        break;
                    }
                    if (kind == ICMP_TYPE_DEST_UNREACH) {
                        terminal_writestring("  [unreachable]");
                        break;
                    }
                }
                flush_line(); return;
            }
        }

        // Команда tcpdump - захват фреймов (in/out) с фильтрами
        // tcpdump [count] [tcp|udp|icmp|arp|ip] [port N] [host IP]
        const char pref_tcpdump[]="tcpdump";
        size_t tl = 0;
        while (pref_tcpdump[tl]) tl++;
        if (len >= tl && cmd_name_len >= tl &&
            (cmd_name_len == tl || cmd_name[tl] == ' ')) {
            bool ok = true;
            for (int i = 0; i < (int)tl; i++) if (cmd[i] != pref_tcpdump[i]) { ok = false; break; }
            if (ok) {
                int count = 20;
                tcpdump_filter_etype = 0;
                tcpdump_filter_proto = 0;
                tcpdump_filter_ipv4 = false;
                tcpdump_filter_port = 0;
                tcpdump_filter_ip = 0;

                bool bad = false;
                size_t di = tl;
                size_t pos = tl;
                while (di < len && cmd[di] == ' ') di++;
                if (di < len && cmd[di] >= '0' && cmd[di] <= '9') {
                    int c = 0;
                    while (di < len && cmd[di] >= '0' && cmd[di] <= '9') {
                        c = c * 10 + (cmd[di] - '0');
                        di++;
                    }
                    if (c >= 1 && c <= 200) count = c;
                    else bad = true;
                }
                pos = di;
                while (pos < len) {
                    while (pos < len && cmd[pos] == ' ') pos++;
                    if (pos >= len) break;
                    const char* tok = cmd + pos;
                    size_t tok_len = 0;
                    while (pos + tok_len < len && cmd[pos + tok_len] != ' ') tok_len++;
                    if (tok_len == 3 && tok[0]=='t'&&tok[1]=='c'&&tok[2]=='p') tcpdump_filter_proto = IP_PROTOCOL_TCP;
                    else if (tok_len == 3 && tok[0]=='u'&&tok[1]=='d'&&tok[2]=='p') tcpdump_filter_proto = IP_PROTOCOL_UDP;
                    else if (tok_len == 4 && tok[0]=='i'&&tok[1]=='c'&&tok[2]=='m'&&tok[3]=='p') tcpdump_filter_proto = IP_PROTOCOL_ICMP;
                    else if (tok_len == 2 && tok[0]=='i'&&tok[1]=='p') { tcpdump_filter_proto = 0; tcpdump_filter_ipv4 = true; }
                    else if (tok_len == 3 && tok[0]=='a'&&tok[1]=='r'&&tok[2]=='p') tcpdump_filter_etype = ETH_TYPE_ARP;
                    else if (tok_len == 4 && tok[0]=='p'&&tok[1]=='o'&&tok[2]=='r'&&tok[3]=='t') {
                        pos += tok_len;
                        while (pos < len && cmd[pos] == ' ') pos++;
                        size_t pstart = pos;
                        uint16_t pval = 0;
                        while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                            pval = (uint16_t)(pval * 10 + (uint16_t)(cmd[pos] - '0'));
                            pos++;
                        }
                        if (pos == pstart) { bad = true; break; }
                        tcpdump_filter_port = pval;
                        continue;
                    } else if (tok_len == 4 && tok[0]=='h'&&tok[1]=='o'&&tok[2]=='s'&&tok[3]=='t') {
                        pos += tok_len;
                        while (pos < len && cmd[pos] == ' ') pos++;
                        size_t hstart = pos;
                        size_t hlen = 0;
                        while (pos + hlen < len && cmd[pos + hlen] != ' ') hlen++;
                        uint32_t hip = 0;
                        if (hlen == 0 || ip_parse_address(cmd + hstart, hlen, &hip) != 0) { bad = true; break; }
                        tcpdump_filter_ip = hip;
                    } else {
                        terminal_writestring("\nUnknown filter: ");
                        for (size_t j = 0; j < tok_len; j++) terminal_putchar(cmd[pos + j]);
                        bad = true;
                        break;
                    }
                    pos += tok_len;
                }

                if (bad) {
                    terminal_writestring("\nUsage: tcpdump [count] [tcp|udp|icmp|arp|ip] [port N] [host IP]");
                    flush_line(); return;
                }

                terminal_writestring("\nCapturing up to ");
                shell_write_u32((uint32_t)count);
                terminal_writestring((tcpdump_filter_proto || tcpdump_filter_etype) ?
                                     " packets (filtered). Press Ctrl+C to stop." :
                                     " packets. Press Ctrl+C to stop.");

                tcpdump_remaining = count;
                net_capture_set(tcpdump_capture);

                uint32_t t0 = timer_ms();
                while (tcpdump_remaining > 0) {
                    nic_process_packets();
                    char k = poll_key();
                    if (k == 3) { terminal_writestring("\n^C"); break; }
                    if (timer_ms() - t0 >= 30000) break;
                    sched_yield();
                }

                net_capture_set(0);
                tcpdump_remaining = 0;
                tcpdump_filter_proto = 0;
                tcpdump_filter_etype = 0;
                tcpdump_filter_ipv4 = false;
                tcpdump_filter_port = 0;
                tcpdump_filter_ip = 0;
                terminal_writestring("\nCapture stopped");
                flush_line(); return;
            }
        }

        // autotest vga — console + framebuffer smoke
        if (len >= 12 && cmd[0]=='a'&&cmd[1]=='u'&&cmd[2]=='t'&&cmd[3]=='o'&&
            cmd[4]=='t'&&cmd[5]=='e'&&cmd[6]=='s'&&cmd[7]=='t'&&cmd[8]==' '&&
            cmd[9]=='v'&&cmd[10]=='g'&&cmd[11]=='a' && (len == 12 || cmd[12] == ' ' || cmd[12] == 0)) {
            if (vga_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] vga failed");
                log_msg(LOG_ERR, "autotest", "vga_failed");
            }
            flush_line(); return;
        }

        // autotest keyboard — PS/2 decode / specials / burst via inject
        if (len >= 17 && cmd[0]=='a'&&cmd[1]=='u'&&cmd[2]=='t'&&cmd[3]=='o'&&
            cmd[4]=='t'&&cmd[5]=='e'&&cmd[6]=='s'&&cmd[7]=='t'&&cmd[8]==' '&&
            cmd[9]=='k'&&cmd[10]=='e'&&cmd[11]=='y'&&cmd[12]=='b'&&cmd[13]=='o'&&
            cmd[14]=='a'&&cmd[15]=='r'&&cmd[16]=='d' &&
            (len == 17 || cmd[17] == ' ' || cmd[17] == 0)) {
            if (keyboard_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] keyboard failed");
                log_msg(LOG_ERR, "autotest", "keyboard_failed");
            }
            flush_line(); return;
        }

        // autotest user — ring3 процессы, страничная изоляция, uid, user buffer
        if (len >= 13 && cmd[0]=='a'&&cmd[1]=='u'&&cmd[2]=='t'&&cmd[3]=='o'&&
            cmd[4]=='t'&&cmd[5]=='e'&&cmd[6]=='s'&&cmd[7]=='t'&&cmd[8]==' '&&
            cmd[9]=='u'&&cmd[10]=='s'&&cmd[11]=='e'&&cmd[12]=='r' &&
            (len == 13 || cmd[13] == ' ' || cmd[13] == 0)) {
            if (user_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] user failed");
                log_msg(LOG_ERR, "autotest", "user_failed");
            }
            flush_line(); return;
        }

        // autotest network [port] [max] — CI: fs, dhcp, /www, HTTP server (markers on serial)
        if (len >= 16 && cmd[0]=='a'&&cmd[1]=='u'&&cmd[2]=='t'&&cmd[3]=='o'&&
            cmd[4]=='t'&&cmd[5]=='e'&&cmd[6]=='s'&&cmd[7]=='t'&&cmd[8]==' '&&
            cmd[9]=='n'&&cmd[10]=='e'&&cmd[11]=='t'&&cmd[12]=='w'&&cmd[13]=='o'&&
            cmd[14]=='r'&&cmd[15]=='k' && (len == 16 || cmd[16] == ' ')) {
            uint16_t port = 8080;
            int max_req = 32;
            size_t pos = 16;
            if (pos < len && cmd[pos] == ' ') {
                pos++;
                uint16_t p = 0;
                if (shell_parse_u16_token(cmd, len, &pos, &p)) port = p;
                while (pos < len && cmd[pos] == ' ') pos++;
                if (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                    int m = 0;
                    while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                        m = m * 10 + (cmd[pos] - '0');
                        pos++;
                    }
                    if (m > 0 && m <= 64) max_req = m;
                }
            }
            terminal_writestring("\n[AUTOTEST] network start");
            log_msg(LOG_INFO, "autotest", "start");

            if (fs_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] fs failed");
                log_msg(LOG_ERR, "autotest", "fs_failed");
                flush_line(); return;
            }

            if (vga_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] vga failed");
                log_msg(LOG_ERR, "autotest", "vga_failed");
                flush_line(); return;
            }

            if (keyboard_autotest_run() != 0) {
                terminal_writestring("\n[AUTOTEST] keyboard failed");
                log_msg(LOG_ERR, "autotest", "keyboard_failed");
                flush_line(); return;
            }

            terminal_writestring("\n[AUTOTEST] dhcp...");
            if (network_config_acquire_dhcp() != 0) {
                terminal_writestring("\n[AUTOTEST] dhcp failed");
                log_msg(LOG_ERR, "autotest", "dhcp failed");
                flush_line(); return;
            }
            terminal_writestring("\n[AUTOTEST] dhcp ok");
            log_msg(LOG_INFO, "autotest", "dhcp_ok");
            if (dhcp_start_service() < 0) {
                terminal_writestring("\n[AUTOTEST] dhcpd start failed");
                log_msg(LOG_ERR, "autotest", "dhcpd_start_failed");
            } else {
                for (int i = 0; i < 32 && dhcp_service_pid() < 0; i++) sched_yield();
            }

            uint32_t dns_ip = 0;
            dns_add_record("knitos.local", ip_get_our_ip());
            if (dns_resolve("knitos.local", &dns_ip) == 0 && dns_ip == ip_get_our_ip()) {
                terminal_writestring("\n[AUTOTEST] dns ok");
                log_fmt3(LOG_INFO, "autotest", "dns_ok", "ip", dns_ip, "ok", 1u, "port", 0u);
            } else {
                terminal_writestring("\n[AUTOTEST] dns failed");
                log_msg(LOG_ERR, "autotest", "dns failed");
                flush_line(); return;
            }

            terminal_writestring("\n[AUTOTEST] ports...");
            int ports_rc = net_ports_autotest();
            if (ports_rc != 0) {
                terminal_writestring("\n[AUTOTEST] ports failed rc=");
                shell_write_u32((uint32_t)(ports_rc < 0 ? (uint32_t)(-ports_rc) : (uint32_t)ports_rc));
                log_fmt3(LOG_ERR, "autotest", "ports_failed", "rc",
                         (uint32_t)(ports_rc < 0 ? (uint32_t)(-ports_rc) : (uint32_t)ports_rc),
                         "ok", 0u, "x", 0u);
                flush_line(); return;
            }
            terminal_writestring("\n[AUTOTEST] ports ok");
            log_msg(LOG_INFO, "autotest", "ports_ok");

            terminal_writestring("\n[AUTOTEST] sched...");
            int sched_rc = sched_autotest();
            if (sched_rc != 0) {
                terminal_writestring("\n[AUTOTEST] sched failed rc=");
                shell_write_u32((uint32_t)(sched_rc < 0 ? (uint32_t)(-sched_rc) : (uint32_t)sched_rc));
                log_fmt3(LOG_ERR, "autotest", "sched_failed", "rc",
                         (uint32_t)(sched_rc < 0 ? (uint32_t)(-sched_rc) : (uint32_t)sched_rc),
                         "ok", 0u, "x", 0u);
                flush_line(); return;
            }
            terminal_writestring("\n[AUTOTEST] sched ok");
            log_msg(LOG_INFO, "autotest", "sched_ok");

            terminal_writestring("\n[AUTOTEST] user...");
            int user_rc = user_autotest_run();
            if (user_rc != 0) {
                terminal_writestring("\n[AUTOTEST] user failed rc=");
                shell_write_u32((uint32_t)(user_rc < 0 ? (uint32_t)(-user_rc) : (uint32_t)user_rc));
                log_fmt3(LOG_ERR, "autotest", "user_failed", "rc",
                         (uint32_t)(user_rc < 0 ? (uint32_t)(-user_rc) : (uint32_t)user_rc),
                         "ok", 0u, "x", 0u);
                flush_line(); return;
            }
            terminal_writestring("\n[AUTOTEST] user ok");
            log_msg(LOG_INFO, "autotest", "user_ok");
            /* sleep_ok is logged inside sched_autotest on success */

            http_server_init();
            const char* test_body = "hello-from-guest";
            fs_write("/www/test.txt", test_body, 16);
            terminal_writestring("\n[AUTOTEST] IP ");
            shell_write_ip(ip_get_our_ip());
            terminal_writestring(" port ");
            shell_write_port(port);
            terminal_writestring(" max=");
            char mb[8];
            int mi = 0, mv = max_req, mt = 0;
            char mtmp[8];
            if (mv == 0) { mb[mi++] = '0'; }
            else {
                while (mv > 0 && mt < 6) { mtmp[mt++] = (char)('0' + (mv % 10)); mv /= 10; }
                while (mt > 0 && mi < 7) mb[mi++] = mtmp[--mt];
            }
            mb[mi] = 0;
            terminal_writestring(mb);
            log_fmt3(LOG_INFO, "autotest", "prep", "port", (uint32_t)port,
                     "max", (uint32_t)max_req, "ip", ip_get_our_ip());

            /* Kill-smoke on alternate port before main server */
            {
                int kid = http_server_start(18080, 64, 2000);
                if (kid > 0) {
                    uint32_t w0 = timer_ms();
                    while (!http_server_ready() && timer_ms_since(w0) < 3000) sched_yield();
                    if (http_server_ready() && net_ports_busy(NET_PROTO_TCP, 18080)) {
                        task_kill(kid);
                        http_server_clear_state();
                        uint32_t w1 = timer_ms();
                        while (net_ports_busy(NET_PROTO_TCP, 18080) && timer_ms_since(w1) < 2000)
                            sched_yield();
                        if (!net_ports_busy(NET_PROTO_TCP, 18080))
                            log_msg(LOG_INFO, "autotest", "httpd_kill_ok");
                    } else {
                        task_kill(kid);
                        http_server_clear_state();
                    }
                }
            }

            int hid = http_server_start(port, max_req, 5000);
            if (hid < 0) {
                terminal_writestring("\n[AUTOTEST] httpd start failed");
                log_msg(LOG_ERR, "autotest", "httpd_start_failed");
                flush_line(); return;
            }
            {
                uint32_t w0 = timer_ms();
                while (!http_server_ready() && timer_ms_since(w0) < 5000) {
                    nic_process_packets();
                    sched_yield();
                }
            }
            if (!http_server_ready()) {
                terminal_writestring("\n[AUTOTEST] http ready timeout");
                log_msg(LOG_ERR, "autotest", "http_ready_timeout");
                flush_line(); return;
            }

            http_server_wait(0); /* until idle_done / max */
            int n = http_server_last_served();
            log_fmt3(LOG_INFO, "autotest", "http_done", "served", (uint32_t)(n < 0 ? 0 : n),
                     "port", (uint32_t)port, "ok", n >= 0 ? 1u : 0u);
            terminal_writestring("\n[AUTOTEST] http_done served=");
            char nb[8]; int ni = 0;
            int v = n < 0 ? 0 : n;
            char tmp[8]; int t = 0;
            if (v == 0) { nb[ni++] = '0'; }
            else { while (v > 0 && t < 6) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
                   while (t > 0 && ni < 7) nb[ni++] = tmp[--t]; }
            nb[ni] = 0;
            terminal_writestring(nb);
            flush_line(); return;
        }

        // httpserver [port] [max] — HTTP/1.1 сервер (файлы из /www)
        if (len >= 10 && cmd[0]=='h'&&cmd[1]=='t'&&cmd[2]=='t'&&cmd[3]=='p'&&
            cmd[4]=='s'&&cmd[5]=='e'&&cmd[6]=='r'&&cmd[7]=='v'&&cmd[8]=='e'&&cmd[9]=='r' &&
            (len == 10 || cmd[10] == ' ')) {
            uint16_t port = 80;
            int max_req = 8;
            size_t pos = 10;
            if (pos < len && cmd[pos] == ' ') {
                pos++;
                uint16_t p = 0;
                if (shell_parse_u16_token(cmd, len, &pos, &p)) port = p;
                while (pos < len && cmd[pos] == ' ') pos++;
                if (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                    int m = 0;
                    while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                        m = m * 10 + (cmd[pos] - '0');
                        pos++;
                    }
                    if (m > 0 && m <= 64) max_req = m;
                }
            }
            if (ip_get_our_ip() == 0) {
                terminal_writestring("\nNo IP (run dhcp first)");
                flush_line(); return;
            }
            terminal_writestring("\nHTTP server on port ");
            char pb[8]; int pi = 0;
            uint16_t pp = port;
            char tmp[8]; int t = 0;
            while (pp > 0 && t < 6) { tmp[t++] = (char)('0' + (pp % 10)); pp /= 10; }
            while (t > 0 && pi < 7) pb[pi++] = tmp[--t];
            pb[pi] = 0;
            terminal_writestring(pb);
            terminal_writestring(" - httpd kthread (curl on host)...");
            int hid = http_server_start(port, max_req, 5000);
            if (hid < 0) {
                terminal_writestring("\nhttpserver start failed");
                flush_line(); return;
            }
            terminal_writestring("\npid=");
            shell_write_u32((uint32_t)hid);
            http_server_wait(0);
            int n = http_server_last_served();
            if (n < 0) {
                terminal_writestring("\nhttpserver failed (port busy?)");
            } else {
                terminal_writestring("\nServed ");
                char nb[8]; int ni = 0;
                int v = n; t = 0;
                if (v == 0) { nb[ni++] = '0'; }
                else { while (v > 0 && t < 6) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
                       while (t > 0 && ni < 7) nb[ni++] = tmp[--t]; }
                nb[ni] = 0;
                terminal_writestring(nb);
                terminal_writestring(" request(s)");
            }
            flush_line(); return;
        }

        // rshd [port] [max] | rshd stop — удалённая оболочка (raw, аналог telnet)
        if (len >= 4 && cmd[0]=='r'&&cmd[1]=='s'&&cmd[2]=='h'&&cmd[3]=='d' &&
            (len == 4 || cmd[4] == ' ')) {
            if (len >= 9 && cmd[5]=='s'&&cmd[6]=='t'&&cmd[7]=='o'&&cmd[8]=='p') {
                if (rsh_server_running()) { rsh_server_stop(); terminal_writestring("\nrshd stopped"); }
                else terminal_writestring("\nrshd not running");
                flush_line(); return;
            }
            uint16_t port = 2323;
            int maxs = 0;   /* 0 = без ограничения */
            size_t pos = 4;
            if (pos < len && cmd[pos] == ' ') {
                pos++;
                uint16_t p = 0;
                if (shell_parse_u16_token(cmd, len, &pos, &p)) port = p;
                while (pos < len && cmd[pos] == ' ') pos++;
                if (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                    int m = 0;
                    while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') { m = m * 10 + (cmd[pos] - '0'); pos++; }
                    if (m > 0 && m <= 64) maxs = m;
                }
            }
            if (ip_get_our_ip() == 0) { terminal_writestring("\nNo IP (run dhcp first)"); flush_line(); return; }
            int rid = rsh_server_start(port, maxs, 2000);
            if (rid < 0) { terminal_writestring("\nrshd start failed (already running?)"); flush_line(); return; }
            terminal_writestring("\nRemote shell (raw) on port ");
            shell_write_u32((uint32_t)port);
            terminal_writestring(", pid=");
            shell_write_u32((uint32_t)rid);
            terminal_writestring("\nConnect: telnet/nc <ip> ");
            shell_write_u32((uint32_t)port);
            terminal_writestring("  (login with /etc/passwd; 'rshd stop' to stop)");
            flush_line(); return;
        }

        // ftpd [port] | ftpd stop — FTP-сервер (control + PASV)
        if (len >= 4 && cmd[0]=='f'&&cmd[1]=='t'&&cmd[2]=='p'&&cmd[3]=='d' &&
            (len == 4 || cmd[4] == ' ')) {
            if (len >= 9 && cmd[5]=='s'&&cmd[6]=='t'&&cmd[7]=='o'&&cmd[8]=='p') {
                if (ftp_server_running()) { ftp_server_stop(); terminal_writestring("\nftpd stopped"); }
                else terminal_writestring("\nftpd not running");
                flush_line(); return;
            }
            uint16_t port = 21;
            size_t pos = 4;
            if (pos < len && cmd[pos] == ' ') {
                pos++;
                uint16_t p = 0;
                if (shell_parse_u16_token(cmd, len, &pos, &p)) port = p;
            }
            if (ip_get_our_ip() == 0) { terminal_writestring("\nNo IP (run dhcp first)"); flush_line(); return; }
            int fid = ftp_server_start(port, 2000);
            if (fid < 0) { terminal_writestring("\nftpd start failed (already running?)"); flush_line(); return; }
            terminal_writestring("\nFTP server on port ");
            shell_write_u32((uint32_t)port);
            terminal_writestring(", pid=");
            shell_write_u32((uint32_t)fid);
            terminal_writestring("\nConnect: ftp/tftp <ip> ");
            shell_write_u32((uint32_t)port);
            terminal_writestring("  ('ftpd stop' to stop)");
            flush_line(); return;
        }

        // cryptotest — проверка крипто-примитивов по известным векторам (KAT)
        if (len == 10 && strncmp(cmd, "cryptotest", 10) == 0) {
            int fails = crypto_selftest_run();
            terminal_writestring(fails == 0 ? "\nCRYPTO: all tests PASS" : "\nCRYPTO: some tests FAILED");
            flush_line(); return;
        }

        // httpget <host> [path] — HTTP/1.1 GET client
        const char pref_httpget[] = "httpget ";
        if (len >= 8) {
            bool ok = true;
            for (int i = 0; i < 8; i++) if (cmd[i] != pref_httpget[i]) { ok = false; break; }
            if (ok) {
                size_t pos = 8;
                while (pos < len && cmd[pos] == ' ') pos++;
                if (pos >= len) {
                    terminal_writestring("\nUsage: httpget <host> [path]");
                    terminal_writestring("\nExample: httpget example.com");
                    flush_line(); return;
                }
                size_t host_start = pos;
                while (pos < len && cmd[pos] != ' ') pos++;
                size_t host_len = pos - host_start;

                char path[64];
                path[0] = '/';
                path[1] = 0;
                while (pos < len && cmd[pos] == ' ') pos++;
                if (pos < len) {
                    size_t pi = 0;
                    while (pos < len && pi + 1 < sizeof(path)) {
                        path[pi++] = cmd[pos++];
                    }
                    path[pi] = 0;
                }

                if (ip_get_our_ip() == 0) {
                    terminal_writestring("\nNo IP address configured (run dhcp first)");
                    flush_line(); return;
                }

                uint32_t dest_ip = 0;
                if (net_resolve_host(cmd + host_start, host_len, &dest_ip) != 0) {
                    terminal_writestring("\nDNS resolution failed");
                    flush_line(); return;
                }

                char req[384];
                size_t rp = 0;
                auto req_put = [&](const char* s) {
                    while (*s && rp + 1 < sizeof(req)) req[rp++] = *s++;
                };
                req_put("GET ");
                req_put(path);
                req_put(" HTTP/1.1\r\nHost: ");
                for (size_t h = 0; h < host_len && rp + 1 < sizeof(req); h++) {
                    req[rp++] = cmd[host_start + h];
                }
                req_put("\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: KnitOS-httpget/1.1\r\n\r\n");
                req[rp] = 0;

                struct tcp_connection* conn = tcp_connect(dest_ip, 80);
                if (!conn) {
                    terminal_writestring("\nTCP connect failed");
                    flush_line(); return;
                }
                if (tcp_connect_wait(conn, 10000) != 0) {
                    tcp_close(conn);
                    terminal_writestring("\nTCP connect timeout");
                    flush_line(); return;
                }
                if (tcp_send_data(conn, req, rp) < 0) {
                    tcp_close(conn);
                    terminal_writestring("\nTCP send failed");
                    flush_line(); return;
                }

                static char http_buf[2048];
                size_t total = 0;
                for (int w = 0; w < 400 && total + 1 < sizeof(http_buf); w++) {
                    nic_process_packets();
                    tcp_process_timers();
                    int n = tcp_recv_data(conn, http_buf + total, (int)(sizeof(http_buf) - total - 1));
                    if (n > 0) total += (size_t)n;
                    for (volatile int d = 0; d < 50000; d++);
                }
                http_buf[total] = 0;
                tcp_close(conn);

                terminal_writestring("\n");
                if (total == 0) {
                    terminal_writestring("(no data received)");
                } else {
                    terminal_writestring(http_buf);
                }
                flush_line(); return;
            }
        }

        // Команда dns - показать сервер или разрешить имя
        if (len == 3 && cmd[0] == 'd' && cmd[1] == 'n' && cmd[2] == 's') {
            uint32_t dns_srv = dns_get_server();
            terminal_writestring("\nDNS Server: ");
            if (dns_srv != 0) {
                shell_write_ip(dns_srv);
            } else {
                terminal_writestring("Not set (run dhcp or network static)");
            }
            terminal_writestring("\nUsage: dns <hostname>");
            terminal_writestring("\nExample: dns example.com");
            flush_line(); return;
        }

        // Команда dns <hostname> - разрешить доменное имя
        const char pref_dns[]="dns ";
        if (len>=4) {
            bool ok=true; for(int i=0;i<4;i++) if(cmd[i]!=pref_dns[i]) {ok=false; break;}
            if (ok) {
                // Парсим hostname
                size_t i = 4;
                while (i < len && cmd[i] == ' ') i++;
                
                if (i >= len) {
                    terminal_writestring("\nUsage: dns <hostname>");
                    flush_line(); return;
                }
                
                char hostname[256];
                int hostname_len = 0;
                while (i < len && hostname_len < 255 && cmd[i] != ' ') {
                    hostname[hostname_len++] = cmd[i++];
                }
                hostname[hostname_len] = 0;
                
                // Разрешаем имя
                uint32_t ip_address;
                
                if (dns_resolve(hostname, &ip_address) == 0) {
                    terminal_writestring("\n");
                    terminal_writestring(hostname);
                    terminal_writestring(" -> ");
                    shell_write_ip(ip_address);
                } else if (dns_get_server() == 0) {
                    terminal_writestring("\nDNS server not configured (run dhcp or network static)");
                } else {
                    terminal_writestring("\nFailed to resolve hostname");
                }
                flush_line(); return;
            }
        }

        // Команда arp - показать ARP таблицу
        if (len == 3 && cmd[0] == 'a' && cmd[1] == 'r' && cmd[2] == 'p') {
            terminal_writestring("\n=== ARP Table ===");
            struct arp_print_ctx ctx = { 0 };
            arp_foreach_entry(arp_shell_print, &ctx);
            if (ctx.count == 0) {
                terminal_writestring("\n(empty)");
            }
            flush_line(); return;
        }

        // Команда netstat
        if (len == 7 && cmd[0] == 'n' && cmd[1] == 'e' && cmd[2] == 't' &&
            cmd[3] == 's' && cmd[4] == 't' && cmd[5] == 'a' && cmd[6] == 't') {
            terminal_writestring("\n=== TCP Connections ===");
            struct arp_print_ctx ctx = { 0 };
            tcp_foreach_connection(netstat_shell_print, &ctx);
            if (ctx.count == 0) {
                terminal_writestring("\n(none)");
            }
            flush_line(); return;
        }

        // ps — список kernel tasks
        if (len == 2 && cmd[0] == 'p' && cmd[1] == 's') {
            terminal_writestring("\nPID  NAME  STATE  RUNS");
            int count = 0;
            sched_foreach(ps_shell_print, &count);
            if (count == 0) {
                terminal_writestring("\n(none)");
            }
            flush_line(); return;
        }

        // kill [-9] <pid> — как kill -9 в Linux (hard terminate kthread)
        if (len >= 4 && cmd[0]=='k'&&cmd[1]=='i'&&cmd[2]=='l'&&cmd[3]=='l' &&
            (len == 4 || cmd[4] == ' ')) {
            size_t pos = 4;
            while (pos < len && cmd[pos] == ' ') pos++;
            if (pos + 2 <= len && cmd[pos] == '-' && cmd[pos + 1] == '9') {
                pos += 2;
                while (pos < len && cmd[pos] == ' ') pos++;
            }
            if (pos >= len || cmd[pos] < '0' || cmd[pos] > '9') {
                terminal_writestring("\nUsage: kill [-9] <pid>");
                flush_line(); return;
            }
            uint32_t pidv = 0;
            while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                pidv = pidv * 10 + (uint32_t)(cmd[pos] - '0');
                if (pidv > 0x7FFFFFFFu) {
                    terminal_writestring("\nInvalid pid");
                    flush_line(); return;
                }
                pos++;
            }
            int rc = task_kill((int)pidv);
            if (rc == 0) {
                terminal_writestring("\nKilled ");
                shell_write_u32(pidv);
            } else if (rc == -2) {
                terminal_writestring("\nOperation not permitted");
            } else {
                terminal_writestring("\nNo such process");
            }
            flush_line(); return;
        }

        // ports — таблица портов (proto, addrs, state, pid, process)
        if (len == 5 && cmd[0]=='p'&&cmd[1]=='o'&&cmd[2]=='r'&&cmd[3]=='t'&&cmd[4]=='s') {
            net_ports_sync_tcp();
            terminal_writestring("\nProto  Local                 Remote               State         PID  Process");
            struct arp_print_ctx ctx = { 0 };
            net_ports_foreach(ports_shell_print, &ctx);
            if (ctx.count == 0) {
                terminal_writestring("\n(none)");
            } else {
                terminal_writestring("\n(");
                shell_write_u32((uint32_t)ctx.count);
                terminal_writestring(" entries)");
            }
            flush_line(); return;
        }

        // port close tcp|udp <port>
        if (len >= 10 && cmd[0]=='p'&&cmd[1]=='o'&&cmd[2]=='r'&&cmd[3]=='t'&&cmd[4]==' ') {
            size_t pos = 5;
            while (pos < len && cmd[pos] == ' ') pos++;
            bool is_close = (pos + 5 <= len && cmd[pos]=='c'&&cmd[pos+1]=='l'&&cmd[pos+2]=='o'&&
                             cmd[pos+3]=='s'&&cmd[pos+4]=='e');
            if (!is_close) {
                terminal_writestring("\nUsage: ports | port close tcp|udp <port>");
                flush_line(); return;
            }
            pos += 5;
            while (pos < len && cmd[pos] == ' ') pos++;
            uint8_t proto = 0;
            if (pos + 3 <= len && cmd[pos]=='t'&&cmd[pos+1]=='c'&&cmd[pos+2]=='p') {
                proto = NET_PROTO_TCP;
                pos += 3;
            } else if (pos + 3 <= len && cmd[pos]=='u'&&cmd[pos+1]=='d'&&cmd[pos+2]=='p') {
                proto = NET_PROTO_UDP;
                pos += 3;
            } else {
                terminal_writestring("\nUsage: port close tcp|udp <port>");
                flush_line(); return;
            }
            while (pos < len && cmd[pos] == ' ') pos++;
            uint16_t port = 0;
            while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                port = (uint16_t)(port * 10 + (cmd[pos] - '0'));
                pos++;
            }
            if (port == 0) {
                terminal_writestring("\nInvalid port");
                flush_line(); return;
            }
            if (net_ports_close_listen(proto, port) != 0) {
                terminal_writestring("\nNo listening ");
                terminal_writestring(net_port_proto_str(proto));
                terminal_writestring(" port ");
                shell_write_port(port);
            } else {
                terminal_writestring("\nClosed ");
                terminal_writestring(net_port_proto_str(proto));
                terminal_writestring("/");
                shell_write_port(port);
            }
            flush_line(); return;
        }

        // socktest tcp|udp <port> — тест Socket API
        if (len >= 13 && cmd[0]=='s'&&cmd[1]=='o'&&cmd[2]=='c'&&cmd[3]=='k'&&cmd[4]=='t'&&
            cmd[5]=='e'&&cmd[6]=='s'&&cmd[7]=='t'&&cmd[8]==' ') {
            bool is_tcp = (len >= 13 && cmd[9]=='t'&&cmd[10]=='c'&&cmd[11]=='p'&&cmd[12]==' ');
            bool is_udp = (len >= 13 && cmd[9]=='u'&&cmd[10]=='d'&&cmd[11]=='p'&&cmd[12]==' ');
            if (!is_tcp && !is_udp) {
                terminal_writestring("\nUsage: socktest tcp <port> | socktest udp <port>");
                flush_line(); return;
            }
            size_t pos = 13;
            while (pos < len && cmd[pos] == ' ') pos++;
            uint16_t port = 0;
            while (pos < len && cmd[pos] >= '0' && cmd[pos] <= '9') {
                port = (uint16_t)(port * 10 + (cmd[pos] - '0'));
                pos++;
            }
            if (port == 0) {
                terminal_writestring("\nInvalid port");
                flush_line(); return;
            }
            if (ip_get_our_ip() == 0) {
                terminal_writestring("\nNo IP (run dhcp first)");
                flush_line(); return;
            }

            int sfd = socket_create(AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
            if (sfd < 0) {
                terminal_writestring("\nsocket() failed");
                flush_line(); return;
            }
            socket_set_owner(sfd, "socktest", NET_PID_SOCKTEST);
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = port;
            addr.sin_addr = 0;
            if (socket_bind(sfd, &addr) != 0) {
                socket_close(sfd);
                terminal_writestring("\nbind() failed");
                flush_line(); return;
            }

            if (is_udp) {
                terminal_writestring("\nUDP socket on port ");
                char pb[8]; int pi = 0;
                uint16_t p = port;
                char tmp[8]; int t = 0;
                while (p > 0 && t < 6) { tmp[t++] = (char)('0' + (p % 10)); p /= 10; }
                while (t > 0 && pi < 7) pb[pi++] = tmp[--t];
                pb[pi] = 0;
                terminal_writestring(pb);
                terminal_writestring(" (echo 8 pkts, Ctrl+C not needed)");
                char buf[256];
                int pkts = 0;
                while (pkts < 8) {
                    int n = socket_recv(sfd, buf, sizeof(buf) - 1, 3000);
                    if (n < 0) break;
                    if (n == 0) continue;
                    buf[n] = 0;
                    socket_send(sfd, buf, (size_t)n);
                    pkts++;
                }
                socket_close(sfd);
                terminal_writestring("\nUDP socktest done");
                flush_line(); return;
            }

            if (socket_listen(sfd, 4) != 0) {
                socket_close(sfd);
                terminal_writestring("\nlisten() failed");
                flush_line(); return;
            }
            terminal_writestring("\nTCP socket listening, waiting client...");
            int cfd = socket_accept(sfd, 15000);
            if (cfd < 0) {
                socket_close(sfd);
                terminal_writestring("\naccept() timeout");
                flush_line(); return;
            }
            terminal_writestring("\nClient connected, echoing...");
            char buf[512];
            int rounds = 0;
            while (rounds < 32) {
                int n = socket_recv(cfd, buf, sizeof(buf) - 1, 5000);
                if (n < 0) break;
                if (n == 0) {
                    socket_service_network();
                    continue;
                }
                socket_send(cfd, buf, (size_t)n);
                rounds++;
            }
            socket_close(cfd);
            socket_close(sfd);
            terminal_writestring("\nTCP socktest done");
            flush_line(); return;
        }

        // Команда route [ip]
        if (len >= 5 && cmd[0] == 'r' && cmd[1] == 'o' && cmd[2] == 'u' &&
            cmd[3] == 't' && cmd[4] == 'e') {
            if (len == 5) {
                terminal_writestring("\n=== Routing table ===");
                int rc = route_count();
                if (rc == 0) {
                    terminal_writestring("\n(empty - using connected/default helpers)");
                }
                for (int i = 0; i < rc; i++) {
                    const struct route_entry* re = route_get(i);
                    if (!re) continue;
                    terminal_writestring("\n");
                    shell_write_ip(re->dest);
                    terminal_writestring("/");
                    shell_write_ip(re->mask);
                    terminal_writestring(" via ");
                    if (re->gateway) shell_write_ip(re->gateway);
                    else terminal_writestring("on-link");
                    if (re->nif) {
                        terminal_writestring(" dev ");
                        terminal_writestring(re->nif->name);
                    }
                }
                terminal_writestring("\nIP: ");
                uint32_t ip = ip_get_our_ip();
                if (ip != 0) shell_write_ip(ip);
                else terminal_writestring("Not set");
                terminal_writestring("\nGateway: ");
                uint32_t gw = ip_get_gateway();
                if (gw != 0) shell_write_ip(gw);
                else terminal_writestring("Not set");
            } else {
                size_t pos = 6;
                while (pos < len && cmd[pos] == ' ') pos++;
                size_t host_start = pos;
                while (pos < len && cmd[pos] != ' ') pos++;
                uint32_t dest = 0;
                if (host_start >= len || net_resolve_host(cmd + host_start, pos - host_start, &dest) != 0) {
                    terminal_writestring("\nUsage: route [dest_ip|hostname]");
                    flush_line(); return;
                }
                uint32_t hop = ip_resolve_next_hop(dest);
                terminal_writestring("\nNext hop for ");
                shell_write_ip(dest);
                terminal_writestring(": ");
                shell_write_ip(hop);
            }
            flush_line(); return;
        }
        
        terminal_writestring("\nUnknown command");
        flush_line();
    };

    static const char* shell_commands[] = {
        "help", "ls", "find", "cd", "pwd", "clear", "echo", "version", "date", "setdate", "settime", "runelf", "disk", "ps", "kill",
        "login", "logout", "whoami", "id", "users", "useradd", "userdel", "usermod", "groupadd", "groups", "passwd", "su", "chgrp",
        "sessions", "session", "newsession",
        "cat", "nano", "write", "rm", "reboot", "shutdown", "poweroff", "acpi", "resolution", "test",
        "network", "ifconfig", "dhcp", "ip", "udp", "tcp", "udplisten", "ping", "traceroute", "tcpdump", "httpget", "httpserver", "rshd", "ftpd", "dns", "arp", "netstat", "ports", "port", "route", "socktest", "cryptotest", "log", "autotest", 0
    };
    static const char* network_subcommands[] = { "static", "save", "reload", 0 };
    static const char* log_subcommands[] = { "off", "err", "info", "debug", "test", 0 };
    static const char* find_subcommands[] = { "-name", "-type", 0 };
    static const char* path_commands[] = { "cd", "cat", "rm", "write", "ls", "nano", "find", 0 };

    #define SHELL_HISTORY_SIZE SESS_HIST

    auto history_push = [&](const char* cmdline, size_t len) {
        if (len == 0) return;
        if (shell_history_count > 0 && shell_history_len[shell_history_count - 1] == len) {
            bool same = true;
            for (size_t i = 0; i < len; i++) {
                if (shell_history[shell_history_count - 1][i] != cmdline[i]) { same = false; break; }
            }
            if (same) return;
        }
        if (shell_history_count < SHELL_HISTORY_SIZE) {
            shell_history_count++;
        } else {
            for (int h = 1; h < SHELL_HISTORY_SIZE; h++) {
                for (size_t i = 0; i < shell_history_len[h]; i++) {
                    shell_history[h - 1][i] = shell_history[h][i];
                }
                shell_history_len[h - 1] = shell_history_len[h];
            }
        }
        size_t idx = (size_t)(shell_history_count - 1);
        size_t copy = len < 127 ? len : 127;
        for (size_t i = 0; i < copy; i++) shell_history[idx][i] = cmdline[i];
        shell_history[idx][copy] = 0;
        shell_history_len[idx] = copy;
    };

    auto clear_prompt_row = [&]() {
        /* Must not use putchar: filling term_cols spaces wraps and scrolls. */
        size_t cols = terminal_get_width();
        if (cols == 0) cols = 80;
        uint8_t colr = terminal_getcolor();
        for (size_t i = 0; i < cols; i++)
            terminal_put_at(prompt_row, i, ' ', colr);
    };

    auto set_input_line = [&](const char* text, size_t new_len) {
        if (terminal_in_scrollback()) terminal_leave_scrollback();
        clear_prompt_row();
        terminal_set_cursor(prompt_row, 0);
        prompt_print();
        line_len = 0;
        for (size_t i = 0; i < new_len && i < sizeof(line) - 1; i++) {
            line[line_len++] = text[i];
            terminal_putchar(text[i]);
        }
        line[line_len] = 0;
        cur_pos = line_len;
        tab_last_line_len = (size_t)-1;
        tab_cycle_idx = -1;
        terminal_set_cursor(prompt_row, prompt_col + cur_pos);
    };

    auto history_up = [&]() {
        if (shell_history_count == 0) return;
        if (shell_history_pos < 0) {
            shell_history_has_draft = (line_len > 0);
            shell_history_draft_len = line_len;
            for (size_t i = 0; i < line_len; i++) shell_history_draft[i] = line[i];
            shell_history_draft[line_len] = 0;
            shell_history_pos = shell_history_count - 1;
        } else if (shell_history_pos > 0) {
            shell_history_pos--;
        }
        set_input_line(shell_history[shell_history_pos], shell_history_len[shell_history_pos]);
    };

    auto history_down = [&]() {
        if (shell_history_pos < 0) return;
        if (shell_history_pos < shell_history_count - 1) {
            shell_history_pos++;
            set_input_line(shell_history[shell_history_pos], shell_history_len[shell_history_pos]);
            return;
        }
        shell_history_pos = -1;
        if (shell_history_has_draft) {
            set_input_line(shell_history_draft, shell_history_draft_len);
        } else {
            set_input_line("", 0);
        }
    };

    auto redraw_input_line = [&]() {
        if (terminal_in_scrollback()) terminal_leave_scrollback();
        clear_prompt_row();
        terminal_set_cursor(prompt_row, 0);
        prompt_print();
        for (size_t i = 0; i < line_len; i++) {
            terminal_putchar(line[i]);
        }
        terminal_set_cursor(prompt_row, prompt_col + cur_pos);
    };

    auto tab_show_matches = [&](int match_count, const char** matches) {
        terminal_putchar('\n');
        int line_used = 0;
        for (int m = 0; m < match_count; m++) {
            size_t ml = 0;
            while (matches[m][ml]) ml++;
            if (line_used > 0 && line_used + (int)ml + 2 > 78) {
                terminal_putchar('\n');
                line_used = 0;
            }
            terminal_writestring(matches[m]);
            terminal_writestring("  ");
            line_used += (int)ml + 2;
        }
        terminal_putchar('\n');
        prompt_print();
        prompt_row = terminal_get_row();
        for (size_t i = 0; i < line_len; i++) {
            terminal_putchar(line[i]);
        }
        terminal_set_cursor(prompt_row, prompt_col + cur_pos);
    };

    auto tab_complete = [&]() {
        if (line_len >= sizeof(line) - 1) return;

        size_t word_start = 0;
        while (word_start < line_len && line[word_start] == ' ') word_start++;
        size_t wi = line_len;
        while (wi > word_start && line[wi - 1] != ' ') wi--;
        word_start = wi;

        size_t prefix_len = line_len - word_start;
        const char* matches[48];
        int match_count = 0;
        bool first_word = (word_start == 0);
        bool add_space_after = first_word;

        auto add_match = [&](const char* s) {
            if (!s || match_count >= 48) return;
            size_t j = 0;
            while (j < prefix_len && s[j] && s[j] == line[word_start + j]) j++;
            if (j == prefix_len && s[j]) matches[match_count++] = s;
        };

        auto add_path_matches = [&]() {
            char partial[96];
            size_t plen = prefix_len < 95 ? prefix_len : 95;
            for (size_t k = 0; k < plen; k++) partial[k] = line[word_start + k];
            partial[plen] = 0;

            char dir_path[128];
            const char* name_prefix = partial;
            const char* slash = 0;
            for (size_t k = 0; k < plen; k++) {
                if (partial[k] == '/') slash = partial + k;
            }

            if (slash) {
                size_t dlen = (size_t)(slash - partial);
                if (dlen >= sizeof(dir_path)) dlen = sizeof(dir_path) - 1;
                for (size_t k = 0; k < dlen; k++) dir_path[k] = partial[k];
                dir_path[dlen] = 0;
                name_prefix = slash + 1;
            } else {
                const char* cwd = utils_get_current_directory();
                if (!cwd) cwd = "/";
                size_t ci = 0;
                while (cwd[ci] && ci + 1 < sizeof(dir_path)) {
                    dir_path[ci] = cwd[ci];
                    ci++;
                }
                dir_path[ci] = 0;
            }

            if (dir_path[0] == 0) {
                dir_path[0] = '/';
                dir_path[1] = 0;
            }

            char resolved[128];
            if (utils_resolve_path(dir_path, resolved, sizeof(resolved)) == 0) {
                size_t ri = 0;
                while (resolved[ri] && ri + 1 < sizeof(dir_path)) {
                    dir_path[ri] = resolved[ri];
                    ri++;
                }
                dir_path[ri] = 0;
            }

            bool path_relative = (plen > 0 && partial[0] != '/');

            char list_buf[1024];
            static char file_matches[48][128];
            if (vfs_list(dir_path, list_buf, sizeof(list_buf)) < 0) return;

            auto path_join = [&](char* out, size_t out_sz, const char* dir, const char* name,
                                 size_t name_len, bool is_dir) {
                size_t o = 0;
                if (path_relative) {
                    if (slash) {
                        size_t dlen = (size_t)(slash - partial);
                        for (size_t i = 0; i < dlen && o + 1 < out_sz; i++) out[o++] = partial[i];
                        if (o > 0 && o < out_sz - 1) out[o++] = '/';
                    }
                    for (size_t i = 0; i < name_len && o + 1 < out_sz; i++) out[o++] = name[i];
                    if (is_dir && o < out_sz - 1) out[o++] = '/';
                    out[o] = 0;
                    return;
                }
                if (dir[0] == '/' && dir[1] == 0) {
                    if (o < out_sz - 1) out[o++] = '/';
                } else {
                    for (size_t i = 0; dir[i] && o + 1 < out_sz; i++) out[o++] = dir[i];
                    if (o > 0 && o < out_sz - 1) out[o++] = '/';
                }
                for (size_t i = 0; i < name_len && o + 1 < out_sz; i++) out[o++] = name[i];
                if (is_dir && o < out_sz - 1) out[o++] = '/';
                out[o] = 0;
            };

            size_t lp = 0;
            while (list_buf[lp] && match_count < 48) {
                size_t nl = 0;
                while (list_buf[lp + nl] && list_buf[lp + nl] != '\n') nl++;
                if (nl > 0) {
                    bool is_dir = (list_buf[lp + nl - 1] == '/');
                    size_t name_len = is_dir ? nl - 1 : nl;
                    bool ok = true;
                    for (size_t k = 0; name_prefix[k]; k++) {
                        if (k >= name_len || name_prefix[k] != list_buf[lp + k]) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok) {
                        path_join(file_matches[match_count], sizeof(file_matches[match_count]),
                                  dir_path, list_buf + lp, name_len, is_dir);
                        matches[match_count] = file_matches[match_count];
                        match_count++;
                    }
                }
                lp += nl;
                if (list_buf[lp] == '\n') lp++;
            }
            add_space_after = false;
        };

        if (first_word) {
            for (int ci = 0; shell_commands[ci]; ci++) add_match(shell_commands[ci]);
        } else {
            const char net_prefix[] = "network ";
            bool is_network = (line_len >= 8);
            for (size_t n = 0; n < 8 && is_network; n++) {
                if (line[n] != net_prefix[n]) is_network = false;
            }
            const char log_prefix[] = "log ";
            bool is_log = (line_len >= 4);
            for (size_t n = 0; n < 4 && is_log; n++) {
                if (line[n] != log_prefix[n]) is_log = false;
            }
            const char find_prefix[] = "find ";
            bool is_find = (line_len >= 5);
            for (size_t n = 0; n < 5 && is_find; n++) {
                if (line[n] != find_prefix[n]) is_find = false;
            }

            if (is_network && word_start >= 8) {
                for (int ci = 0; network_subcommands[ci]; ci++) add_match(network_subcommands[ci]);
            } else if (is_log && word_start >= 4) {
                for (int ci = 0; log_subcommands[ci]; ci++) add_match(log_subcommands[ci]);
            } else if (is_find && word_start >= 5) {
                size_t cmd_end = 5;
                while (cmd_end < line_len && line[cmd_end] == ' ') cmd_end++;
                size_t arg_start = cmd_end;
                while (arg_start < line_len && line[arg_start] != ' ') arg_start++;
                bool on_options = (word_start > arg_start);
                if (!on_options && word_start == cmd_end) {
                    add_path_matches();
                } else {
                    for (int ci = 0; find_subcommands[ci]; ci++) add_match(find_subcommands[ci]);
                }
            } else {
                size_t cmd_end = 0;
                while (cmd_end < line_len && line[cmd_end] != ' ') cmd_end++;
                bool path_cmd = false;
                for (int pi = 0; path_commands[pi]; pi++) {
                    const char* pc = path_commands[pi];
                    size_t pl = 0;
                    while (pc[pl]) pl++;
                    if (cmd_end == pl) {
                        bool eq = true;
                        for (size_t k = 0; k < pl; k++) {
                            if (line[k] != pc[k]) { eq = false; break; }
                        }
                        if (eq) { path_cmd = true; break; }
                    }
                }
                if (path_cmd && word_start > cmd_end) {
                    add_path_matches();
                }
            }
        }

        if (match_count == 0) return;

        for (int a = 0; a < match_count - 1; a++) {
            for (int b = a + 1; b < match_count; b++) {
                const char* sa = matches[a];
                const char* sb = matches[b];
                bool gt = false;
                for (int k = 0; ; k++) {
                    char ca = sa[k];
                    char cb = sb[k];
                    if (ca > cb) { gt = true; break; }
                    if (ca != cb) break;
                    if (ca == 0) break;
                }
                if (gt) {
                    const char* tmp = matches[a];
                    matches[a] = matches[b];
                    matches[b] = tmp;
                }
            }
        }

        bool same_tab_state = (tab_last_line_len == line_len &&
                               tab_last_word_start == word_start);
        if (!same_tab_state) tab_cycle_idx = -1;
        tab_last_line_len = line_len;
        tab_last_word_start = word_start;

        if (match_count == 1) {
            line_len = word_start;
            const char* full = matches[0];
            for (size_t fi = 0; full[fi] && line_len < sizeof(line) - 1; fi++)
                line[line_len++] = full[fi];
            if (first_word && add_space_after && line_len < sizeof(line) - 1)
                line[line_len++] = ' ';
            line[line_len] = 0;
            tab_last_line_len = (size_t)-1;
            tab_cycle_idx = -1;
            redraw_input_line();
            return;
        }

        size_t common = prefix_len;
        bool extend = true;
        while (extend) {
            char ch = matches[0][common];
            if (!ch) break;
            for (int m = 1; m < match_count; m++) {
                if (matches[m][common] != ch) {
                    extend = false;
                    break;
                }
            }
            if (extend) common++;
        }

        if (common > prefix_len) {
            for (size_t k = prefix_len; k < common && line_len < sizeof(line) - 1; k++)
                line[line_len++] = matches[0][k];
            line[line_len] = 0;
            tab_last_line_len = (size_t)-1;
            tab_cycle_idx = -1;
            redraw_input_line();
            return;
        }

        if (same_tab_state) {
            tab_cycle_idx++;
            if (tab_cycle_idx >= match_count) tab_cycle_idx = 0;
            line_len = word_start;
            for (const char* p = matches[tab_cycle_idx]; *p && line_len < sizeof(line) - 1; p++) {
                line[line_len++] = *p;
            }
            line[line_len] = 0;
            redraw_input_line();
            return;
        }

        terminal_putchar('\n');
        tab_show_matches(match_count, matches);
    };

    // Авторизация при запуске ОС — до входа в shell.
    do_login_prompt();
    terminal_writestring("\nWelcome to ");
    terminal_writestring(KERNEL_NAME);
    terminal_putchar('\n');
    prompt_row = terminal_get_row();
    line_len = 0;
    prompt_print();

    // Главный цикл: softirq net_process + TCP/DHCP на PIT time
    uint32_t last_timer_ms = timer_ms();
    uint32_t last_status_ms = last_timer_ms;
    while (1) {
        nic_process_packets();

        /* Отложенная команда ядра от user-space (SYS_KCMD / SSH):
           выполняем тем же обработчиком, вывод захватываем в буфер. */
        {
            char kc[256];
            if (kernel_kcmd_take(kc, sizeof(kc))) {
                terminal_capture_begin(kernel_kcmd_resp(), kernel_kcmd_resp_cap());
                process_command(kc, strlen(kc));
                size_t rl = terminal_capture_end();
                kernel_kcmd_reply(rl);
                /* Восстановить приглашение (захваченный вывод не рисовался). */
                prompt_row = terminal_get_row();
                line_len = 0;
                cur_pos = 0;
                prompt_print();
            }
        }

        uint32_t now_ms = timer_ms();
        if (now_ms - last_timer_ms >= 10) {
            tcp_process_timers();
            dhcp_poll();
            last_timer_ms = now_ms;
        }

        /* Живые часы в строке статуса (~1 раз в секунду). */
        if (now_ms - last_status_ms >= 1000) {
            last_status_ms = now_ms;
            if (!terminal_in_scrollback()) refresh_status_line();
        }

        /* Мигание курсора (программный блок). */
        terminal_cursor_tick(now_ms);
        
        /* Drain several keys per tick so IRQ buffer does not overflow under yield/FB. */
        for (int kdrain = 0; kdrain < 16; kdrain++) {
            char c = poll_key();
            if (c == 0) break;

            uint8_t uc = (uint8_t)c;
            if (uc == KEY_UP) {
                history_up();
            } else if (uc == KEY_DOWN) {
                history_down();
            } else if (uc == KEY_LEFT) {
                if (cur_pos > 0) { cur_pos--; terminal_set_cursor(prompt_row, prompt_col + cur_pos); }
            } else if (uc == KEY_RIGHT) {
                if (cur_pos < line_len) { cur_pos++; terminal_set_cursor(prompt_row, prompt_col + cur_pos); }
            } else if (uc == KEY_HOME) {
                cur_pos = 0;
                terminal_set_cursor(prompt_row, prompt_col);
            } else if (uc == KEY_END) {
                cur_pos = line_len;
                terminal_set_cursor(prompt_row, prompt_col + line_len);
            } else if (uc == KEY_INSERT || (uc >= KEY_F1 && uc <= KEY_F12)) {
                /* unused in line editor */
            } else if (uc == KEY_PGUP) {
                terminal_scroll_page_up();
                refresh_status_line();
            } else if (uc == KEY_PGDN) {
                terminal_scroll_page_down();
                refresh_status_line();
            } else if (c == 12 || (keyboard_ctrl_down() && (c == 'l' || c == 'L'))) {
                line_len = 0;
                cur_pos = 0;
                cmd_clear();
            } else if (c == 3) {
                /* Ctrl+C: отмена ввода — прервать текущую строку */
                if (line_len > 0) {
                    terminal_writestring("^C\n");
                    line_len = 0;
                    cur_pos = 0;
                } else {
                    terminal_writestring("^C\n");
                }
                flush_line();
            } else if (c == 21) {
                /* Ctrl+U: удалить строку от курсора до начала */
                if (line_len > 0) {
                    size_t cols = terminal_get_width();
                    if (cols == 0) cols = 80;
                    uint8_t colr = terminal_getcolor();
                    for (size_t i = 0; i < cols; i++)
                        terminal_put_at(prompt_row, i, ' ', colr);
                    terminal_set_cursor(prompt_row, 0);
                    prompt_print();
                    line_len = 0;
                    cur_pos = 0;
                    line[0] = 0;
                }
            } else if (c == 1) {
                /* Ctrl+A: переместить курсор в начало строки */
                cur_pos = 0;
                terminal_set_cursor(prompt_row, prompt_col);
            } else if (c == 5) {
                /* Ctrl+E: переместить курсор в конец строки */
                cur_pos = line_len;
                terminal_set_cursor(prompt_row, prompt_col + line_len);
            } else if (c == '\n' || c == '\r') {
                line[line_len] = 0;
                if (line_len > 0) history_push(line, line_len);
                shell_history_pos = -1;
                shell_history_has_draft = false;
                process_command(line, line_len);
                line_len = 0;
                cur_pos = 0;
            } else if (c == '\b') {
                if (cur_pos > 0) {
                    if (terminal_in_scrollback()) terminal_leave_scrollback();
                    bool mid = (cur_pos < line_len);
                    for (size_t i = cur_pos - 1; i + 1 < line_len; i++) line[i] = line[i + 1];
                    line_len--;
                    cur_pos--;
                    if (!mid) {
                        size_t col = prompt_col + line_len;
                        terminal_put_at(prompt_row, col, ' ', terminal_getcolor());
                        terminal_set_cursor(prompt_row, col);
                        log_mirror_char('\b');
                        log_mirror_char(' ');
                        log_mirror_char('\b');
                    } else {
                        redraw_input_line();
                    }
                    tab_last_line_len = (size_t)-1;
                    tab_cycle_idx = -1;
                    shell_history_pos = -1;
                }
            } else if (uc == KEY_DELETE) {
                /* Delete: удаляет символ ПОД курсором (вперёд), курсор не сдвигаем. */
                if (cur_pos < line_len) {
                    if (terminal_in_scrollback()) terminal_leave_scrollback();
                    for (size_t i = cur_pos; i + 1 < line_len; i++) line[i] = line[i + 1];
                    line_len--;
                    redraw_input_line();
                    tab_last_line_len = (size_t)-1;
                    tab_cycle_idx = -1;
                    shell_history_pos = -1;
                }
            } else if (c == '\t') {
                if (terminal_in_scrollback()) terminal_leave_scrollback();
                tab_complete();
            } else if (c == 27) {
                line_len = 0;
                cur_pos = 0;
                redraw_input_line();
                tab_last_line_len = (size_t)-1;
                tab_cycle_idx = -1;
            } else if (uc < 0x80 && c >= 32) {
                if (line_len < sizeof(line) - 1) {
                    if (terminal_in_scrollback()) terminal_leave_scrollback();
                    bool mid = (cur_pos < line_len);
                    for (size_t i = line_len; i > cur_pos; i--) line[i] = line[i - 1];
                    line[cur_pos] = c;
                    line_len++;
                    cur_pos++;
                    if (!mid) {
                        terminal_set_cursor(prompt_row, prompt_col + line_len - 1);
                        terminal_putchar(c);
                    } else {
                        redraw_input_line();
                    }
                    tab_last_line_len = (size_t)-1;
                    tab_cycle_idx = -1;
                    shell_history_pos = -1;
                }
            }
        }
        sched_maybe_preempt();
        sched_yield();
    }
}

