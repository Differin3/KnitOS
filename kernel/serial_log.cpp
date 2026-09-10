#include "serial_log.h"

#define COM1_DATA   0x3F8
#define COM1_STATUS 0x3FD

/* Логи по умолчанию отключены: serial-консоль показывает только зеркало
   VGA-терминала (промпт, echo ввода, вывод команд). Включить: log info|debug|err. */
static int g_log_level = LOG_OFF;
static bool g_mirror = true;
static bool g_mirror_input = false;
static int g_telnet_skip = 0;

/* Состояние парсера ESC-последовательностей (стрелки/Home/End/Delete).
 *  0 = нет, 1 = ESC получен, 2 = ESC[ получен, 3-6 = ожидание '~' */
static int g_esc_state = 0;

#define KEY_UP      0x80
#define KEY_DOWN    0x81
#define KEY_LEFT    0x82
#define KEY_RIGHT   0x83
#define KEY_HOME    0x86
#define KEY_END     0x87
#define KEY_DELETE  0x89

static inline uint8_t ser_inb(uint16_t port) {
    uint8_t v;
    asm volatile ("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static inline void ser_outb(uint16_t port, uint8_t val) {
    asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void ser_putchar(char c) {
    for (int i = 0; i < 100000; i++) {
        if (ser_inb(COM1_STATUS) & 0x20) {
            ser_outb(COM1_DATA, (uint8_t)c);
            return;
        }
    }
}

static void ser_puts(const char* s) {
    if (!s) return;
    while (*s) {
        if (*s == '\n') ser_putchar('\r');
        ser_putchar(*s++);
    }
}

static void ser_put_hex32(uint32_t v) {
    ser_puts("0x");
    for (int shift = 28; shift >= 0; shift -= 4) {
        int d = (int)((v >> shift) & 0xF);
        ser_putchar((char)(d < 10 ? ('0' + d) : ('a' + d - 10)));
    }
}

static void ser_put_dec32(uint32_t v) {
    char tmp[12];
    int t = 0;
    if (v == 0) {
        ser_putchar('0');
        return;
    }
    while (v > 0) {
        tmp[t++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (t > 0) ser_putchar(tmp[--t]);
}

static const char* level_name(int level) {
    switch (level) {
        case LOG_ERR:  return "ERR";
        case LOG_INFO: return "INF";
        case LOG_DBG:  return "DBG";
        default:       return "?";
    }
}

static void ser_put_kv_hex(const char* key, uint32_t val) {
    ser_puts(key ? key : "?");
    ser_puts("=");
    ser_put_hex32(val);
}

static void ser_put_kv_dec(const char* key, uint32_t val) {
    ser_puts(key ? key : "?");
    ser_puts("=");
    ser_put_dec32(val);
}

void serial_init(void) {
    ser_outb(0x3F9, 0x00);
    ser_outb(0x3FB, 0x80);
    ser_outb(0x3F8, 0x03);
    ser_outb(0x3F9, 0x00);
    ser_outb(0x3FB, 0x03);
    ser_outb(0x3FC, 0x00);
    if (g_log_level >= LOG_INFO) {
        ser_puts("[INF][serial] mirror enabled -> logs/qemu-serial.log\n");
    }
}

void log_mirror_set(bool enabled) {
    g_mirror = enabled;
}

bool log_mirror_get(void) {
    return g_mirror;
}

void log_mirror_set_input(bool is_user_typing) {
    g_mirror_input = is_user_typing;
}

void log_mirror_char(char c) {
    if (!g_mirror || g_mirror_input) return;
    if (c == '\b') {
        ser_putchar('\b');
        return;
    }
    if (c == '\n') {
        ser_putchar('\r');
        ser_putchar('\n');
        return;
    }
    if (c == '\r') {
        ser_putchar('\r');
        return;
    }
    if (c == '\t' || (c >= 32 && c < 127)) {
        ser_putchar(c);
    }
}

void log_shell_cmd(const char* cwd, const char* cmd, size_t len) {
    if (!g_mirror || g_log_level < LOG_INFO) return;
    ser_puts("[CMD] ");
    if (cwd && cwd[0]) {
        ser_puts(cwd);
    } else {
        ser_puts("/");
    }
    ser_puts(" > ");
    for (size_t i = 0; i < len; i++) {
        char c = cmd[i];
        if (c == '\0') break;
        ser_putchar(c);
    }
    ser_puts("\n");
}

void log_driver_event(const char* name, const char* event) {
    if (g_log_level < LOG_INFO) return;
    ser_puts("[DRV][");
    ser_puts(name ? name : "?");
    ser_puts("] ");
    ser_puts(event ? event : "");
    ser_puts("\n");
}

void log_set_level(int level) {
    if (level < LOG_OFF) level = LOG_OFF;
    if (level > LOG_DBG) level = LOG_DBG;
    g_log_level = level;
}

int log_get_level(void) {
    return g_log_level;
}

void log_msg(int level, const char* tag, const char* message) {
    if (level > g_log_level || g_log_level == LOG_OFF) return;
    ser_puts("[");
    ser_puts(level_name(level));
    ser_puts("][");
    ser_puts(tag ? tag : "?");
    ser_puts("] ");
    ser_puts(message ? message : "");
    ser_puts("\n");
}

void log_u32(int level, const char* tag, const char* message,
             uint32_t a, uint32_t b, uint32_t c) {
    log_fmt3(level, tag, message, "a", a, "b", b, "c", c);
}

void log_fmt3(int level, const char* tag, const char* message,
              const char* k1, uint32_t v1,
              const char* k2, uint32_t v2,
              const char* k3, uint32_t v3) {
    if (level > g_log_level || g_log_level == LOG_OFF) return;
    ser_puts("[");
    ser_puts(level_name(level));
    ser_puts("][");
    ser_puts(tag ? tag : "?");
    ser_puts("] ");
    ser_puts(message ? message : "");
    ser_puts(" ");
    ser_put_kv_hex(k1, v1);
    ser_puts(" ");
    ser_put_kv_hex(k2, v2);
    ser_puts(" ");
    ser_put_kv_dec(k3, v3);
    ser_puts("\n");
}

void log_ip(int level, const char* tag, const char* message, uint32_t ip) {
    if (level > g_log_level || g_log_level == LOG_OFF) return;
    ser_puts("[");
    ser_puts(level_name(level));
    ser_puts("][");
    ser_puts(tag ? tag : "?");
    ser_puts("] ");
    ser_puts(message ? message : "");
    ser_puts(" ip=");
    ser_put_dec32((ip >> 24) & 0xFF);
    ser_putchar('.');
    ser_put_dec32((ip >> 16) & 0xFF);
    ser_putchar('.');
    ser_put_dec32((ip >> 8) & 0xFF);
    ser_putchar('.');
    ser_put_dec32(ip & 0xFF);
    ser_puts("\n");
}

char serial_poll_char(void) {
    if (g_telnet_skip > 0) {
        g_telnet_skip--;
        if (ser_inb(COM1_STATUS) & 0x01) {
            (void)ser_inb(COM1_DATA);
        }
        return 0;
    }
    if (!(ser_inb(COM1_STATUS) & 0x01)) {
        return 0;
    }
    uint8_t b = ser_inb(COM1_DATA);
    if (b == 0xFF) {
        g_telnet_skip = 2;
        return 0;
    }

    /* Enter (CR) должен выполнить команду, поэтому раньше Ctrl+key ветки
       преобразуем его в LF как при обычном пере вода строки. */
    if (b == '\r') {
        g_esc_state = 0;
        return '\n';
    }

    /* Ctrl+key: 1-26 → специальные коды для shell (Ctrl+A..Ctrl+Z) */
    if (b >= 1 && b <= 26) {
        g_esc_state = 0;
        return (char)b; /* shell распознаёт Ctrl+C=3, Ctrl+U=21, Ctrl+A=1, Ctrl+E=5 и т.д. */
    }

    /* Парсер ESC-последовательностей: ESC [ A/B/C/D, ESC [ H/F, ESC [ 2~ (DEL), ESC [ 3~ (DEL) */
    if (g_esc_state == 1) {
        if (b == '[') {
            g_esc_state = 2;
            return 0;
        }
        g_esc_state = 0;
        return 0; /* ESC-однобайтный (Alt) — игнорируем */
    }
    if (g_esc_state == 2) {
        g_esc_state = 0;
        switch (b) {
            case 'A': return KEY_UP;
            case 'B': return KEY_DOWN;
            case 'C': return KEY_RIGHT;
            case 'D': return KEY_LEFT;
            case 'H': return KEY_HOME;
            case 'F': return KEY_END;
            case '2': g_esc_state = 3; return 0; /* ожидаем ~ */
            case '3': g_esc_state = 4; return 0;
            case '1': g_esc_state = 5; return 0;
            case '4': g_esc_state = 6; return 0;
            default:  return 0;
        }
    }
    if (g_esc_state >= 3 && g_esc_state <= 6) {
        if (b == '~') {
            int key = 0;
            switch (g_esc_state) {
                case 3: key = KEY_DELETE; break; /* ESC [ 2~ */
                case 4: key = KEY_DELETE; break; /* ESC [ 3~ */
                case 5: key = KEY_HOME;   break; /* ESC [ 1~ */
                case 6: key = KEY_END;    break; /* ESC [ 4~ */
            }
            g_esc_state = 0;
            return (char)key;
        }
        g_esc_state = 0;
        return 0;
    }

    /* Начало ESC-последовательности */
    if (b == 0x1B) {
        g_esc_state = 1;
        return 0;
    }

    if (b == 127 || b == 8) return '\b';
    if (b == '\n' || b == '\t' || (b >= 32 && b < 127)) {
        return (char)b;
    }
    return 0;
}
