#include "drivers/power/rtc.h"
#include "serial_log.h"
#include <stddef.h>

#define CMOS_INDEX    0x70
#define CMOS_DATA     0x71

#define RTC_SECONDS   0x00
#define RTC_MINUTES   0x02
#define RTC_HOURS     0x04
#define RTC_DAY_MONTH 0x07
#define RTC_MONTH     0x08
#define RTC_YEAR      0x09
#define RTC_STATUS_A  0x0A
#define RTC_STATUS_B  0x0B
#define RTC_CENTURY   0x32

/* Status B: bit1 = 24h mode, bit2 = binary (else BCD). */
#define RTC_B_BIN     (1u << 2)
#define RTC_B_24H     (1u << 1)
#define RTC_B_SET     (1u << 7)

static bool g_rtc_ok = false;

static inline void cmos_write(uint8_t reg) {
    asm volatile ("outb %0, %1" : : "a"(reg), "Nd"((uint16_t)CMOS_INDEX));
}

static inline void cmos_write_byte(uint8_t reg, uint8_t val) {
    cmos_write(reg);
    asm volatile ("outb %0, %1" : : "a"(val), "Nd"((uint16_t)CMOS_DATA));
}

static inline uint8_t cmos_read_byte(uint8_t reg) {
    cmos_write(reg);
    uint8_t v;
    asm volatile ("inb %1, %0" : "=a"(v) : "Nd"((uint16_t)CMOS_DATA));
    return v;
}

static bool cmos_update_in_progress(void) {
    return (cmos_read_byte(RTC_STATUS_A) & 0x80) != 0;
}

static uint8_t rtc_bcd_to_bin(uint8_t v) {
    return (uint8_t)((v & 0x0Fu) + ((v >> 4) & 0x0Fu) * 10u);
}

static uint8_t rtc_bin_to_bcd(uint8_t v) {
    return (uint8_t)(((v / 10u) << 4) | (v % 10u));
}

struct rtc_time rtc_read(void) {
    struct rtc_time t;
    t.year = 0; t.month = 0; t.day = 0;
    t.hour = 0; t.minute = 0; t.second = 0;

    for (int i = 0; i < 100000 && cmos_update_in_progress(); i++) {
        asm volatile ("nop");
    }

    /* Читаем блок регистров атомарно, чтобы не поймать rollover секунды. */
    asm volatile ("cli");
    uint8_t status_b = cmos_read_byte(RTC_STATUS_B);
    uint8_t sec     = cmos_read_byte(RTC_SECONDS);
    uint8_t min     = cmos_read_byte(RTC_MINUTES);
    uint8_t hour    = cmos_read_byte(RTC_HOURS);
    uint8_t mday    = cmos_read_byte(RTC_DAY_MONTH);
    uint8_t mon     = cmos_read_byte(RTC_MONTH);
    uint8_t year    = cmos_read_byte(RTC_YEAR);
    uint8_t century = cmos_read_byte(RTC_CENTURY);
    asm volatile ("sti");

    if (!(status_b & RTC_B_BIN)) {
        sec  = rtc_bcd_to_bin(sec);
        min  = rtc_bcd_to_bin(min);
        hour = rtc_bcd_to_bin(hour);
        mday = rtc_bcd_to_bin(mday);
        mon  = rtc_bcd_to_bin(mon);
        year = rtc_bcd_to_bin(year);
        if (century != 0 && century != 0xFF) century = rtc_bcd_to_bin(century);
    }

    if (!(status_b & RTC_B_24H)) {
        bool pm = (hour & 0x80) != 0;
        hour &= 0x7F;
        if (hour == 0) hour = 12;
        if (pm) {
            if (hour < 12) hour = (uint8_t)(hour + 12);
        } else if (hour == 12) {
            hour = 0;
        }
    }

    uint16_t full_year = 2000u + year;
    if (century >= 19 && century <= 99) {
        full_year = (uint16_t)(century * 100u + year);
    }

    t.year = full_year;
    t.month = mon;
    t.day = mday;
    t.hour = hour;
    t.minute = min;
    t.second = sec;
    return t;
}

bool rtc_valid(void) {
    return g_rtc_ok;
}

bool rtc_write(struct rtc_time t) {
    if (t.year < 1970 || t.year > 2099 ||
        t.month < 1 || t.month > 12 ||
        t.day < 1 || t.day > 31 ||
        t.hour > 23 || t.minute > 59 || t.second > 59) {
        return false;
    }

    for (int i = 0; i < 100000 && cmos_update_in_progress(); i++) {
        asm volatile ("nop");
    }

    asm volatile ("cli");

    uint8_t status_b = cmos_read_byte(RTC_STATUS_B);
    uint8_t century = cmos_read_byte(RTC_CENTURY);

    cmos_write_byte(RTC_STATUS_B, (uint8_t)(status_b | RTC_B_SET));

    uint8_t sec  = t.second;
    uint8_t min  = t.minute;
    uint8_t hour = t.hour;
    uint8_t mday = t.day;
    uint8_t mon  = t.month;
    uint8_t year = (uint8_t)(t.year % 100u);
    bool use_bcd = !(status_b & RTC_B_BIN);

    if (use_bcd) {
        sec  = rtc_bin_to_bcd(sec);
        min  = rtc_bin_to_bcd(min);
        hour = rtc_bin_to_bcd(hour);
        mday = rtc_bin_to_bcd(mday);
        mon  = rtc_bin_to_bcd(mon);
        year = rtc_bin_to_bcd(year);
    }

    if (!(status_b & RTC_B_24H)) {
        /* 12-hour mode: keep low nibble, map 0 -> 12 AM, PM bit set for >=12. */
        uint8_t h12 = (uint8_t)(((hour + 11) % 12) + 1);
        if (hour >= 12) h12 |= 0x80;
        hour = h12;
    }

    cmos_write_byte(RTC_SECONDS, sec);
    cmos_write_byte(RTC_MINUTES, min);
    cmos_write_byte(RTC_HOURS, hour);
    cmos_write_byte(RTC_DAY_MONTH, mday);
    cmos_write_byte(RTC_MONTH, mon);
    cmos_write_byte(RTC_YEAR, year);
    if (century != 0 && century != 0xFF) {
        uint8_t c = (uint8_t)(t.year / 100u);
        if (use_bcd) c = rtc_bin_to_bcd(c);
        cmos_write_byte(RTC_CENTURY, c);
    }

    cmos_write_byte(RTC_STATUS_B, status_b);

    asm volatile ("sti");

    g_rtc_ok = true;
    return true;
}

/*
 * Дней с 1.1.1970 по пролептическому григорианскому календарю.
 * Только uint32-математика (год >= 1970), без 64-битных делителей.
 */
static uint32_t rtc_days_from_civil(uint32_t y, uint32_t m, uint32_t d) {
    uint32_t yy = y - (m <= 2);
    uint32_t era = yy / 400u;
    uint32_t yoe = yy - era * 400u;
    int32_t  mp = (int32_t)m + ((m > 2) ? -3 : 9);
    uint32_t doy = (153u * (uint32_t)mp + 2u) / 5u + d - 1u;
    uint32_t doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097u + doe - 719468u;
}

static bool rtc_time_valid(const struct rtc_time* t) {
    return t->year >= 1970 && t->year <= 2105 &&
           t->month >= 1 && t->month <= 12 &&
           t->day >= 1 && t->day <= 31 &&
           t->hour < 24 && t->minute < 60 && t->second < 60;
}

uint64_t rtc_unix_seconds(void) {
    struct rtc_time t = rtc_read();
    if (!rtc_time_valid(&t)) return 0;
    uint32_t days = rtc_days_from_civil(t.year, t.month, t.day);
    uint32_t secs = days * 86400u + (uint32_t)t.hour * 3600u +
                    (uint32_t)t.minute * 60u + (uint32_t)t.second;
    return (uint64_t)secs;
}

static void rtc_fmt2(char*& p, uint8_t v) {
    p[0] = (char)('0' + (v / 10));
    p[1] = (char)('0' + (v % 10));
    p += 2;
}

static void rtc_fmt4(char*& p, uint16_t v) {
    for (int mul = 1000; mul >= 1; mul /= 10) {
        *p++ = (char)('0' + (v / (uint16_t)mul));
        v %= (uint16_t)mul;
    }
}

void rtc_format_date(char* buf, size_t cap) {
    struct rtc_time t = rtc_read();
    if (!buf || cap < 11) return;
    char* p = buf;
    rtc_fmt4(p, t.year);
    *p++ = '-';
    rtc_fmt2(p, t.month);
    *p++ = '-';
    rtc_fmt2(p, t.day);
    *p = 0;
}

void rtc_format_time(char* buf, size_t cap) {
    struct rtc_time t = rtc_read();
    if (!buf || cap < 9) return;
    char* p = buf;
    rtc_fmt2(p, t.hour);
    *p++ = ':';
    rtc_fmt2(p, t.minute);
    *p++ = ':';
    rtc_fmt2(p, t.second);
    *p = 0;
}

void rtc_format_timestamp(char* buf, size_t cap) {
    struct rtc_time t = rtc_read();
    if (!buf || cap < 20) return;
    char* p = buf;
    rtc_fmt4(p, t.year);
    *p++ = '-';
    rtc_fmt2(p, t.month);
    *p++ = '-';
    rtc_fmt2(p, t.day);
    *p++ = ' ';
    rtc_fmt2(p, t.hour);
    *p++ = ':';
    rtc_fmt2(p, t.minute);
    *p++ = ':';
    rtc_fmt2(p, t.second);
    *p = 0;
}

void rtc_init(void) {
    struct rtc_time t = rtc_read();
    g_rtc_ok = rtc_time_valid(&t);
    if (g_rtc_ok) {
        char buf[21];
        rtc_format_timestamp(buf, sizeof(buf));
        log_msg(LOG_INFO, "rtc", buf);
    } else {
        log_msg(LOG_ERR, "rtc", "invalid time");
    }
}