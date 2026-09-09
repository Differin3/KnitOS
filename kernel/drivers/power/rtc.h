#ifndef RTC_H
#define RTC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct rtc_time {
    uint16_t year;   /* полный год, например 2026 */
    uint8_t  month;  /* 1-12 */
    uint8_t  day;    /* 1-31 */
    uint8_t  hour;   /* 0-23 */
    uint8_t  minute; /* 0-59 */
    uint8_t  second; /* 0-59 */
};

/* Инициализация RTC: читает текущее время CMOS. */
void rtc_init(void);

/* Достоверное время получено (rtc_init прошла успешно). */
bool rtc_valid(void);

/* Текущее время из CMOS (с учётом BCD/12h). */
struct rtc_time rtc_read(void);

/* Секунды с 1970-01-01 UTC (uint32-математика, до ~2106). */
uint64_t rtc_unix_seconds(void);

/* Записать время в RTC (CMOS). Возвращает true при успехе. */
bool rtc_write(struct rtc_time t);

/* Форматирование: "YYYY-MM-DD", "HH:MM:SS", "YYYY-MM-DD HH:MM:SS". */
void rtc_format_date(char* buf, size_t cap);
void rtc_format_time(char* buf, size_t cap);
void rtc_format_timestamp(char* buf, size_t cap);

#endif