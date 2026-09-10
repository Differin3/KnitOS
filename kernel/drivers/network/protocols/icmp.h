#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stddef.h>

#define ICMP_TYPE_ECHO_REPLY    0
#define ICMP_TYPE_DEST_UNREACH  3
#define ICMP_TYPE_ECHO_REQUEST  8
#define ICMP_TYPE_TIME_EXCEEDED 11

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

// Обработать входящий ICMP пакет
void icmp_handle_packet(uint32_t src_ip, const void* payload, size_t payload_size);

// Ping хоста (блокирующий, polling)
int icmp_ping(uint32_t dest_ip, int count);

// Результат одного probe (traceroute)
// kind: 0=timeout, ICMP_TYPE_ECHO_REPLY=destination, ICMP_TYPE_TIME_EXCEEDED=router,
//       ICMP_TYPE_DEST_UNREACH=unreachable (stop)
int icmp_probe_to(uint32_t dest_ip, int ttl, int timeout_ms,
                  int* out_kind, uint32_t* out_from_ip, uint32_t* out_rtt_ms);

#endif
