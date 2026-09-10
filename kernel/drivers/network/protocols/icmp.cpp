#include "icmp.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "../nic.h"
#include "tcp_connection.h"
#include <stddef.h>

static inline uint16_t htons(uint16_t hostshort) {
    return ((hostshort & 0xFF) << 8) | ((hostshort >> 8) & 0xFF);
}

static inline uint16_t ntohs(uint16_t netshort) {
    return ((netshort & 0xFF) << 8) | ((netshort >> 8) & 0xFF);
}

static struct {
    bool waiting;
    uint16_t id;
    uint16_t sequence;
    uint32_t from_ip;
    bool received;
    int kind; /* 0 = нет ответа, иначе ICMP_TYPE_* */
} icmp_pending = { false, 0, 0, 0, false, 0 };

static uint16_t icmp_id_counter = 0x4D59; // "MY"

static uint16_t icmp_checksum(void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)bytes[i] << 8) | bytes[i + 1];
    }
    if (len & 1u) {
        sum += (uint16_t)bytes[len - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

static int icmp_send_echo(uint32_t dest_ip, uint16_t id, uint16_t sequence) {
    uint8_t icmp_buffer[sizeof(struct icmp_header) + 32];
    struct icmp_header* hdr = (struct icmp_header*)icmp_buffer;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->checksum = 0;
    hdr->id = htons(id);
    hdr->sequence = htons(sequence);

    const char* payload = "KNITOS PING";
    size_t payload_len = 9;
    for (size_t i = 0; i < payload_len; i++) {
        icmp_buffer[sizeof(struct icmp_header) + i] = payload[i];
    }

    size_t icmp_len = sizeof(struct icmp_header) + payload_len;
    uint16_t csum = icmp_checksum(icmp_buffer, icmp_len);
    hdr->checksum = htons(csum);

    if (ip_get_our_ip() == 0) {
        return -1;
    }
    return ip_output(dest_ip, IP_PROTOCOL_ICMP, icmp_buffer, icmp_len);
}

/* Из ICMP-ошибки (TIME_EXCEEDED/DEST_UNREACH) извлекаем первые 8 байт
   исходного ICMP (id/seq) и сверяем с нашим ожиданием. */
static bool icmp_echo_id_seq_matches(const void* payload, size_t payload_size,
                                     uint16_t want_id, uint16_t want_seq) {
    const uint8_t* p = (const uint8_t*)payload;
    if (payload_size < 8 + 20 + 8) return false;
    uint8_t ihl = (uint8_t)((p[8] & 0x0F) * 4);
    if (ihl < 20 || (size_t)(8 + ihl + 8) > payload_size) return false;
    if (p[8 + 9] != IP_PROTOCOL_ICMP) return false; /* protocol вложенного IP */
    const uint8_t* inner = p + 8 + ihl;
    uint16_t id = ((uint16_t)inner[4] << 8) | inner[5];
    uint16_t seq = ((uint16_t)inner[6] << 8) | inner[7];
    return id == want_id && seq == want_seq;
}

void icmp_handle_packet(uint32_t src_ip, const void* payload, size_t payload_size) {
    if (!payload || payload_size < sizeof(struct icmp_header)) {
        return;
    }

    const struct icmp_header* hdr = (const struct icmp_header*)payload;
    uint8_t type = hdr->type;
    uint16_t id = ntohs(hdr->id);
    uint16_t seq = ntohs(hdr->sequence);

    if (type == ICMP_TYPE_ECHO_REPLY) {
        if (icmp_pending.waiting && id == icmp_pending.id && seq == icmp_pending.sequence) {
            icmp_pending.from_ip = src_ip;
            icmp_pending.received = true;
            icmp_pending.kind = ICMP_TYPE_ECHO_REPLY;
        }
        return;
    }

    if (type == ICMP_TYPE_DEST_UNREACH || type == ICMP_TYPE_TIME_EXCEEDED) {
        /* Внутри ICMP-ошибки лежит исходный IP-заголовок + первые 8 байт
           нашего ICMP echo (id/seq) — по ним сопоставляем ответ с probe. */
        if (icmp_pending.waiting &&
            payload_size >= 8 + 20 + 8 &&
            icmp_echo_id_seq_matches(payload, payload_size,
                                     icmp_pending.id, icmp_pending.sequence)) {
            icmp_pending.from_ip = src_ip;
            icmp_pending.received = true;
            icmp_pending.kind = type;
        }
        return;
    }

    if (type == ICMP_TYPE_ECHO_REQUEST) {
        uint8_t reply[sizeof(struct icmp_header) + 64];
        size_t copy_len = payload_size;
        if (copy_len > sizeof(reply)) {
            copy_len = sizeof(reply);
        }
        for (size_t i = 0; i < copy_len; i++) {
            reply[i] = ((const uint8_t*)payload)[i];
        }
        struct icmp_header* rhdr = (struct icmp_header*)reply;
        rhdr->type = ICMP_TYPE_ECHO_REPLY;
        rhdr->code = 0;
        rhdr->checksum = 0;
        uint16_t csum = icmp_checksum(reply, copy_len);
        rhdr->checksum = htons(csum);

        if (ip_get_our_ip() == 0) {
            return;
        }
        ip_output(src_ip, IP_PROTOCOL_ICMP, reply, copy_len);
    }
}

int icmp_ping(uint32_t dest_ip, int count) {
    if (ip_get_our_ip() == 0) {
        return -1;
    }
    if (count < 1) {
        count = 4;
    }
    if (count > 10) {
        count = 10;
    }

    uint16_t ping_id = icmp_id_counter++;
    int received_total = 0;

    for (int n = 0; n < count; n++) {
        icmp_pending.waiting = true;
        icmp_pending.id = ping_id;
        icmp_pending.sequence = (uint16_t)n;
        icmp_pending.from_ip = 0;
        icmp_pending.received = false;
        icmp_pending.kind = 0;

        if (icmp_send_echo(dest_ip, ping_id, (uint16_t)n) != 0) {
            icmp_pending.waiting = false;
            return -1;
        }

        uint32_t start_time = tcp_get_time();
        int attempts = 0;
        const int max_attempts = 50;

        while (attempts < max_attempts) {
            nic_process_packets();
            if (icmp_pending.received) {
                received_total++;
                uint32_t elapsed = tcp_get_time() - start_time;
                extern void terminal_writestring(const char*);
                terminal_writestring("\nReply from ");
                char ip_buf[20];
                ip_format_address(icmp_pending.from_ip, ip_buf, sizeof(ip_buf));
                terminal_writestring(ip_buf);
                terminal_writestring(": seq=");
                char num[8];
                int np = 0;
                int val = n;
                if (val == 0) num[np++] = '0';
                else {
                    char tmp[8];
                    int t = 0;
                    while (val > 0) { tmp[t++] = '0' + (val % 10); val /= 10; }
                    while (t > 0) num[np++] = tmp[--t];
                }
                num[np] = 0;
                terminal_writestring(num);
                terminal_writestring(" time=");
                np = 0;
                val = (int)elapsed;
                if (val == 0) num[np++] = '0';
                else {
                    char tmp[8];
                    int t = 0;
                    while (val > 0) { tmp[t++] = '0' + (val % 10); val /= 10; }
                    while (t > 0) num[np++] = tmp[--t];
                }
                num[np] = 0;
                terminal_writestring(num);
                terminal_writestring("ms");
                break;
            }
            extern void net_wait_ms(uint32_t ms);
            net_wait_ms(10);
            attempts++;
        }

        if (!icmp_pending.received) {
            extern void terminal_writestring(const char*);
            terminal_writestring("\nRequest timed out");
        }

        icmp_pending.waiting = false;
        extern void net_wait_ms(uint32_t ms);
        net_wait_ms(200);
    }

    return received_total;
}

/* Один traceroute-probe: ICMP echo request с заданным TTL.
   return: 0 = ответ получен (kind/from_ip/rtt заполнены),
           -1 = ошибка отправки, -2 = таймаут. */
int icmp_probe_to(uint32_t dest_ip, int ttl, int timeout_ms,
                  int* out_kind, uint32_t* out_from_ip, uint32_t* out_rtt_ms) {
    if (ip_get_our_ip() == 0) {
        return -1;
    }
    if (ttl < 1) ttl = 1;
    if (ttl > 255) ttl = 255;
    if (timeout_ms <= 0) timeout_ms = 1000;

    uint8_t icmp_buffer[sizeof(struct icmp_header) + 32];
    struct icmp_header* hdr = (struct icmp_header*)icmp_buffer;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->checksum = 0;
    uint16_t probe_id = icmp_id_counter++;
    hdr->id = htons(probe_id);
    hdr->sequence = 0;

    const char* payload = "KNITOS TRACE";
    size_t payload_len = 12;
    for (size_t i = 0; i < payload_len; i++) {
        icmp_buffer[sizeof(struct icmp_header) + i] = payload[i];
    }
    size_t icmp_len = sizeof(struct icmp_header) + payload_len;
    hdr->checksum = htons(icmp_checksum(icmp_buffer, icmp_len));

    icmp_pending.waiting = true;
    icmp_pending.id = probe_id;
    icmp_pending.sequence = 0;
    icmp_pending.from_ip = 0;
    icmp_pending.received = false;
    icmp_pending.kind = 0;

    if (ip_output_ttl(dest_ip, IP_PROTOCOL_ICMP, icmp_buffer, icmp_len, (uint8_t)ttl) != 0) {
        icmp_pending.waiting = false;
        return -1;
    }

    uint32_t start_time = tcp_get_time();
    int attempts = 0;
    int max_attempts = timeout_ms / 10;
    if (max_attempts < 1) max_attempts = 1;

    while (attempts < max_attempts) {
        nic_process_packets();
        if (icmp_pending.received) break;
        extern void net_wait_ms(uint32_t ms);
        net_wait_ms(10);
        attempts++;
    }

    uint32_t rtt = tcp_get_time() - start_time;
    int kind = icmp_pending.kind;
    uint32_t from_ip = icmp_pending.from_ip;
    bool got = icmp_pending.received;
    icmp_pending.waiting = false;

    if (out_kind) *out_kind = kind;
    if (out_from_ip) *out_from_ip = from_ip;
    if (out_rtt_ms) *out_rtt_ms = rtt;

    if (!got) return -2;
    return 0;
}
