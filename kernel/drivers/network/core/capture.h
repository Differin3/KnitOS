#ifndef NET_CAPTURE_H
#define NET_CAPTURE_H

#include <stddef.h>

struct netif;

/* Направление пакета: 0 = RX (из сети), 1 = TX (в сеть).
   Вызывается после того как фрейм принят/отправлен на уровне Ethernet. */
typedef void (*net_capture_fn)(struct netif* nif, int dir,
                               const void* frame, size_t len);

void net_capture_set(net_capture_fn fn);
net_capture_fn net_capture_get(void);

#endif