#include "net_queue.h"

/* net_process() вызывается и из задач, и enqueue — из IRQ, поэтому очередь
   защищаем запретом прерываний на время операций над head/tail. */
static inline uint32_t irq_save(void) {
    uint32_t flags;
    asm volatile("pushfl; popl %0; cli" : "=r"(flags) :: "memory");
    return flags;
}
static inline void irq_restore(uint32_t flags) {
    asm volatile("pushl %0; popfl" :: "r"(flags) : "memory", "cc");
}

void net_queue_init(struct net_queue* q) {
    if (!q) return;
    uint32_t f = irq_save();
    q->head = 0;
    q->tail = 0;
    q->drops = 0;
    for (int i = 0; i < NET_QUEUE_SIZE; i++) {
        q->slots[i] = 0;
    }
    irq_restore(f);
}

bool net_queue_push(struct net_queue* q, struct skb* skb) {
    if (!q || !skb) return false;
    uint32_t f = irq_save();
    uint32_t next = (q->tail + 1) % NET_QUEUE_SIZE;
    if (next == q->head) {
        q->drops++;
        irq_restore(f);
        return false;
    }
    q->slots[q->tail] = skb;
    q->tail = next;
    irq_restore(f);
    return true;
}

struct skb* net_queue_pop(struct net_queue* q) {
    if (!q) return 0;
    uint32_t f = irq_save();
    if (q->head == q->tail) { irq_restore(f); return 0; }
    struct skb* skb = q->slots[q->head];
    q->slots[q->head] = 0;
    q->head = (q->head + 1) % NET_QUEUE_SIZE;
    irq_restore(f);
    return skb;
}

bool net_queue_empty(const struct net_queue* q) {
    if (!q) return true;
    return q->head == q->tail;
}
