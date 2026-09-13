#ifndef NET_RX_H
#define NET_RX_H

void net_stack_init(void);
void net_process(void);

/* Запускает выделенную kernel-задачу, которая постоянно вызывает
   net_process() (единственный штатный поллер RX). */
void net_start_poller(void);

#endif
