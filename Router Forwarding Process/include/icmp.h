#ifndef ICMP_H
#define ICMP_H

#include "skel.h"


void sender_for_icmp(packet m, u_int8_t type);

void icmp_timeout(packet m);

void icmp_unreach(packet m);

void rfc1624(struct iphdr *iphr);

int check_ip(packet m, struct route_table_entry *table, int rtable_size, struct iphdr **iphr, struct ether_header* ethr);

#endif /*ICMP_H */