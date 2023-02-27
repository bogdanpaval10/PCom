#ifndef ARP_H
#define ARP_H

#include "skel.h"
#include "route_table.h"
#include "queue.h"

#define MAX_ARP 5


struct arp_entry *get_arp(__u32 ip, struct arp_entry *arp, int arp_size);

struct arp_header *make_arphr(uint16_t op);

void arp_request(packet m, struct arp_header *arphr);

queue arp_send_packets(queue q, struct route_table_entry *table, int rtable_size, struct ether_header *ethr, struct arp_header *arphr, struct arp_entry **arp, int *arp_size);

queue arp_reply(packet m, queue q, struct route_table_entry *lpfm);

#endif /*ARP_H */