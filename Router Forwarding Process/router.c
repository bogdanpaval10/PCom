#include "include/queue.h"
#include "include/skel.h"

#include "include/route_table.h"
#include "include/arp.h"
#include "include/icmp.h"

static int cmp(const void* x, const void* y) // functia de comparatie pt qsort
{
	uint32_t p1 = ((struct route_table_entry*)x)->prefix;
	uint32_t m1 = ((struct route_table_entry*)x)->mask;
	uint32_t p2 = ((struct route_table_entry*)y)->prefix;
	uint32_t m2 = ((struct route_table_entry*)y)->mask;
	uint32_t min_mask;

	if (ntohl(m1) < ntohl(m2)) {
		min_mask = m1;
	} else {
		min_mask = m2;
	}

	if ((p1 & min_mask) == (p2 & min_mask)) {
		if (m1 > m2) {
			return -1;
		}
	} else {
		if (ntohl(p1 & min_mask) < ntohl(p2 & min_mask)) {
			return -1;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	queue q = queue_create(); // se salveaza pachetele ce sunt in asteptare
	int rtable_size = 0, arp_size = 0;
	struct route_table_entry *table = route_table(argv[1]);
	rtable_size = read_rtable(argv[1], table); // dimensiunea tabelei de rutare

	struct arp_entry *arp = malloc(MAX_ARP * sizeof(struct arp_entry));
	DIE(arp == NULL, "Error malloc");

	// sortare table pt binary search
	qsort(table, rtable_size, sizeof(struct route_table_entry), cmp);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header *ethr = (struct ether_header*)m.payload; // din payload-ul pachetului m

		if (ethr->ether_type == htons(ETHERTYPE_ARP)) { // este arp
			struct arp_header *arphr = (struct arp_header*)(m.payload + sizeof(struct ether_header));
			
			if (arphr->op == htons(ARPOP_REPLY)) { // este reply, se trimit pachetele din coada
				q = arp_send_packets(q, table, rtable_size, ethr, arphr, &arp, &arp_size);
				continue;
			}
			if (arphr->op == htons(ARPOP_REQUEST)) { // este request
				arp_request(m, arphr); //se trimite arp reply
				continue;
			}
		}

		struct iphdr *iphr = (struct iphdr*)(m.payload + sizeof(struct ether_header)); // din payload-ul pachetului m
		struct route_table_entry *lpfm = lpm(iphr->daddr, table, rtable_size);

		if (ethr->ether_type == htons(ETHERTYPE_IP)) { // este ip
			if (check_ip(m, table, rtable_size, &iphr, ethr) == 1) { // verificare conditii
				continue;											 // checksum si erori
			}
			if (get_arp(lpfm->next_hop, arp, arp_size) == NULL) { // daca adresa nu este in arp,
				q = arp_reply(m, q, lpfm);						  // trimit request
				continue;
			}
			struct arp_entry *aux_arp = get_arp(lpfm->next_hop, arp, arp_size);
			memcpy(ethr->ether_dhost, aux_arp->mac, sizeof(aux_arp->mac));
			get_interface_mac(lpfm->interface, ethr->ether_shost); // modificare adersa mac
		} else {
			continue;
		}
		m.interface = lpfm->interface; // modificare interfata
		send_packet(&m); // se trimite pachetul pe ruta cea mai buna
	}
	free(arp);
	free(table);
	return 0;
}
