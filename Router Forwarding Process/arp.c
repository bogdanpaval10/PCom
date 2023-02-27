#include "include/arp.h"


struct arp_entry *get_arp(__u32 proto, struct arp_entry* arp, int arp_size)
{ // intoarce arp[i] care are ip-ul cerut sau NULL daca nu exista
	for (int i = 0; i < arp_size; i++) {
		if (arp[i].ip == proto) {
			return &arp[i];
		}
	}
	return NULL;
}

struct arp_header *make_arphr(uint16_t op)
{
	struct arp_header *arphr = malloc(sizeof(struct arp_header));
	arphr->htype = htons(1);
	arphr->ptype = 8;
	arphr->op = op;
	arphr->hlen = 6;
	arphr->plen = 4;
	return arphr;
}

void arp_request(packet m, struct arp_header *arphr)
{ // se trimite raspuns cu adresa mac
	struct ether_header ethr; // se formeaza intr-un nou ether_header
	uint8_t mac[6];
	ethr.ether_type = htons(ETHERTYPE_ARP);
	memcpy(ethr.ether_dhost, arphr->sha, sizeof(arphr->sha)); // mac destinatie este emitatorul
	get_interface_mac(m.interface, mac); // seteaza mac-ul
	memcpy(ethr.ether_shost, &mac, sizeof(mac));
	memcpy(m.payload, &ethr, sizeof(struct ether_header));
	m.len = sizeof(struct ether_header);
	
	struct arp_header *aux_arphr = make_arphr(htons(ARPOP_REPLY));
	aux_arphr->spa = arphr->tpa;
	memcpy(aux_arphr->tha, arphr->sha, sizeof(arphr->sha));
	memcpy(m.payload + m.len, aux_arphr, sizeof(struct arp_header));
	free(aux_arphr);
	m.len += sizeof(struct arp_header);

	send_packet(&m); // se trimite pachetul
}

queue arp_send_packets(queue q, struct route_table_entry *table, int rtable_size,
						struct ether_header *ethr, struct arp_header *arphr, 
						struct arp_entry **arp, int *arp_size)
{ // se actualizeaza arp table
	queue aux_q = queue_create();
	// se adauga in arp table
	(*arp)[*arp_size].ip = arphr->spa; // ip este de la emitator
	memcpy((*arp)[*arp_size].mac, arphr->sha, sizeof(arphr->sha)); // mac este de la emitator
	
	while (queue_empty(q) == 0) { // pana cand coada nu este goala
		packet *take_packet = queue_deq(q); // se scoate primul pachet din coada
		struct iphdr *iphr = (struct iphdr*)(take_packet->payload + sizeof(struct ether_header));
					
		struct route_table_entry *lpfm = lpm(iphr->daddr, table, rtable_size);
		if (lpfm->next_hop != arphr->spa) { // daca destinatia != cu adresa ceruta,
			queue_enq(aux_q, take_packet);	// se adauga in coada
		} else {
			struct ether_header *aux_ethr = (struct ether_header*)take_packet->payload;
			memcpy(aux_ethr->ether_dhost, ethr->ether_shost, sizeof(ethr->ether_shost));
			memcpy(take_packet->payload, aux_ethr, sizeof(struct ether_header));
			take_packet->interface = lpfm->interface;
			send_packet(take_packet); // se trimite pachetul din coada
		}
	}
	*arp_size += 1;
	return aux_q;
}

queue arp_reply(packet m, queue q, struct route_table_entry *lpfm)
{ // nu exista nicio adresa mac pt pasul urmator
	packet *take_pack = malloc(sizeof(packet)); // se salveaza pachetul in coada
	DIE(take_pack == NULL, "Error malloc");
	memcpy(take_pack, &m, sizeof(packet));
	queue_enq(q, take_pack); // se pune in asteptare (in coada)
	
	struct ether_header *ethr = malloc(sizeof(struct ether_header));
	DIE(ethr == NULL, "Error malloc");
	memset(ethr->ether_dhost, 0xFF, sizeof(ethr->ether_dhost));
	ethr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(lpfm->interface, ethr->ether_shost); // mac_sursa == mac_interfata
	memcpy(m.payload, ethr, sizeof(struct ether_header));
	free(ethr);
	m.len = sizeof(struct ether_header);
	
	struct arp_header *arphr = make_arphr(htons(ARPOP_REQUEST));
	arphr->spa = inet_addr(get_interface_ip(lpfm->interface));
	arphr->tpa = lpfm->next_hop;
	get_interface_mac(lpfm->interface, arphr->sha);
	memcpy(m.payload + m.len, arphr, sizeof(struct arp_header));
	free(arphr);
	m.len += sizeof(struct arp_header);

	m.interface = lpfm->interface; // se seteaza interfata pe care se trimite
	send_packet(&m); // se trimite pachetul

	return q;
}