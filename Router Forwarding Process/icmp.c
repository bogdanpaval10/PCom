#include "include/icmp.h"
#include "include/route_table.h"


void sender_for_icmp(packet m, u_int8_t type)
{ // se adauga in m ethr, iphr si icmphr
	struct ether_header *ethr = malloc(sizeof(struct ether_header));
	ethr->ether_type = htons(ETHERTYPE_IP);
	memcpy(m.payload, ethr, sizeof(struct ether_header));
	free(ethr);
	m.len = sizeof(struct ether_header);

	struct iphdr *iphr = malloc(sizeof(struct iphdr));
	iphr->version = 4;
	iphr->protocol = 0x1;
	iphr->tot_len = sizeof(struct iphdr);
	iphr->ttl = 32;
	memcpy(m.payload + m.len, iphr, sizeof(struct iphdr));
	free(iphr);
	m.len += sizeof(struct iphdr);
	
	struct icmphdr *icmphr = malloc(sizeof(struct icmphdr));
	icmphr->type = type;
	icmphr->code = 0;
	memcpy(m.payload + m.len, icmphr, sizeof(struct icmphdr));
	free(icmphr);
	m.len += sizeof(struct icmphdr);
	
	send_packet(&m); // se trimite pachetul
}

void icmp_timeout(packet m)
{ // cand ttl este 0/1 se arunca pachetul si se trimite la emitator un mesaj ICMP
	sender_for_icmp(m, ICMP_TIME_EXCEEDED);
}

void icmp_unreach(packet m)
{ // cand ip_destinatie nu este in tabela de rutare
	sender_for_icmp(m, ICMP_DEST_UNREACH); // se arunca pachetul si se trimite la
}													 // emitator un mesaj ICMP

void rfc_1624(uint16_t initial, struct iphdr **iphr) // bonus
{
	(*iphr)->ttl--;
	(*iphr)->check = initial - ~((*iphr)->ttl) - (*iphr)->ttl;
}

int check_ip(packet m, struct route_table_entry *table, int rtable_size, 
			 struct iphdr **iphr, struct ether_header *ethr)
{
	uint16_t initial = (*iphr)->check;
	(*iphr)->check = 0;
	if (ip_checksum((void*)*iphr, sizeof(struct iphdr)) != initial) {
		return 1; // daca sumele nu sunt egale, pachetul este corupt, trebuie aruncat
	}

	(*iphr)->ttl--;	// reactualizare ttl
	(*iphr)->check = 0;
	(*iphr)->check = ip_checksum((void*)*iphr, sizeof(struct iphdr)); // recalculare suma control
	//rfc_1624(initial, iphr); // bonus
	
	if (lpm((*iphr)->daddr, table, rtable_size) == NULL) { // daca nu exista o ruta
		icmp_unreach(m);
		return 1;
	}

	if ((*iphr)->ttl <= 1) { // eroare timp depasit
		icmp_timeout(m);
		return 1;
	}

	if ((*iphr)->protocol == IPPROTO_ICMP && 
		(*iphr)->daddr == inet_addr(get_interface_ip(m.interface))) {
		sender_for_icmp(m, ICMP_ECHOREPLY); // daca pachetul este pt router, se trimite
		return 1;							// la emitator
	}
	return 0;
}