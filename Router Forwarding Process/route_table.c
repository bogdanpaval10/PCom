#include "include/skel.h"
#include "include/route_table.h"
#include <string.h>


struct route_table_entry *route_table(char *fname)
{// formeaza tabela de rutare cu informatiile citite
	struct route_table_entry *table = malloc(MAX_RTABLE_SIZE * sizeof(struct route_table_entry));
	DIE(table == NULL, "Error malloc");
	FILE *in_file = fopen(fname, "r");
	DIE(in_file == NULL, "Error open file");

	char line[MAX_LINE_SIZE], prefix[MAX_WORD_SIZE], next_hop[MAX_WORD_SIZE], mask[MAX_WORD_SIZE];
	int interface, rtable_size = 0;

	while(sscanf(line, "%s %s %s %d", prefix, next_hop, mask, &interface) == 4) {
		table[rtable_size].prefix = inet_addr(prefix);
		table[rtable_size].next_hop = inet_addr(next_hop);
		table[rtable_size].mask = inet_addr(mask);
		table[rtable_size].interface = interface;
		rtable_size += 1;
	}
	fclose(in_file);
	return table;
}


struct route_table_entry *lpm_liniar(__u32 dest, struct route_table_entry *table, int rtable_size)
{ // cu cautare liniara
	int i = rtable_size, save_i = rtable_size, maxi = 0;
	while (i) {
		if(table[i].prefix == (table[i].mask & dest)) { // verifica daca adresa data exista
			if (table[i].mask > maxi) {					// in tabela de rutare
				save_i = i;
				maxi = table[save_i].mask;
			}
		}
		i--;
	}
	return save_i == rtable_size ? NULL : &table[save_i];
} // nu este apelata

struct route_table_entry *lpm(__u32 dest, struct route_table_entry *table, int rtable_size)
{ // cu cautare binara
	int left = 0, mid, save_left = -1;
	while (left < rtable_size) {
		mid = (left + rtable_size) / 2;
		if (ntohl(table[mid].prefix) < ntohl(dest & table[mid].mask)) { // left most
			left = mid + 1;
			save_left = left;
		} else {
			rtable_size = mid;
		}
	}
	if (save_left >= 0) {
		return &table[save_left]; // daca exista, intoarce intrarea cu masca maxima
	}
	return NULL; // daca nu exista, intoarce NULL
} // este apelata