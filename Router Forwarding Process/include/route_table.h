#ifndef ROUTE_TABLE_H
#define ROUTE_TABLE_H

#include "skel.h"

#define MAX_RTABLE_SIZE 100000
#define MAX_WORD_SIZE 50
#define MAX_LINE_SIZE 100

struct route_table_entry *route_table(char *fname);

struct route_table_entry *lpm_liniar(__u32 dest, struct route_table_entry *table, int rtable_size);
struct route_table_entry *lpm(__u32 dest, struct route_table_entry *table, int rtable_size);

#endif /*ROUTE_TABLE_H */