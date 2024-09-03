#ifndef BLACKLIST_HANDLER_H
#define BLACKLIST_HANDLER_H

#include <stdbool.h>
#include <rte_hash.h>

#define MAX_BLACKLIST_SIZE 1000000

extern struct rte_hash *blacklist_hash;

int init_blacklist(const char *db_path, int reset_db);
int add_to_blacklist(const char *ip);
int remove_from_blacklist(const char *ip);
bool is_ip_blacklisted(const char *ip);
void close_blacklist(void);
char** get_all_blacklisted_ips(int* count);
int clear_all_blacklisted_ips(void);

#endif // BLACKLIST_HANDLER_H
