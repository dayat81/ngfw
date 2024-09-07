#ifndef BLACKLIST_HANDLER_H
#define BLACKLIST_HANDLER_H

#include <stdbool.h>
#include <rte_hash.h>

#define MAX_BLACKLIST_SIZE 1000000

extern struct rte_hash *blacklist_hash;

int init_blacklist_db(void);

bool is_ip_blacklisted(const char *ip);
void close_blacklist_db(void);


#endif // BLACKLIST_HANDLER_H
