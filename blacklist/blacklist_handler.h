#ifndef BLACKLIST_HANDLER_H
#define BLACKLIST_HANDLER_H

#include <stdbool.h>
#include <rte_hash.h>

#define MAX_BLACKLIST_SIZE 1000000

extern struct rte_hash *blacklist_hash;

int init_blacklist_db(void);

bool is_ip_blacklisted(const char *ip);
void close_blacklist_db(void);

// Add these new function prototypes
int add_ip_to_acl_blacklist(const char *ip);
bool is_ip_in_acl_blacklist(const char *ip);

int init_acl_context(void);
void close_acl_context();

#endif // BLACKLIST_HANDLER_H
