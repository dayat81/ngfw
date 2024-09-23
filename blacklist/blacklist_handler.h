#ifndef BLACKLIST_HANDLER_H
#define BLACKLIST_HANDLER_H

#include <stdbool.h>
#include <rte_hash.h>

#define MAX_BLACKLIST_SIZE 1000000

extern struct rte_hash *blacklist_hash;
// Define a structure for the 5-tuple rule
struct ipv4_5tuple {
    uint8_t proto;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
};

int init_blacklist_db(void);

bool is_ip_blacklisted(const char *ip);
void close_blacklist_db(void);

// Add these new function prototypes
int add_ip_to_acl_blacklist(const struct ipv4_5tuple *tuple);
bool is_ip_in_acl_blacklist(const struct ipv4_5tuple *tuple);

int init_acl_context(void);
void close_acl_context();

#endif // BLACKLIST_HANDLER_H
