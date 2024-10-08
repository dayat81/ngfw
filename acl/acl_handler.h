#ifndef ACL_HANDLER_H
#define ACL_HANDLER_H

#include <rte_acl.h>

#define MAX_ACL_RULES 1024

extern struct rte_acl_ctx *acl_ctx;

int init_acl(void);
int load_acl_rules(const char *filename);
void cleanup_acl(void);
struct rte_acl_rule *get_stored_rule(int index);
void print_rule_fields(const struct rte_acl_rule *rule);

#endif // ACL_HANDLER_H
