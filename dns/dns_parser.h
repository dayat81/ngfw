#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <rte_mbuf.h>

void open_dns_log_file(void);
void close_dns_log_file(void);
void parse_dns_packet(struct rte_mbuf *m);

#endif // DNS_PARSER_H