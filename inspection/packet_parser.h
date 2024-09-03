#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <rte_mbuf.h>
// DNS header structure
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

void open_dns_log_file(void);
void close_dns_log_file(void);
void parse_packet(struct rte_mbuf *m);
void log_dns_mapping(const char *domain, const char *ip);
void parse_dns_name(const uint8_t *dns_data, char *name, int max_len);
void parse_dns_packet(const struct dns_hdr *dns_hdr, const uint8_t *dns_data);

#endif // DNS_PARSER_H