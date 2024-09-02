#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

// DNS header structure
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__));

// Function to parse domain name from DNS packet
static void parse_dns_name(const uint8_t *dns_data, char *name, int max_len) {
    int name_len = 0;
    int label_len = dns_data[0];
    int i = 1;

    while (label_len > 0 && name_len < max_len - 1) {
        for (int j = 0; j < label_len && name_len < max_len - 1; j++) {
            name[name_len++] = dns_data[i++];
        }
        name[name_len++] = '.';
        label_len = dns_data[i++];
    }

    if (name_len > 0) {
        name[name_len - 1] = '\0';  // Replace last dot with null terminator
    } else {
        name[0] = '\0';
    }
}

// Global file pointer for the log file
static FILE *dns_log_file = NULL;

// Function to open the log file
void open_dns_log_file(void) {
    if (dns_log_file == NULL) {
        dns_log_file = fopen("dns_mappings.log", "a");
        if (dns_log_file == NULL) {
            RTE_LOG(ERR, L2FWD, "Failed to open dns_mappings.log file\n");
        }
    }
}

// Function to close the log file
void close_dns_log_file(void) {
    if (dns_log_file != NULL) {
        fclose(dns_log_file);
        dns_log_file = NULL;
    }
}

// Function to log DNS mapping
static void log_dns_mapping(const char *domain, const char *ip) {
    if (dns_log_file != NULL) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(dns_log_file, "[%s] %s,%s\n", timestamp, domain, ip);
        fflush(dns_log_file);
    }
}

// Function to parse DNS packet
void parse_dns_packet(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct dns_hdr *dns_hdr;
    
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    if (RTE_BE16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
        ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        
        if (ip_hdr->next_proto_id == IPPROTO_UDP) {
            udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
            
            // Check if it's a DNS packet (UDP port 53)
            if (RTE_BE16(udp_hdr->dst_port) == 53 || RTE_BE16(udp_hdr->src_port) == 53) {
                dns_hdr = (struct dns_hdr *)(udp_hdr + 1);
                uint16_t flags = rte_be_to_cpu_16(dns_hdr->flags);
                uint16_t qdcount = rte_be_to_cpu_16(dns_hdr->qdcount);
                uint16_t ancount = rte_be_to_cpu_16(dns_hdr->ancount);

                if ((flags & 0x8000) != 0 && qdcount > 0 && ancount > 0) {  // Response with questions and answers
                    char domain_name[256];
                    uint8_t *dns_data = (uint8_t *)(dns_hdr + 1);
                    
                    // Parse question section to get the domain name
                    parse_dns_name(dns_data, domain_name, sizeof(domain_name));
                    
                    // Skip to the answer section
                    while (*dns_data != 0) dns_data++;
                    dns_data += 5;  // Skip null byte, QTYPE, and QCLASS

                    // Parse answer section
                    uint16_t answer_type = (dns_data[2] << 8) | dns_data[3];
                    dns_data += 10;  // Skip NAME, TYPE, CLASS, TTL
                    uint16_t data_len = (dns_data[0] << 8) | dns_data[1];
                    dns_data += 2;

                    if (answer_type == 1 && data_len == 4) {  // A record (IPv4)
                        struct in_addr ip_addr;
                        memcpy(&ip_addr, dns_data, 4);
                        log_dns_mapping(domain_name, inet_ntoa(ip_addr));
                    }
                }
            }
        }
    }
}