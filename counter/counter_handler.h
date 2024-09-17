#ifndef ROCKSDB_HANDLER_H
#define ROCKSDB_HANDLER_H

#include <rocksdb/c.h>
#include <stdint.h>
#include <arpa/inet.h> // Add this line

// Initialize RocksDB
int init_rocksdb(const char *db_path, int reset_db);

// Close RocksDB
void close_rocksdb(void);

// Update IP traffic in RocksDB
void update_ip_traffic(const char *ip_addr, uint32_t bytes);
void update_dropped_traffic(const char *ip_addr, uint32_t bytes);

// Update ICMP packets in RocksDB
void update_icmp_packets(const char *ip_addr);
void update_tcp_syn_packets(const char *ip_addr);

// Structure to hold ICMP packet data for an IP address
typedef struct {
    char ip_addr[INET_ADDRSTRLEN];
    uint64_t packet_count;
} ICMPData;

// Read ICMP packet data from RocksDB
ICMPData* read_icmp_packet_data(int* count);

// Function to validate IP address format
int is_valid_ip(const char *ip_addr);

// Function to reset a database
void reset_database(rocksdb_iterator_t* it, rocksdb_t* db);

#endif // ROCKSDB_HANDLER_H