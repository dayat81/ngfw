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

// Structure to hold traffic data for an IP address
typedef struct {
    char ip_addr[16];
    uint64_t bytes;
    uint64_t dropped_bytes;
} TrafficData;

// Structure to hold ICMP packet data for an IP address
typedef struct {
    char ip_addr[INET_ADDRSTRLEN];
    uint64_t packet_count;
} ICMPData;

// Read allowed traffic data from RocksDB
TrafficData* read_allowed_traffic_data(int* count);

// Read blacklisted traffic data from RocksDB
TrafficData* read_blacklisted_traffic_data(int* count);

// Read ICMP packet data from RocksDB
ICMPData* read_icmp_packet_data(int* count);

#endif // ROCKSDB_HANDLER_H