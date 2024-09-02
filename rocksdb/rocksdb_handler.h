#ifndef ROCKSDB_HANDLER_H
#define ROCKSDB_HANDLER_H

#include <rocksdb/c.h>

// Initialize RocksDB
int init_rocksdb(const char *db_path, int reset_db);

// Close RocksDB
void close_rocksdb(void);

// Update IP traffic in RocksDB
void update_ip_traffic(const char *ip_addr, uint32_t bytes);

// Structure to hold traffic data for an IP address
typedef struct {
    char ip_addr[16];
    uint64_t bytes;
} TrafficData;

// Read all traffic data from RocksDB
TrafficData* read_all_traffic_data(int* count);


#endif // ROCKSDB_HANDLER_H