#include "counter_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Add this include for inet_pton
#include <inttypes.h>
#include <rte_log.h>

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

static rocksdb_t *db;
static rocksdb_options_t *options;
static rocksdb_writeoptions_t *writeoptions;
static rocksdb_readoptions_t *readoptions;

// Function to validate IP address format
int is_valid_ip(const char *ip_addr) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_addr, &(sa.sin_addr)) != 0;
}

int init_rocksdb(const char *db_path, int reset_db) {
    options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 1);
    writeoptions = rocksdb_writeoptions_create();
    readoptions = rocksdb_readoptions_create();

    char *err = NULL;
    db = rocksdb_open(options, db_path, &err);
    if (err != NULL) {
        fprintf(stderr, "Error opening database: %s\n", err);
        free(err);
        return 1;
    }

    if (reset_db) {
        // Reset all data in the database
        rocksdb_iterator_t* it = rocksdb_create_iterator(db, readoptions);
        rocksdb_iter_seek_to_first(it);

        while (rocksdb_iter_valid(it)) {
            size_t key_len;
            const char* key = rocksdb_iter_key(it, &key_len);
            rocksdb_delete(db, writeoptions, key, key_len, &err);
            if (err != NULL) {
                fprintf(stderr, "Error deleting key: %s\n", err);
                free(err);
                err = NULL;
            }
            rocksdb_iter_next(it);
        }

        rocksdb_iter_destroy(it);
    }

    return 0;
}

void close_rocksdb(void) {
    rocksdb_close(db);
    rocksdb_options_destroy(options);
    rocksdb_writeoptions_destroy(writeoptions);
    rocksdb_readoptions_destroy(readoptions);
}

void update_ip_traffic(const char *ip_addr, uint32_t bytes) {
    if (!is_valid_ip(ip_addr)) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_addr);
        return;
    }

    char key[64];
    char value[32];
    char *err = NULL;
    size_t read_len;
    
    snprintf(key, sizeof(key), "allowed_traffic_%s", ip_addr);
    
    char *existing_value = rocksdb_get(db, readoptions, key, strlen(key), &read_len, &err);
    if (err != NULL) {
        fprintf(stderr, "Error reading from database: %s\n", err);
        free(err);
        return;
    }
    
    uint64_t total_bytes = bytes;
    if (existing_value != NULL) {
        total_bytes += strtoull(existing_value, NULL, 10);
        free(existing_value);
    }
    
    snprintf(value, sizeof(value), "%" PRIu64, total_bytes);
    
    rocksdb_put(db, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing to database: %s\n", err);
        free(err);
    }
}

void update_dropped_traffic(const char *ip_addr, uint32_t bytes) {
    char key[64];
    char value[32];
    char *err = NULL;
    size_t read_len;
    
    snprintf(key, sizeof(key), "dropped_traffic_%s", ip_addr);
    
    char *existing_value = rocksdb_get(db, readoptions, key, strlen(key), &read_len, &err);
    if (err != NULL) {
        fprintf(stderr, "Error reading dropped traffic from database for IP %s: %s\n", ip_addr, err);
        free(err);
        return;
    }
    
    uint64_t total_bytes = bytes;
    if (existing_value != NULL) {
        total_bytes += strtoull(existing_value, NULL, 10);
        free(existing_value);
    }
    
    snprintf(value, sizeof(value), "%" PRIu64, total_bytes);
    // Print total dropped traffic to RTE log
    //RTE_LOG(INFO, L2FWD, "Total dropped traffic for IP %s: %" PRIu64 " bytes\n", ip_addr, total_bytes);
    rocksdb_put(db, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing dropped traffic to database for IP %s: %s\n", ip_addr, err);
        free(err);
    }
}

TrafficData* read_allowed_traffic_data(int* count) {
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, readoptions);
    rocksdb_iter_seek_to_first(iter);

    TrafficData* data = NULL;
    int capacity = 10;
    *count = 0;

    data = malloc(capacity * sizeof(TrafficData));
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        rocksdb_iter_destroy(iter);
        return NULL;
    }

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, value_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* value = rocksdb_iter_value(iter, &value_len);

        // Only process keys that start with "allowed_traffic_"
        if (strncmp(key, "allowed_traffic_", 16) != 0) {
            rocksdb_iter_next(iter);
            continue;
        }

        if (*count >= capacity) {
            capacity *= 2;
            TrafficData* temp = realloc(data, capacity * sizeof(TrafficData));
            if (temp == NULL) {
                fprintf(stderr, "Memory reallocation failed\n");
                free(data);
                rocksdb_iter_destroy(iter);
                return NULL;
            }
            data = temp;
        }

        // Extract IP address from the key
        const char* ip_start = key + 16; // Skip "allowed_traffic_"
        size_t ip_len = key_len - 16;

        // Ensure the IP address is null-terminated
        if (ip_len >= sizeof(data[*count].ip_addr)) {
            ip_len = sizeof(data[*count].ip_addr) - 1;
        }
        strncpy(data[*count].ip_addr, ip_start, ip_len);
        data[*count].ip_addr[ip_len] = '\0'; // Null-terminate the string

        data[*count].bytes = strtoull(value, NULL, 10);
        //data[*count].dropped_bytes = 0; // Not applicable for allowed traffic

        (*count)++;
        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
    return data;
}

TrafficData* read_blacklisted_traffic_data(int* count) {
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, readoptions);
    rocksdb_iter_seek_to_first(iter);

    TrafficData* data = NULL;
    int capacity = 10;
    *count = 0;

    data = malloc(capacity * sizeof(TrafficData));
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        rocksdb_iter_destroy(iter);
        return NULL;
    }

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, value_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* value = rocksdb_iter_value(iter, &value_len);

        // Only process keys that start with "dropped_traffic_"
        if (strncmp(key, "dropped_traffic_", 16) != 0) {
            rocksdb_iter_next(iter);
            continue;
        }

        if (*count >= capacity) {
            capacity *= 2;
            TrafficData* temp = realloc(data, capacity * sizeof(TrafficData));
            if (temp == NULL) {
                fprintf(stderr, "Memory reallocation failed\n");
                free(data);
                rocksdb_iter_destroy(iter);
                return NULL;
            }
            data = temp;
        }

        // Extract IP address from the key
        const char* ip_start = key + 16; // Skip "dropped_traffic_"
        size_t ip_len = key_len - 16;

        // Ensure the IP address is null-terminated
        if (ip_len >= sizeof(data[*count].ip_addr)) {
            ip_len = sizeof(data[*count].ip_addr) - 1;
        }
        strncpy(data[*count].ip_addr, ip_start, ip_len);
        data[*count].ip_addr[ip_len] = '\0'; // Null-terminate the string

        data[*count].bytes = strtoull(value, NULL, 10);
        //data[*count].bytes = 0; // Not applicable for blacklisted traffic

        (*count)++;
        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
    return data;
}

void update_icmp_packets(const char *ip_addr) {
    if (!is_valid_ip(ip_addr)) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_addr);
        return;
    }

    char key[64];
    char value[32];
    char *err = NULL;
    size_t read_len;
    
    snprintf(key, sizeof(key), "icmp_packets_%s", ip_addr);
    
    char *existing_value = rocksdb_get(db, readoptions, key, strlen(key), &read_len, &err);
    if (err != NULL) {
        fprintf(stderr, "Error reading ICMP packet count from database: %s\n", err);
        free(err);
        return;
    }
    
    uint64_t total_packets = 1;
    if (existing_value != NULL) {
        total_packets += strtoull(existing_value, NULL, 10);
        free(existing_value);
    }
    
    snprintf(value, sizeof(value), "%" PRIu64, total_packets);
    
    rocksdb_put(db, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing ICMP packet count to database: %s\n", err);
        free(err);
    }
}

ICMPData* read_icmp_packet_data(int* count) {
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, readoptions);
    rocksdb_iter_seek_to_first(iter);

    ICMPData* data = NULL;
    int capacity = 10;
    *count = 0;

    data = malloc(capacity * sizeof(ICMPData));
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        rocksdb_iter_destroy(iter);
        return NULL;
    }

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, value_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* value = rocksdb_iter_value(iter, &value_len);

        // Only process keys that start with "icmp_packets_"
        if (strncmp(key, "icmp_packets_", 13) != 0) {
            rocksdb_iter_next(iter);
            continue;
        }

        if (*count >= capacity) {
            capacity *= 2;
            ICMPData* temp = realloc(data, capacity * sizeof(ICMPData));
            if (temp == NULL) {
                fprintf(stderr, "Memory reallocation failed\n");
                free(data);
                rocksdb_iter_destroy(iter);
                return NULL;
            }
            data = temp;
        }

        // Extract IP address from the key
        const char* ip_start = key + 13; // Skip "icmp_packets_"
        size_t ip_len = key_len - 13;

        // Ensure the IP address is null-terminated
        if (ip_len >= sizeof(data[*count].ip_addr)) {
            ip_len = sizeof(data[*count].ip_addr) - 1;
        }
        strncpy(data[*count].ip_addr, ip_start, ip_len);
        data[*count].ip_addr[ip_len] = '\0'; // Null-terminate the string

        data[*count].packet_count = strtoull(value, NULL, 10);

        (*count)++;
        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
    return data;
}