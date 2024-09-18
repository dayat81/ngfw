#include "counter_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Add this include for inet_pton
#include <inttypes.h>
#include <rte_log.h>

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

static rocksdb_t *db_allowed, *db_blocked, *db_icmp, *db_tcp_syn, *db_flow; // New database for flow packets
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
    char db_path_allowed[256], db_path_blocked[256], db_path_icmp[256], db_path_tcp_syn[256], db_path_flow[256]; // New path for flow packets
    snprintf(db_path_allowed, sizeof(db_path_allowed), "%s_allowed", db_path);
    snprintf(db_path_blocked, sizeof(db_path_blocked), "%s_blocked", db_path);
    snprintf(db_path_icmp, sizeof(db_path_icmp), "%s_icmp", db_path);
    snprintf(db_path_tcp_syn, sizeof(db_path_tcp_syn), "%s_tcp_syn", db_path);
    snprintf(db_path_flow, sizeof(db_path_flow), "%s_flow", db_path); // Set path for flow packets

    db_allowed = rocksdb_open(options, db_path_allowed, &err);
    if (err != NULL) {
        fprintf(stderr, "Error opening allowed traffic database: %s\n", err);
        free(err);
        return 1;
    }

    db_blocked = rocksdb_open(options, db_path_blocked, &err);
    if (err != NULL) {
        fprintf(stderr, "Error opening blocked traffic database: %s\n", err);
        free(err);
        return 1;
    }

    db_icmp = rocksdb_open(options, db_path_icmp, &err);
    if (err != NULL) {
        fprintf(stderr, "Error opening ICMP packet database: %s\n", err);
        free(err);
        return 1;
    }

    db_tcp_syn = rocksdb_open(options, db_path_tcp_syn, &err); // Add opening TCP SYN database
    if (err != NULL) {
        fprintf(stderr, "Error opening TCP SYN packet database: %s\n", err);
        free(err);
        return 1;
    }

    db_flow = rocksdb_open(options, db_path_flow, &err); // Open flow packets database
    if (err != NULL) {
        fprintf(stderr, "Error opening flow packets database: %s\n", err);
        free(err);
        return 1;
    }

    if (reset_db) {
        // Reset all data in the databases
        rocksdb_iterator_t* it;
        
        it = rocksdb_create_iterator(db_allowed, readoptions);
        reset_database(it, db_allowed);
        rocksdb_iter_destroy(it);

        it = rocksdb_create_iterator(db_blocked, readoptions);
        reset_database(it, db_blocked);
        rocksdb_iter_destroy(it);

        it = rocksdb_create_iterator(db_icmp, readoptions);
        reset_database(it, db_icmp);
        rocksdb_iter_destroy(it);

        it = rocksdb_create_iterator(db_tcp_syn, readoptions); // Add iterator for TCP SYN database
        reset_database(it, db_tcp_syn);
        rocksdb_iter_destroy(it);

        it = rocksdb_create_iterator(db_flow, readoptions); // Add iterator for flow packets database
        reset_database(it, db_flow);
        rocksdb_iter_destroy(it);
    }

    return 0;
}

void reset_database(rocksdb_iterator_t* it, rocksdb_t* db) {
    rocksdb_iter_seek_to_first(it);
    char *err = NULL;

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
}

void close_rocksdb(void) {
    rocksdb_close(db_allowed);
    rocksdb_close(db_blocked);
    rocksdb_close(db_icmp);
    rocksdb_close(db_flow); // Close flow packets database
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
    
    snprintf(key, sizeof(key), "%s", ip_addr);
    
    char *existing_value = rocksdb_get(db_allowed, readoptions, key, strlen(key), &read_len, &err);
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
    
    rocksdb_put(db_allowed, writeoptions, key, strlen(key), value, strlen(value), &err);
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
    
    snprintf(key, sizeof(key), "%s", ip_addr);
    
    char *existing_value = rocksdb_get(db_blocked, readoptions, key, strlen(key), &read_len, &err);
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
    rocksdb_put(db_blocked, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing dropped traffic to database for IP %s: %s\n", ip_addr, err);
        free(err);
    }
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
    
    snprintf(key, sizeof(key), "%s", ip_addr);
    
    char *existing_value = rocksdb_get(db_icmp, readoptions, key, strlen(key), &read_len, &err);
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
    
    rocksdb_put(db_icmp, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing ICMP packet count to database: %s\n", err);
        free(err);
    }
}

void update_tcp_syn_packets(const char *ip_addr) {
    if (!is_valid_ip(ip_addr)) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_addr);
        return;
    }

    char key[64];
    char value[32];
    char *err = NULL;
    size_t read_len;
    
    snprintf(key, sizeof(key), "%s", ip_addr);
    
    char *existing_value = rocksdb_get(db_tcp_syn, readoptions, key, strlen(key), &read_len, &err);
    if (err != NULL) {
        fprintf(stderr, "Error reading TCP SYN packet count from database: %s\n", err);
        free(err);
        return;
    }
    
    uint64_t total_packets = 1;
    if (existing_value != NULL) {
        total_packets += strtoull(existing_value, NULL, 10);
        free(existing_value);
    }
    
    snprintf(value, sizeof(value), "%" PRIu64, total_packets);
    
    rocksdb_put(db_tcp_syn, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing TCP SYN packet count to database: %s\n", err);
        free(err);
    }
}

ICMPData* read_icmp_packet_data(int* count) {
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db_icmp, readoptions);
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
        const char* ip_start = key;
        size_t ip_len = key_len;

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

// New function to update flow packet counts
void update_flow_packets(const char *src_ip, const char *dst_ip, const char *protocol) {
    char key[128]; // Adjust size as needed
    char value[32];
    char *err = NULL;
    size_t read_len;

    snprintf(key, sizeof(key), "%s_%s_%s", src_ip, dst_ip, protocol); // Create a unique key

    char *existing_value = rocksdb_get(db_flow, readoptions, key, strlen(key), &read_len, &err);
    if (err != NULL) {
        fprintf(stderr, "Error reading flow packet count from database: %s\n", err);
        free(err);
        return;
    }

    uint64_t total_packets = 1; // Start with 1 for the new packet
    if (existing_value != NULL) {
        total_packets += strtoull(existing_value, NULL, 10);
        free(existing_value);
    }

    snprintf(value, sizeof(value), "%" PRIu64, total_packets);

    rocksdb_put(db_flow, writeoptions, key, strlen(key), value, strlen(value), &err);
    if (err != NULL) {
        fprintf(stderr, "Error writing flow packet count to database: %s\n", err);
        free(err);
    }
}