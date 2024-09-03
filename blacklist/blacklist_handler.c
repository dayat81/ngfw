#include "blacklist_handler.h"
#include <string.h>
#include <arpa/inet.h>
#include <rte_log.h>
#include <rocksdb/c.h>
#include <stdio.h>

// Add this line
#define RTE_LOGTYPE_DB RTE_LOGTYPE_USER1

static rocksdb_t *db;
static rocksdb_options_t *options;
static rocksdb_writeoptions_t *writeoptions;
static rocksdb_readoptions_t *readoptions;
static bool blacklist_initialized = false;

// Function to validate IP address format
static int is_valid_ip(const char *ip_addr) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_addr, &(sa.sin_addr)) != 0;
}

int init_blacklist(const char *db_path, int reset_db)
{
    options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 1);
    
    char *err = NULL;
    db = rocksdb_open(options, db_path, &err);
    if (err != NULL) {
        RTE_LOG(ERR, DB, "Failed to open RocksDB: %s\n", err);
        free(err);
        return -1;
    }

    writeoptions = rocksdb_writeoptions_create();
    readoptions = rocksdb_readoptions_create();

    if (reset_db) {
        // Reset all data in the database
        rocksdb_iterator_t* it = rocksdb_create_iterator(db, readoptions);
        rocksdb_iter_seek_to_first(it);

        while (rocksdb_iter_valid(it)) {
            size_t key_len;
            const char* key = rocksdb_iter_key(it, &key_len);
            rocksdb_delete(db, writeoptions, key, key_len, &err);
            if (err != NULL) {
                RTE_LOG(ERR, DB, "Error deleting key: %s\n", err);
                free(err);
                err = NULL;
            }
            rocksdb_iter_next(it);
        }

        rocksdb_iter_destroy(it);
    }

    blacklist_initialized = true;
    return 0;
}

int add_to_blacklist(const char *ip)
{
    if (!blacklist_initialized || !ip) {
        RTE_LOG(ERR, DB, "Blacklist not initialized or invalid IP\n");
        return -1;
    }

    if (!is_valid_ip(ip)) {
        RTE_LOG(ERR, DB, "Invalid IP address format: %s\n", ip);
        return -1;
    }

    char *err = NULL;
    rocksdb_put(db, writeoptions, ip, strlen(ip), "1", 1, &err);
    if (err != NULL) {
        RTE_LOG(ERR, DB, "Failed to add IP to blacklist: %s\n", err);
        free(err);
        return -1;
    }
    return 0;
}

int remove_from_blacklist(const char *ip)
{
    if (!blacklist_initialized || !ip) {
        RTE_LOG(ERR, DB, "Blacklist not initialized or invalid IP\n");
        return -1;
    }

    char *err = NULL;
    rocksdb_delete(db, writeoptions, ip, strlen(ip), &err);
    if (err != NULL) {
        RTE_LOG(ERR, DB, "Failed to remove IP from blacklist: %s\n", err);
        free(err);
        return -1;
    }
    return 0;
}

bool is_ip_blacklisted(const char *ip)
{
    if (!blacklist_initialized || !ip) {
        RTE_LOG(ERR, DB, "Blacklist not initialized or invalid IP\n");
        return false;
    }

    char *err = NULL;
    size_t len;
    char *value = rocksdb_get(db, readoptions, ip, strlen(ip), &len, &err);
    if (err != NULL) {
        RTE_LOG(ERR, DB, "Failed to check IP in blacklist: %s\n", err);
        free(err);
        return false;
    }
    
    bool result = (value != NULL);
    if (value) {
        free(value);
    }
    return result;
}

// New function to show all blacklisted IPs
char** get_all_blacklisted_ips(int* count)
{
    if (!blacklist_initialized) {
        RTE_LOG(ERR, DB, "Blacklist not initialized\n");
        *count = 0;
        return NULL;
    }

    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, readoptions);
    rocksdb_iter_seek_to_first(iter);

    // Count the number of entries
    int num_entries = 0;
    while (rocksdb_iter_valid(iter)) {
        num_entries++;
        rocksdb_iter_next(iter);
    }

    // Allocate memory for the array of IP strings
    char** ip_list = (char**)malloc(num_entries * sizeof(char*));
    if (!ip_list) {
        RTE_LOG(ERR, DB, "Failed to allocate memory for IP list\n");
        rocksdb_iter_destroy(iter);
        *count = 0;
        return NULL;
    }

    // Reset iterator and populate the array
    rocksdb_iter_seek_to_first(iter);
    int index = 0;
    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        ip_list[index] = strndup(key, key_len);
        index++;
        rocksdb_iter_next(iter);
    }

    rocksdb_iter_destroy(iter);
    *count = num_entries;
    return ip_list;
}

void close_blacklist(void)
{
    if (blacklist_initialized) {
        rocksdb_close(db);
        rocksdb_options_destroy(options);
        rocksdb_writeoptions_destroy(writeoptions);
        rocksdb_readoptions_destroy(readoptions);
        blacklist_initialized = false;
    }
}

