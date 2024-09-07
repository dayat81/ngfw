#include "blacklist_handler.h"
#include <string.h>
#include <arpa/inet.h>
#include <rte_log.h>
#include <rocksdb/c.h>
#include <stdio.h>

// Add this line
#define RTE_LOGTYPE_DB RTE_LOGTYPE_USER1

static rocksdb_t *db = NULL;
static rocksdb_options_t *options = NULL;
static rocksdb_readoptions_t *readoptions = NULL;

 int init_blacklist_db() {
    if (db != NULL) {
        return 0;  // Already initialized
    }

    options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 0);  // Don't create if missing
    
    char *err = NULL;
    db = rocksdb_open_for_read_only(options, "/tmp/blacklist.db", 0, &err);  // Open in read-only mode
    if (err != NULL) {
        RTE_LOG(ERR, DB, "Failed to open RocksDB in read-only mode: %s\n", err);
        free(err);
        return -1;
    }

    readoptions = rocksdb_readoptions_create();
    return 0;
}

 void close_blacklist_db() {
    if (db != NULL) {
        rocksdb_close(db);
        db = NULL;
    }
    if (options != NULL) {
        rocksdb_options_destroy(options);
        options = NULL;
    }
    if (readoptions != NULL) {
        rocksdb_readoptions_destroy(readoptions);
        readoptions = NULL;
    }
}

bool is_ip_blacklisted(const char *ip)
{
    if (!ip) {
        RTE_LOG(ERR, DB, "Invalid IP\n");
        return false;
    }

    if (init_blacklist_db() != 0) {
        return false;
    }

    // Check if IP is blacklisted
    size_t len;
    char *err = NULL;
    char *value = rocksdb_get(db, readoptions, ip, strlen(ip), &len, &err);
    if (err != NULL) {
        RTE_LOG(ERR, DB, "Failed to check IP in blacklist: %s\n", err);
        free(err);
        close_blacklist_db();
        return false;
    }
    
    bool result = (value != NULL);
    if (value) {
        free(value);
    }

    close_blacklist_db();
    return result;
}


