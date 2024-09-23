#include "blacklist_handler.h"
#include <string.h>
#include <arpa/inet.h>
#include <rte_log.h>
#include <rocksdb/c.h>
#include <stdio.h>
#include <rte_acl.h>

// Add this line
#define RTE_LOGTYPE_DB RTE_LOGTYPE_USER1

static rocksdb_t *db = NULL;
static rocksdb_options_t *options = NULL;
static rocksdb_readoptions_t *readoptions = NULL;

#define MAX_ACL_RULES 1000000
#define IPV4_ADDR_SIZE 4

static struct rte_acl_ctx *acl_ctx = NULL;

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

// New function to initialize ACL context
int init_acl_context() {
    RTE_LOG(DEBUG, DB, "Entering init_acl_context()\n");

    if (acl_ctx != NULL) {
        RTE_LOG(INFO, DB, "ACL context already initialized\n");
        return 0;  // Already initialized
    }

    RTE_LOG(DEBUG, DB, "Initializing acl_param\n");
    struct rte_acl_param acl_param;
    memset(&acl_param, 0, sizeof(acl_param));
    acl_param.name = "ACL_Context";
    acl_param.socket_id = SOCKET_ID_ANY;
    acl_param.rule_size = RTE_ACL_RULE_SZ(1);
    acl_param.max_rule_num = MAX_ACL_RULES;

    RTE_LOG(INFO, DB, "Creating ACL context\n");
    acl_ctx = rte_acl_create(&acl_param);
    if (acl_ctx == NULL) {
        RTE_LOG(ERR, DB, "Failed to create ACL context. rte_errno: %d (%s)\n", 
                rte_errno, rte_strerror(rte_errno));
        return -1;
    }
    RTE_LOG(DEBUG, DB, "ACL context created successfully\n");

    RTE_LOG(DEBUG, DB, "Initializing acl_config\n");
    struct rte_acl_config acl_config;
    memset(&acl_config, 0, sizeof(acl_config));
    acl_config.num_categories = 1;
    acl_config.num_fields = 1;

    RTE_LOG(DEBUG, DB, "Configuring IP field\n");
    struct rte_acl_field_def field;
    field.type = RTE_ACL_FIELD_TYPE_MASK;
    field.size = sizeof(uint32_t);
    field.field_index = 0;
    field.input_index = 0;
    acl_config.num_fields = 1;
    //acl_config.defs = field; // Changed from &field to field

    if (rte_acl_set_ctx_classify(acl_ctx, RTE_ACL_CLASSIFY_DEFAULT) != 0) {
        RTE_LOG(ERR, DB, "Failed to set ACL classify method\n");
        rte_acl_free(acl_ctx);
        acl_ctx = NULL;
        return -1;
    }

    RTE_LOG(INFO, DB, "ACL context created and configured successfully\n");
    return 0;
}

// New function to add IP to ACL blacklist
int add_ip_to_acl_blacklist(const char *ip) {
    if (init_acl_context() != 0) {
        return -1;
    }

    struct rte_acl_rule_data rule_data;
    struct rte_acl_field fields[1];
    memset(&rule_data, 0, sizeof(rule_data));
    memset(fields, 0, sizeof(fields));

    // Convert IP string to network byte order
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        RTE_LOG(ERR, DB, "Invalid IP address: %s\n", ip);
        return -1;
    }

    // Set up the rule data
    rule_data.category_mask = 1;
    rule_data.priority = 1;
    rule_data.userdata = 1;  // Mark as blacklisted

    // Set up the IP field
    fields[0].value.u32 = addr.s_addr;
    fields[0].mask_range.u32 = 0xFFFFFFFF;  // Exact match

    // Add the rule
    if (rte_acl_add_rules(acl_ctx, (struct rte_acl_rule *)fields, 1) != 0) {
        RTE_LOG(ERR, DB, "Failed to add ACL rule for IP: %s\n", ip);
        return -1;
    }

    // Build the ACL trie
    struct rte_acl_config acl_config;
    if (rte_acl_build(acl_ctx, &acl_config) != 0) {
        RTE_LOG(ERR, DB, "Failed to build ACL trie\n");
        return -1;
    }

    RTE_LOG(INFO, DB, "Added IP %s to ACL blacklist successfully\n", ip);
    return 0;
}

// New function to check if IP is in ACL blacklist
bool is_ip_in_acl_blacklist(const char *ip) {
    if (acl_ctx == NULL) {
        RTE_LOG(ERR, DB, "ACL context not initialized\n");
        return false;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        RTE_LOG(ERR, DB, "Invalid IP address: %s\n", ip);
        return false;
    }

    uint32_t results[1];
    const uint8_t *data_to_check = (const uint8_t *)&addr.s_addr;

    if (rte_acl_classify(acl_ctx, &data_to_check, results, 1, 1) != 0) {
        RTE_LOG(ERR, DB, "ACL classification failed for IP: %s\n", ip);
        return false;
    }

    return (results[0] != 0);
}

// New function to close ACL context
void close_acl_context() {
    if (acl_ctx != NULL) {
        rte_acl_free(acl_ctx);
        acl_ctx = NULL;
    }
}



