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
    acl_param.rule_size = RTE_ACL_RULE_SZ(1);  // Only one field (IP address)
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
    struct rte_acl_field_def field_defs[1];
    field_defs[0].type = RTE_ACL_FIELD_TYPE_MASK;
    field_defs[0].size = sizeof(uint32_t);
    field_defs[0].field_index = 0;
    field_defs[0].input_index = 0;
    field_defs[0].offset = 0;  // Offset for the IP field in the input data

    memcpy(acl_config.defs, field_defs, sizeof(field_defs));

    if (rte_acl_set_ctx_classify(acl_ctx, RTE_ACL_CLASSIFY_DEFAULT) != 0) {
        RTE_LOG(ERR, DB, "Failed to set ACL classify method\n");
        rte_acl_free(acl_ctx);
        acl_ctx = NULL;
        return -1;
    }

    RTE_LOG(INFO, DB, "ACL context created and configured successfully\n");
    return 0;
}



int add_ip_to_acl_blacklist(const struct ipv4_5tuple *tuple) {
    if (init_acl_context() != 0) {
        return -1;
    }

    RTE_ACL_RULE_DEF(acl_rule, 5);
    struct acl_rule rule;
    memset(&rule, 0, sizeof(rule));

    // Set up the rule data
    rule.data.userdata = 1;  // Mark as blacklisted
    rule.data.category_mask = 1;  // Use only the first category
    rule.data.priority = 1;  // All blacklist entries have the same priority

    // Set up the fields
    // Field 0: Protocol
    rule.field[0].value.u8 = tuple->proto;
    rule.field[0].mask_range.u8 = 0xff;  // Exact match

    // Field 1: Source IP
    rule.field[1].value.u32 = tuple->ip_src;
    rule.field[1].mask_range.u32 = 32;  // Exact match (/32 subnet)

    // Field 2: Destination IP
    rule.field[2].value.u32 = tuple->ip_dst;
    rule.field[2].mask_range.u32 = 32;  // Exact match (/32 subnet)

    // Field 3: Source port
    rule.field[3].value.u16 = tuple->port_src;
    rule.field[3].mask_range.u16 = 0xffff;  // Exact match

    // Field 4: Destination port
    rule.field[4].value.u16 = tuple->port_dst;
    rule.field[4].mask_range.u16 = 0xffff;  // Exact match

    // Add the rule
    if (rte_acl_add_rules(acl_ctx, (struct rte_acl_rule *)&rule, 1) != 0) {
        RTE_LOG(ERR, DB, "Failed to add ACL rule for 5-tuple\n");
        return -1;
    }

    // Prepare AC build config
    struct rte_acl_config acl_build_param;
    memset(&acl_build_param, 0, sizeof(acl_build_param));
    acl_build_param.num_categories = 1;
    acl_build_param.num_fields = 5;

    // Set up the field definitions
    struct rte_acl_field_def field_defs[5] = {
        // Proto field
        {
            .type = RTE_ACL_FIELD_TYPE_BITMASK,
            .size = sizeof(uint8_t),
            .field_index = 0,
            .input_index = 0,
            .offset = offsetof(struct ipv4_5tuple, proto),
        },
        // Source IP field
        {
            .type = RTE_ACL_FIELD_TYPE_MASK,
            .size = sizeof(uint32_t),
            .field_index = 1,
            .input_index = 1,
            .offset = offsetof(struct ipv4_5tuple, ip_src),
        },
        // Destination IP field
        {
            .type = RTE_ACL_FIELD_TYPE_MASK,
            .size = sizeof(uint32_t),
            .field_index = 2,
            .input_index = 2,
            .offset = offsetof(struct ipv4_5tuple, ip_dst),
        },
        // Source port field
        {
            .type = RTE_ACL_FIELD_TYPE_RANGE,
            .size = sizeof(uint16_t),
            .field_index = 3,
            .input_index = 3,
            .offset = offsetof(struct ipv4_5tuple, port_src),
        },
        // Destination port field
        {
            .type = RTE_ACL_FIELD_TYPE_RANGE,
            .size = sizeof(uint16_t),
            .field_index = 4,
            .input_index = 3,
            .offset = offsetof(struct ipv4_5tuple, port_dst),
        },
    };

    memcpy(&acl_build_param.defs, field_defs, sizeof(field_defs));

    // Build the runtime structures for added rules
    if (rte_acl_build(acl_ctx, &acl_build_param) != 0) {
        RTE_LOG(ERR, DB, "Failed to build ACL context\n");
        return -1;
    }

    RTE_LOG(INFO, DB, "Added 5-tuple to ACL blacklist successfully\n");
    return 0;
}

// New function to check if IP is in ACL blacklist
bool is_ip_in_acl_blacklist(const struct ipv4_5tuple *tuple) {
    if (acl_ctx == NULL) {
        RTE_LOG(ERR, DB, "ACL context not initialized\n");
        return false;
    }

    if (tuple == NULL) {
        RTE_LOG(ERR, DB, "Invalid input: tuple is NULL\n");
        return false;
    }

    uint32_t result = 0;
    const uint8_t *data_to_check[1] = { (const uint8_t *)tuple };
    RTE_LOG(DEBUG, DB, "Checking 5-tuple: proto=%u, src_ip=%u, dst_ip=%u, src_port=%u, dst_port=%u\n",
            tuple->proto, tuple->ip_src, tuple->ip_dst, tuple->port_src, tuple->port_dst);

    if (rte_acl_classify(acl_ctx, data_to_check, &result, 1, 1) != 0) {
        RTE_LOG(ERR, DB, "ACL classification failed for 5-tuple\n");
        return false;
    }

    return (result != 0);
}

// New function to close ACL context
void close_acl_context() {
    if (acl_ctx != NULL) {
        rte_acl_free(acl_ctx);
        acl_ctx = NULL;
    }
}



