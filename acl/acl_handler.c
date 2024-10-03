#include "acl_handler.h"
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_tcp.h>  // Add this line to include the TCP header definition

struct rte_acl_ctx *acl_ctx;

static struct rte_acl_field_def ipv4_defs[] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = offsetof(struct rte_ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 1,
        .input_index = 1,
        .offset = offsetof(struct rte_ipv4_hdr, src_addr),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = 2,
        .input_index = 2,
        .offset = offsetof(struct rte_ipv4_hdr, dst_addr),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset = sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_tcp_hdr, src_port),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = 4,
        .input_index = 3,
        .offset = sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_tcp_hdr, dst_port),
    },
};

#define MAX_RULES 1024
struct rte_acl_rule stored_rules[MAX_RULES];
int stored_rule_count = 0;

int init_acl(void)
{
    acl_ctx = rte_acl_create(&(struct rte_acl_param){
        .name = "ACL Context",
        .socket_id = rte_socket_id(),
        .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
        .max_rule_num = MAX_ACL_RULES,
    });
    if (acl_ctx == NULL) {
        RTE_LOG(ERR, ACL, "Failed to create ACL context\n");
        return -1;
    }
    return 0;
}

int load_acl_rules(const char *filename)
{
    FILE *f;
    char buf[1024];
    struct rte_acl_rule rule;
    int rule_cnt = 0;

    f = fopen(filename, "r");
    if (f == NULL) {
        RTE_LOG(ERR, ACL, "Failed to open ACL rules file %s\n", filename);
        return -1;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (buf[0] == '#' || buf[0] == '\n')
            continue;

        if (rule_cnt >= MAX_ACL_RULES)
            break;

        memset(&rule, 0, sizeof(rule));

        uint8_t src_ip[4], dst_ip[4];
        uint8_t src_mask, dst_mask, proto, proto_mask;
        uint16_t sport_low, sport_high, dport_low, dport_high;

        if (sscanf(buf, "@%hhu.%hhu.%hhu.%hhu/%hhu %hhu.%hhu.%hhu.%hhu/%hhu %hu : %hu %hu : %hu %hhu/%hhu",
                   &src_ip[0], &src_ip[1], &src_ip[2], &src_ip[3], &src_mask,
                   &dst_ip[0], &dst_ip[1], &dst_ip[2], &dst_ip[3], &dst_mask,
                   &sport_low, &sport_high, &dport_low, &dport_high,
                   &proto, &proto_mask) != 16) {
            RTE_LOG(ERR, ACL, "Failed to parse ACL rule: %s\n", buf);
            continue;
        }

        rule.field[0].value.u8 = proto;
        rule.field[0].mask_range.u8 = proto_mask;
        rule.field[1].value.u32 = RTE_IPV4(src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        rule.field[1].mask_range.u32 = src_mask;
        rule.field[2].value.u32 = RTE_IPV4(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
        rule.field[2].mask_range.u32 = dst_mask;
        rule.field[3].value.u16 = sport_low;
        rule.field[3].mask_range.u16 = sport_high;
        rule.field[4].value.u16 = dport_low;
        rule.field[4].mask_range.u16 = dport_high;

        rule.data.category_mask = 1;
        rule.data.priority = MAX_ACL_RULES - rule_cnt;
        rule.data.userdata = rule_cnt + 1;

        if (rte_acl_add_rules(acl_ctx, &rule, 1) != 0) {
            RTE_LOG(ERR, ACL, "Failed to add ACL rule\n");
        } else {
            rule_cnt++;
            if (stored_rule_count < MAX_RULES) {
                stored_rules[stored_rule_count++] = rule;  // Store the rule
            }
            print_rule_fields(&rule);  // Print the rule fields
        }
    }

    fclose(f);

    struct rte_acl_config acl_config;
    memset(&acl_config, 0, sizeof(acl_config));
    acl_config.num_categories = 1;
    acl_config.num_fields = RTE_DIM(ipv4_defs);
    memcpy(&acl_config.defs, ipv4_defs, sizeof(ipv4_defs));
    if (rte_acl_build(acl_ctx, &acl_config) != 0) {
        RTE_LOG(ERR, ACL, "Failed to build ACL trie\n");
        return -1;
    }

    return rule_cnt;
}

// Function to retrieve a stored rule by index
struct rte_acl_rule *get_stored_rule(int index) {
    if (index < 0 || index >= stored_rule_count) {
        return NULL;  // Invalid index
    }
    return &stored_rules[index];
}

void cleanup_acl(void)
{
    if (acl_ctx != NULL) {
        rte_acl_free(acl_ctx);
        acl_ctx = NULL;
    }
}

void print_rule_fields(const struct rte_acl_rule *rule) {
    uint32_t src_ip = rule->field[1].value.u32;
    uint32_t dst_ip = rule->field[2].value.u32;

    printf("Protocol: %u/%u\n", rule->field[0].value.u8, rule->field[0].mask_range.u8);
    printf("Source IP: %u.%u.%u.%u/%u\n",
           (src_ip >> 24) & 0xFF,
           (src_ip >> 16) & 0xFF,
           (src_ip >> 8) & 0xFF,
           src_ip & 0xFF,
           rule->field[1].mask_range.u32);
    printf("Destination IP: %u.%u.%u.%u/%u\n",
           (dst_ip >> 24) & 0xFF,
           (dst_ip >> 16) & 0xFF,
           (dst_ip >> 8) & 0xFF,
           dst_ip & 0xFF,
           rule->field[2].mask_range.u32);
    printf("Source Port: %u-%u\n", rule->field[3].value.u16, rule->field[3].mask_range.u16);
    printf("Destination Port: %u-%u\n", rule->field[4].value.u16, rule->field[4].mask_range.u16);
}
