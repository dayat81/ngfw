#include "rest_api.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../acl/acl_handler.h"
#include "../counter/counter_handler.h"

static struct mg_mgr mgr;
static pthread_t mongoose_thread;
static volatile bool force_quit = false;

// Helper to send JSON response
static void send_json_response(struct mg_connection *c, int status, const char *fmt, ...) {
    char *json = NULL;
    va_list ap;
    va_start(ap, fmt);
    vasprintf(&json, fmt, ap);
    va_end(ap);

    if (json) {
        mg_http_reply(c, status, "Content-Type: application/json\r\n", "%s\n", json);
        free(json);
    } else {
        mg_http_reply(c, 500, "", "Internal Server Error\n");
    }
}

// Function to handle HTTP requests
static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        
        if (mg_match(hm->uri, mg_str("/api/stats"), NULL)) {
            // Placeholder: Fetch real stats if available
            send_json_response(c, 200, "{\"status\": \"running\"}");
        } 
        else if (mg_match(hm->uri, mg_str("/api/blacklist"), NULL)) {
            if (mg_vcmp(&hm->method, "GET") == 0) {
                // List blacklist (simplified, just count for now or need iterator)
                int count = get_stored_rules_count(); // We might need a specific blacklist count
                send_json_response(c, 200, "{\"rules_count\": %d}", count);
            } else if (mg_vcmp(&hm->method, "POST") == 0) {
                char ip_str[32];
                if (mg_json_get_str(hm->body, "$.ip", ip_str, sizeof(ip_str)) > 0) {
                     // Create a block rule string
                    char rule[256];
                    snprintf(rule, sizeof(rule), "@0.0.0.0/0 %s/32 0 : 65535 0 : 65535 0/0", ip_str);
                    if (add_acl_rule_from_string(rule) == 0) {
                        // Also add reverse rule
                        snprintf(rule, sizeof(rule), "@%s/32 0.0.0.0/0 0 : 65535 0 : 65535 0/0", ip_str);
                        add_acl_rule_from_string(rule);
                        send_json_response(c, 200, "{\"status\": \"blocked\", \"ip\": \"%s\"}", ip_str);
                    } else {
                        send_json_response(c, 400, "{\"error\": \"Failed to add rule\"}");
                    }
                } else {
                    send_json_response(c, 400, "{\"error\": \"Missing 'ip' field\"}");
                }
            }
        }
        else if (mg_match(hm->uri, mg_str("/api/whitelist"), NULL)) {
             if (mg_vcmp(&hm->method, "POST") == 0) {
                char ip_str[32];
                if (mg_json_get_str(hm->body, "$.ip", ip_str, sizeof(ip_str)) > 0) {
                    // Implement whitelist logic (similar to blacklist but different ACL context or rule ID?)
                    // For now, assuming single ACL context, so 'whitelist' might mean 'unblacklist' or 'allow'
                    // For this NGFW, let's assume it adds an ALLOW rule with higher priority if possible, 
                    // or we might need to remove the block rule.
                    // Given the current simple ACL implementation, we'll just log it for now as "Not Implemented correctly yet"
                    send_json_response(c, 501, "{\"error\": \"Whitelist not fully implemented\"}");
                }
             }
        }
        else if (mg_match(hm->uri, mg_str("/api/icmp_data"), NULL)) {
             int count;
             ICMPData *data = read_icmp_packet_data(&count);
             if (data) {
                 // Construct JSON array
                 // Note: quick and dirty JSON construction
                 size_t size = count * 64 + 32;
                 char *json_arr = malloc(size);
                 strcpy(json_arr, "[");
                 for(int i=0; i<count; i++) {
                     char entry[64];
                     snprintf(entry, sizeof(entry), "{\"ip\": \"%s\", \"packets\": %llu}%s", 
                        data[i].ip_addr, data[i].packet_count, (i < count-1) ? "," : "");
                     strcat(json_arr, entry);
                 }
                 strcat(json_arr, "]");
                 
                 mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", json_arr);
                 free(json_arr);
                 free(data);
             } else {
                 send_json_response(c, 200, "[]");
             }
        }
        else {
            mg_http_reply(c, 404, "", "Not Found\n");
        }
    }
}

// Thread function to run Mongoose event loop
void *run_mongoose(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct mg_mgr *mgr = data->mgr;
    const char *listen_addr = data->listen_addr;

    mg_http_listen(mgr, listen_addr, fn, NULL);

    while (!force_quit) {
        mg_mgr_poll(mgr, 1000);  // Poll every 1000ms
    }

    mg_mgr_free(mgr);
    free(data);
    return NULL;
}

void init_rest_api(const char *listen_addr) {
    mg_mgr_init(&mgr);

    // Prepare thread data
    struct thread_data *data = malloc(sizeof(struct thread_data));
    data->mgr = &mgr;
    data->listen_addr = listen_addr;

    // Create and start the Mongoose thread
    if (pthread_create(&mongoose_thread, NULL, run_mongoose, data) != 0) {
        fprintf(stderr, "Failed to create Mongoose thread\n");
        exit(EXIT_FAILURE);
    }
}

void cleanup_rest_api(void) {
    force_quit = true;
    pthread_join(mongoose_thread, NULL);
}
