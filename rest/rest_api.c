#include "rest_api.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

static struct mg_mgr mgr;
static pthread_t mongoose_thread;
static volatile bool force_quit = false;

// Function to handle HTTP requests
static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_match(hm->uri, mg_str("/api/stats"), NULL)) {
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                          "{\"temperature\":22,\"humidity\":60}\n");
        } else {
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
