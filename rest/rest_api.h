#ifndef REST_API_H
#define REST_API_H

#include "../mongoose.h"

// Define the structure to pass to the thread
struct thread_data {
    struct mg_mgr *mgr;
    const char *listen_addr;
};

// Function prototypes
void *run_mongoose(void *arg);
void init_rest_api(const char *listen_addr);
void cleanup_rest_api(void);

#endif // REST_API_H
