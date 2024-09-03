#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include "socket_handler.h"
#include "../rocksdb/rocksdb_handler.h"

#define PORT 8080
#define BUFFER_SIZE 1024

extern volatile bool force_quit;

void *handle_socket_communication(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = {0};

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (!force_quit) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        // Process the command using the new command handler
        int count;
        TrafficData* data = read_all_traffic_data(&count);
        
        if (data == NULL) {
            snprintf(response, BUFFER_SIZE, "Error reading traffic data");
            send(new_socket, response, strlen(response), 0);
        } else {
            int offset = 0;
            while (offset < count) {
                int remaining = count - offset;
                int to_send = (remaining > BUFFER_SIZE / 50) ? BUFFER_SIZE / 50 : remaining;
                
                int written = 0;
                for (int i = 0; i < to_send && written < BUFFER_SIZE; i++) {
                    written += snprintf(response + written, BUFFER_SIZE - written, 
                                        "%s: %lu bytes\n", data[offset + i].ip_addr, data[offset + i].bytes);
                }
                
                int bytes_sent = send(new_socket, response, written, 0);
                if (bytes_sent < 0) {
                    perror("send");
                    break;
                }
                
                offset += to_send;
            }
            
            free(data);
        }
        close(new_socket);
    }

    close(server_fd);
    return NULL;
}
