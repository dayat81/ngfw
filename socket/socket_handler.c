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
#include "../counter/counter_handler.h"
#include <rte_log.h>
#include <ctype.h>
#include "../blacklist/blacklist_handler.h"

#define PORT 8080
#define BUFFER_SIZE 1024

extern volatile bool force_quit;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

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

        int valread = read(new_socket, buffer, BUFFER_SIZE);
        RTE_LOG(INFO, L2FWD, "Received command: %s\n", buffer);

        // Process the command only if it's "get_traffic_data"
        // Remove newline character if present
        buffer[strcspn(buffer, "\n")] = 0;
        
        // Trim leading and trailing whitespace
        char *trimmed_buffer = buffer;
        while (isspace(*trimmed_buffer)) trimmed_buffer++;
        char *end = trimmed_buffer + strlen(trimmed_buffer) - 1;
        while (end > trimmed_buffer && isspace(*end)) end--;
        *(end + 1) = 0;

        if (strcmp(trimmed_buffer, "get_traffic_data") == 0) {
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
        } else if (strncmp(trimmed_buffer, "blacklist ", 10) == 0) {
            char *ip = trimmed_buffer + 10;
            if (add_to_blacklist(ip) == 0) {
                snprintf(response, BUFFER_SIZE, "IP %s added to blacklist", ip);
            } else {
                snprintf(response, BUFFER_SIZE, "Failed to add IP %s to blacklist", ip);
            }
            send(new_socket, response, strlen(response), 0);
        } else if (strncmp(trimmed_buffer, "unblacklist ", 12) == 0) {
            char *ip = trimmed_buffer + 12;
            if (remove_from_blacklist(ip) == 0) {
                snprintf(response, BUFFER_SIZE, "IP %s removed from blacklist", ip);
            } else {
                snprintf(response, BUFFER_SIZE, "Failed to remove IP %s from blacklist", ip);
            }
            send(new_socket, response, strlen(response), 0);
        } else if (strncmp(trimmed_buffer, "check_blacklist ", 16) == 0) {
            char *ip = trimmed_buffer + 16;
            if (is_ip_blacklisted(ip)) {
                snprintf(response, BUFFER_SIZE, "IP %s is blacklisted", ip);
            } else {
                snprintf(response, BUFFER_SIZE, "IP %s is not blacklisted", ip);
            }
            send(new_socket, response, strlen(response), 0);
        } else if (strcmp(trimmed_buffer, "show_blacklist") == 0) {
            int count;
            char **blacklisted_ips = get_all_blacklisted_ips(&count);
            
            if (blacklisted_ips == NULL) {
                snprintf(response, BUFFER_SIZE, "Error retrieving blacklisted IPs");
            } else if (count == 0) {
                snprintf(response, BUFFER_SIZE, "No IPs are currently blacklisted");
            } else {
                int written = snprintf(response, BUFFER_SIZE, "Blacklisted IPs:\n");
                for (int i = 0; i < count && written < BUFFER_SIZE; i++) {
                    written += snprintf(response + written, BUFFER_SIZE - written, "%s\n", blacklisted_ips[i]);
                    free(blacklisted_ips[i]);
                }
                free(blacklisted_ips);
            }
            send(new_socket, response, strlen(response), 0);
        } else {
            snprintf(response, BUFFER_SIZE, "Unknown command. Available commands:\n"
                                            "- get_traffic_data\n"
                                            "- blacklist <ip>\n"
                                            "- unblacklist <ip>\n"
                                            "- check_blacklist <ip>\n"
                                            "- show_blacklist");
            send(new_socket, response, strlen(response), 0);
        }
        close(new_socket);
    }

    // Option 1: If you meant to call close_blacklist()
    close_blacklist();

 

    close(server_fd);
    return NULL;
}
