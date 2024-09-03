#ifndef SOCKET_HANDLER_H
#define SOCKET_HANDLER_H

#include <stdbool.h>

extern volatile bool force_quit;

void *handle_socket_communication(void *arg);

// New function declarations for command handlers
void handle_get_traffic_data(int socket);
void handle_blacklist(int socket, const char *ip);
void handle_unblacklist(int socket, const char *ip);
void handle_check_blacklist(int socket, const char *ip);
void handle_show_blacklist(int socket);
void handle_unknown_command(int socket);

#endif // SOCKET_HANDLER_H
