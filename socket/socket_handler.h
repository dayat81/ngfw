#ifndef SOCKET_HANDLER_H
#define SOCKET_HANDLER_H

extern volatile bool force_quit;

void *handle_socket_communication(void *arg);

#endif // SOCKET_HANDLER_H
