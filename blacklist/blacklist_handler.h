#ifndef BLACKLIST_HANDLER_H
#define BLACKLIST_HANDLER_H

#include <stdbool.h>


int init_blacklist_db(void);

bool is_ip_blacklisted(const char *ip);
void close_blacklist_db(void);


#endif // BLACKLIST_HANDLER_H
