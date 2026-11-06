#ifndef SESSION_H
#define SESSION_H

#include "packet.h"

struct session {
    int fd;
    struct channel tx;
    struct channel rx;
};

/* The TLS connection stays open for the lifetime of the packet keys. */
int session_open(struct session *session, int device, const char *local_ip,
                 const char *peer_ip, uint16_t port, const char *ca,
                 const char *cert, const char *key);

#endif
