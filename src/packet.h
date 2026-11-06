#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>

enum { TAG_SIZE = 16, KEY_SIZE = 32, WINDOW = 64, MAX_FRAME = 14 + 65535 };
/* A conservative lifetime limit per directional key. Restart both peers to rekey. */
#define PACKET_LIMIT (UINT64_C(1) << 24)

struct channel {
    uint8_t key[KEY_SIZE];
    uint32_t direction;
    uint64_t sent;
    uint64_t highest;
    uint64_t seen;
};

struct policy {
    uint8_t pc[2][4];
    uint16_t port;
};

enum frame_result { DROP, ARP, PROTECTED, REJECT };

/* All indices are in PC1 -> PC2 order. Returns the exact outgoing frame length. */
enum frame_result transform(uint8_t *frame, size_t *len, size_t out_mtu,
                            const struct policy *policy, unsigned source,
                            int encrypt, struct channel *channel);

#endif
