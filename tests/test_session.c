#include "session.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    assert(argc == 6);
    signal(SIGPIPE, SIG_IGN);
    const int device = atoi(argv[1]);
    struct session session;
    if (session_open(&session, device, "127.0.0.1", "127.0.0.1",
                     (uint16_t)atoi(argv[2]), argv[3], argv[4], argv[4]))
        return 1;
    assert(session.tx.direction == (uint32_t)device);
    assert(session.rx.direction == (uint32_t)(3 - device));
    assert(memcmp(session.tx.key, session.rx.key, KEY_SIZE));
    uint8_t context[KEY_SIZE * 2];
    memcpy(context, device == 1 ? session.tx.key : session.rx.key, KEY_SIZE);
    memcpy(context + KEY_SIZE, device == 1 ? session.rx.key : session.tx.key, KEY_SIZE);
    /* Temporary output only for the loopback test. Production never exports files. */
    FILE *out = fopen(argv[5], "wb");
    assert(out);
    assert(fwrite(context, sizeof context, 1, out) == 1);
    assert(fclose(out) == 0);
    close(session.fd);
}
