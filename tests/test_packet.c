#include "packet.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const struct policy policy = { .pc = {{10, 0, 0, 1}, {10, 0, 0, 2}}, .port = 8080 };

static unsigned word(const uint8_t *p)
{
    return 256u * p[0] + p[1];
}

static unsigned sum(const uint8_t *p, size_t len, unsigned initial)
{
    for (size_t i = 0; i < len; ++i)
        initial += i % 2 ? p[i] : 256u * p[i];
    while (initial > 65535)
        initial = initial % 65536 + initial / 65536;
    return initial;
}

static void set_word(uint8_t *p, unsigned w)
{
    p[0] = (uint8_t)(w >> 8);
    p[1] = (uint8_t)w;
}

static size_t fixture(uint8_t *f, unsigned source, size_t payload)
{
    const size_t ihl = 24, thl = 24, tcp_len = thl + payload;
    const size_t total = ihl + tcp_len;
    memset(f, 0, MAX_FRAME);
    f[0] = 2;
    f[6] = 4;
    f[12] = 8;
    uint8_t *ip = f + 14, *tcp = ip + ihl;
    ip[0] = 0x46;
    set_word(ip + 2, (unsigned)total);
    ip[4] = 99;
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    memcpy(ip + 12, policy.pc[source], 4);
    memcpy(ip + 16, policy.pc[1 - source], 4);
    ip[20] = 1; /* IPv4 NOP option */
    set_word(tcp, source ? 8080 : 43210);
    set_word(tcp + 2, source ? 43210 : 8080);
    tcp[7] = 17;
    tcp[12] = 0x60;
    tcp[13] = payload ? 0x18 : 0x10;
    tcp[14] = 32;
    tcp[20] = 1; /* TCP NOP option */
    for (size_t i = 0; i < payload; ++i)
        tcp[thl + i] = (uint8_t)(i + 29);
    set_word(ip + 10, 65535 - sum(ip, ihl, 0));
    set_word(tcp + 16, 65535 - sum(tcp, tcp_len, sum(ip + 12, 8, 6 + (unsigned)tcp_len)));
    return 14 + total;
}

static void roundtrip(unsigned source, size_t payload)
{
    uint8_t original[MAX_FRAME], first[MAX_FRAME], second[MAX_FRAME], altered[MAX_FRAME];
    const size_t length = fixture(original, source, payload);
    struct channel tx = { .key = {7}, .direction = source + 1 }, rx = tx;
    memcpy(first, original, length);
    memcpy(second, original, length);
    size_t one = length, two = length;
    assert(transform(first, &one, 1500, &policy, source, 1, &tx) == PROTECTED);
    assert(transform(second, &two, 1500, &policy, source, 1, &tx) == PROTECTED);
    assert(one == length + TAG_SIZE && two == one && tx.sent == 2);
    assert(memcmp(first + length, second + length, TAG_SIZE)); /* exact TCP retransmission */
    if (payload)
        assert(memcmp(first + 62, original + 62, payload));
    assert(word(first + 16) == one - 14);
    assert(sum(first + 14, 24, 0) == 65535);
    assert(sum(first + 38, one - 38, sum(first + 26, 8, 6 + (unsigned)(one - 38))) == 65535);

    /* Tamper with tag, then with a TCP sequence number, then with ciphertext. */
    const size_t targets[] = {one - 1, 38 + 7, payload ? 62u : one - 1};
    for (unsigned i = 0; i < sizeof targets / sizeof targets[0]; ++i) {
        memcpy(altered, second, two);
        altered[targets[i]] ^= 1;
        size_t tampered = two;
        assert(transform(altered, &tampered, 1484, &policy, source, 0, &rx) == REJECT);
        assert(tampered == two && rx.highest == 0 && rx.seen == 0);
    }

    memcpy(altered, second, two);
    assert(transform(second, &two, 1484, &policy, source, 0, &rx) == PROTECTED);
    assert(two == length && !memcmp(second, original, length));
    assert(transform(first, &one, 1484, &policy, source, 0, &rx) == PROTECTED);
    assert(one == length && !memcmp(first, original, length));
    two += TAG_SIZE;
    assert(transform(altered, &two, 1484, &policy, source, 0, &rx) == REJECT);
}

int main(void)
{
    roundtrip(0, 0);
    roundtrip(1, 1);
    roundtrip(0, 47);
    roundtrip(1, 1436); /* fills the 1500-byte transit MTU exactly */

    uint8_t frame[MAX_FRAME];
    struct channel tx = { .key = {7}, .direction = 1 }, rx = tx;
    size_t len = fixture(frame, 0, 1437);
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == REJECT && !tx.sent);
    len = fixture(frame, 0, 7);
    frame[20] |= 0x20;
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == DROP);
    len = fixture(frame, 0, 7);
    --len;
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == DROP);
    len = fixture(frame, 0, 7);
    frame[40] = 0;
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == DROP);
    len = fixture(frame, 0, 7);
    assert(transform(frame, &len, 1500, &policy, 0, 0, &rx) == REJECT);

    tx.sent = WINDOW - 1;
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == PROTECTED);
    assert(transform(frame, &len, 1484, &policy, 0, 0, &rx) == PROTECTED);
    assert(rx.highest == WINDOW);
    tx.sent += WINDOW;
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == PROTECTED);
    assert(transform(frame, &len, 1484, &policy, 0, 0, &rx) == REJECT);
    assert(rx.highest == WINDOW);
    tx.sent = PACKET_LIMIT;
    assert(transform(frame, &len, 1500, &policy, 0, 1, &tx) == REJECT);
    puts("PASS packet transforms, checksums, MTU, replay, reordering and tamper rejection");
}
