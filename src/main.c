#include "packet.h"
#include "session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct link {
    int fd;
    size_t mtu;
    struct sockaddr_ll addr;
};

static volatile sig_atomic_t stopping;

static void stop(int sig)
{
    (void)sig;
    stopping = 1;
}

static int link_open(struct link *link, const char *name)
{
    struct ifreq req = {0};
    if (strlen(name) >= sizeof req.ifr_name)
        return -1;
    strcpy(req.ifr_name, name);
    unsigned index = if_nametoindex(name);
    if (!index)
        return -1;
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;
    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)index
    };
    struct packet_mreq membership = {
        .mr_ifindex = (int)index, .mr_type = PACKET_MR_PROMISC
    };
    if (ioctl(fd, SIOCGIFMTU, &req) || req.ifr_mtu < 68 ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) ||
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &membership, sizeof membership)) {
        close(fd);
        return -1;
    }
    *link = (struct link){ .fd = fd, .mtu = (size_t)req.ifr_mtu, .addr = addr };
    return 0;
}

static uint16_t port_number(const char *arg)
{
    char *end;
    unsigned long value = strtoul(arg, &end, 10);
    return end != arg && !*end && value <= 65535 ? (uint16_t)value : 0;
}

static int run(const struct link links[2], struct session *session,
               const struct policy *policy, int device)
{
    struct pollfd wait[] = {
        { .fd = links[0].fd, .events = POLLIN },
        { .fd = links[1].fd, .events = POLLIN },
        { .fd = session->fd, .events = POLLIN }
    };
    unsigned long encrypted = 0, decrypted = 0, rejected = 0, send_errors = 0;
    uint8_t frame[MAX_FRAME];
    int status = 0;
    while (!stopping) {
        if (poll(wait, 3, 500) < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            status = 1;
            break;
        }
        if (wait[2].revents) {
            fprintf(stderr, "Control connection ended. Restart both devices for fresh keys.\n");
            break;
        }
        if ((wait[0].revents | wait[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "Packet interface error\n");
            status = 1;
            break;
        }
        for (unsigned i = 0; i < 2; ++i) {
            if (!(wait[i].revents & POLLIN))
                continue;
            struct sockaddr_ll incoming;
            socklen_t addrlen = sizeof incoming;
            ssize_t n = recvfrom(links[i].fd, frame, sizeof frame, MSG_TRUNC,
                                 (struct sockaddr *)&incoming, &addrlen);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                perror("recvfrom");
                return 1;
            }
            if (incoming.sll_pkttype == PACKET_OUTGOING || (size_t)n > sizeof frame)
                continue;
            size_t len = (size_t)n;
            const unsigned source = i == 0 ? (unsigned)(device - 1) : (unsigned)(2 - device);
            const struct link *out = &links[1 - i];
            enum frame_result result = transform(frame, &len, out->mtu, policy, source,
                                                 i == 0, i == 0 ? &session->tx : &session->rx);
            if (result == REJECT)
                ++rejected;
            if (result != ARP && result != PROTECTED)
                continue;

            /* Fill Ethernet padding with zeroes so no stale bytes can leak. */
            if (len < ETH_ZLEN) {
                memset(frame + len, 0, ETH_ZLEN - len);
                len = ETH_ZLEN;
            }
            struct sockaddr_ll target = out->addr;
            target.sll_protocol = htons((uint16_t)((frame[12] << 8) | frame[13]));
            target.sll_halen = ETH_ALEN;
            memcpy(target.sll_addr, frame, ETH_ALEN);
            if (sendto(out->fd, frame, len, MSG_DONTWAIT,
                       (struct sockaddr *)&target, sizeof target) != (ssize_t)len) {
                if (++send_errors == 1)
                    perror("sendto");
                continue;
            }
            if (result == PROTECTED) {
                if (i == 0)
                    ++encrypted;
                else
                    ++decrypted;
            }
        }
        if (session->tx.sent == PACKET_LIMIT) {
            fprintf(stderr, "Key lifetime reached. Restart both devices for fresh keys.\n");
            break;
        }
    }
    fprintf(stderr, "Encrypted=%lu Decrypted=%lu Rejected=%lu SendErrors=%lu\n",
            encrypted, decrypted, rejected, send_errors);
    return status;
}

int main(int argc, char **argv)
{
    if (argc != 12 || (strcmp(argv[1], "1") && strcmp(argv[1], "2"))) {
        fprintf(stderr, "Usage: %s DEVICE LAN_IF TRANSIT_IF LOCAL_CTL_IP PEER_CTL_IP "
                "CTL_PORT PC1_IP PC2_IP SERVICE_PORT CA_PEM DEVICE_PEM\n"
                "DEVICE_PEM contains the device certificate and its private key.\n", argv[0]);
        return 2;
    }

    const int device = argv[1][0] - '0';
    struct policy policy = { .port = port_number(argv[9]) };
    const uint16_t control_port = port_number(argv[6]);
    struct in_addr local, peer;
    if (!policy.port || !control_port || !strcmp(argv[2], argv[3]) ||
        inet_pton(AF_INET, argv[4], &local) != 1 ||
        inet_pton(AF_INET, argv[5], &peer) != 1 || local.s_addr == peer.s_addr ||
        inet_pton(AF_INET, argv[7], policy.pc[0]) != 1 ||
        inet_pton(AF_INET, argv[8], policy.pc[1]) != 1 ||
        !memcmp(policy.pc[0], policy.pc[1], 4) ||
        !memcmp(policy.pc[0], &local, 4) || !memcmp(policy.pc[1], &local, 4) ||
        !memcmp(policy.pc[0], &peer, 4) || !memcmp(policy.pc[1], &peer, 4)) {
        fprintf(stderr, "Invalid interface, IPv4 address or port configuration\n");
        return 2;
    }

    struct sigaction stop_action = { .sa_handler = stop };
    sigemptyset(&stop_action.sa_mask);
    sigaction(SIGINT, &stop_action, NULL);
    sigaction(SIGTERM, &stop_action, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct link links[2];
    if (link_open(&links[0], argv[2])) {
        perror(argv[2]);
        return 1;
    }
    if (link_open(&links[1], argv[3])) {
        perror(argv[3]);
        close(links[0].fd);
        return 1;
    }

    int status = 1;
    struct session session;
    if (links[1].mtu < links[0].mtu + TAG_SIZE) {
        fprintf(stderr, "Transit MTU must exceed LAN MTU by at least 16 bytes\n");
    } else if (session_open(&session, device, argv[4], argv[5], control_port,
                            argv[10], argv[11], argv[11])) {
        fprintf(stderr, "Secure session failed\n");
    } else {
        fprintf(stderr, "Device%d ready (mutual TLS 1.3 / X25519)\n", device);
        status = run(links, &session, &policy, device);
        close(session.fd);
        OPENSSL_cleanse(&session, sizeof session);
    }
    close(links[0].fd);
    close(links[1].fd);
    return status;
}
