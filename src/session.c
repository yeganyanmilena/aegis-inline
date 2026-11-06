#include "session.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int control_socket(int device, const char *local, const char *peer, uint16_t port)
{
    struct sockaddr_in here = { .sin_family = AF_INET };
    struct sockaddr_in there = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (inet_pton(AF_INET, local, &here.sin_addr) != 1 ||
        inet_pton(AF_INET, peer, &there.sin_addr) != 1)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    if (device == 2)
        here.sin_port = htons(port);
    int reuse = 1;
    struct timeval timeout = { .tv_sec = 10 };
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
        bind(fd, (struct sockaddr *)&here, sizeof here))
        goto fail;
    if (device == 1) {
        if (connect(fd, (struct sockaddr *)&there, sizeof there))
            goto fail;
        return fd;
    }

    if (listen(fd, 1))
        goto fail;
    fprintf(stderr, "Device2 listening for TLS\n");
    struct sockaddr_in remote;
    socklen_t remote_len = sizeof remote;
    int peer_fd = accept(fd, (struct sockaddr *)&remote, &remote_len);
    if (peer_fd < 0)
        goto fail;
    close(fd);
    if (remote.sin_addr.s_addr != there.sin_addr.s_addr ||
        setsockopt(peer_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(peer_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout)) {
        close(peer_fd);
        return -1;
    }
    return peer_fd;

fail:
    perror("control socket");
    close(fd);
    return -1;
}

int session_open(struct session *session, int device, const char *local_ip,
                 const char *peer_ip, uint16_t port, const char *ca,
                 const char *cert, const char *key)
{
    static const char forward[] = "EXPORTER-aegis-inline-v1-device1-to-device2";
    static const char reverse[] = "EXPORTER-aegis-inline-v1-device2-to-device1";
    const char *tx_label = device == 1 ? forward : reverse;
    const char *rx_label = device == 1 ? reverse : forward;

    memset(session, 0, sizeof *session);
    session->fd = -1;
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *tls = NULL;
    int fd = -1, ok = 0;
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set1_groups_list(ctx, "X25519") ||
        !SSL_CTX_set_num_tickets(ctx, 0) ||
        !SSL_CTX_load_verify_locations(ctx, ca, NULL) ||
        !SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(ctx))
        goto done;
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    fd = control_socket(device, local_ip, peer_ip, port);
    tls = SSL_new(ctx);
    if (fd < 0 || !tls || !SSL_set_fd(tls, fd) ||
        !SSL_set1_host(tls, device == 1 ? "device2.aegis" : "device1.aegis"))
        goto done;
    if ((device == 1 ? SSL_connect(tls) : SSL_accept(tls)) != 1 ||
        SSL_get_verify_result(tls) != X509_V_OK ||
        SSL_get_negotiated_group(tls) != NID_X25519 ||
        !SSL_export_keying_material(tls, session->tx.key, KEY_SIZE, tx_label,
                                    strlen(tx_label), NULL, 0, 0) ||
        !SSL_export_keying_material(tls, session->rx.key, KEY_SIZE, rx_label,
                                    strlen(rx_label), NULL, 0, 0))
        goto done;

    /* Confirm the server accepted the client's TLS Finished and identity
       before the client can enable its data plane. */
    char ready = 'R';
    if (device == 2 ? SSL_write(tls, &ready, 1) != 1 :
        (SSL_read(tls, &ready, 1) != 1 || ready != 'R'))
        goto done;

    session->tx.direction = (uint32_t)device;
    session->rx.direction = (uint32_t)(3 - device);
    session->fd = fd;
    ok = 1;

done:
    if (!ok) {
        ERR_print_errors_fp(stderr);
        if (fd >= 0)
            close(fd);
        OPENSSL_cleanse(session, sizeof *session);
        session->fd = -1;
    }
    /* SSL_set_fd uses a BIO with BIO_NOCLOSE. Poll the TCP control
       connection for termination once the final TLS record is consumed. */
    SSL_free(tls);
    SSL_CTX_free(ctx);
    return ok ? 0 : -1;
}
