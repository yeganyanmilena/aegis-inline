# Design and security

## Control plane

Device2 listens on its transit IPv4 address. Device1 connects from its own transit IPv4 address. Both devices validate the peer's certificate against the configured CA and check its role-specific DNS identity. OpenSSL permits TLS 1.3 and the X25519 group for an ephemeral elliptic-curve Diffie–Hellman key exchange. Session resumption is disabled. The TLS exporter derives 32 bytes per direction using separate labels. Device2 sends an authenticated readiness byte after it accepts Device1's identity and Finished message. Device1 waits for that byte before opening its forwarding loop. Loss of the control connection stops forwarding.

## Data plane

Only untagged Ethernet frames carrying the selected IPv4/TCP flow or ARP between the two configured endpoints are forwarded. The flow matches both endpoint IPv4 addresses and the configured server port. In the forward direction the port match is on the TCP destination. In the reverse direction it is on the TCP source. ARP between the endpoints is passed so their TCP stacks can resolve each other's Ethernet addresses.

| Field | LAN frame | Transit frame |
| --- | --- | --- |
| Ethernet | Original addresses and IPv4 EtherType | Same |
| IPv4 | Original addresses, TTL, protocol, ID, flags and options | Same fields with total length increased by 16 and checksum recalculated |
| TCP | Original ports, sequence, acknowledgment, flags, window and options | Same fields with checksum recalculated for the protected segment |
| Data | TCP payload | Same-length AES-GCM ciphertext, then 16-byte tag |

IP and TCP headers are included in the GCM associated data in canonical form. The canonical form uses the original IPv4 total length and zeros both checksum fields. These changes let both devices compute the same associated data. The received ciphertext is decrypted into temporary memory and copied into the forwarded frame only after tag verification. SYN, ACK, FIN, and other segments without payload still carry an authentication tag over their headers and empty plaintext. Endpoint TCP stacks see the tag removed before they process those segments. Ethernet padding is generated as needed and lies outside the IPv4 datagram.

## Nonce and replay handling

A nonce is 96 bits. The first 32 bits encode the sending device number and the last 64 bits encode its packet counter in big-endian order. Each sender starts with counter 1 and spends a new counter on every encryption attempt that reaches the cipher. The device stops after 2^24 attempts for a directional key. Restarting both devices runs a fresh handshake and creates new keys.

The nonce counter is implicit. The receiver tries the next 64 counters after the highest authenticated counter and any unseen counters in its 64-position replay bitmap. The usual in-order packet succeeds on the first attempt. Only successful authentication advances the window or marks a counter as seen. A replay of an authenticated packet is discarded. A retransmission from an endpoint receives a fresh nonce, even when its headers and payload are byte-for-byte identical.

A gap of 64 or more consecutive missing protected packets can leave the receiver unable to recover the implicit counter. Both devices must then be restarted for fresh keys. Packets arriving more than 63 positions behind the highest authenticated counter are discarded. Invalid traffic can force multiple GCM attempts per packet, so the design targets a dedicated low-loss link and laboratory rates.

## Lab assumptions

- The protected path is a direct Layer 2 connection. A normal TCP-aware middlebox on that link can misinterpret the tag as additional application bytes because the TCP sequence numbers remain unchanged.
- Untagged Ethernet and unfragmented IPv4/TCP are supported. Use a 16-byte MTU margin, avoid IPv4 source routing, and disable offloads that coalesce packets or defer checksums.
- Layer 2 addresses, IP and TCP headers, packet sizes and timing remain observable. ARP is outside the protected channel. The prototype assumes trusted endpoint-side LANs and an isolated device-to-device Ethernet link.
- The integration test exercises one selected server port. Multiple simultaneous flows for that port share the directional packet counter and replay window.

## References

- [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
- [OpenSSL TLS group configuration](https://docs.openssl.org/3.4/man3/SSL_CTX_set1_curves/)
- [OpenSSL TLS key exporter](https://docs.openssl.org/3.3/man3/SSL_export_keying_material/)
- [OpenSSL EVP authenticated encryption](https://docs.openssl.org/3.4/man3/EVP_EncryptInit/)
