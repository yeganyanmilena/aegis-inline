"""Integration driver and Ethernet PCAP assertion helper."""
import socket
import struct
import sys

REQUEST = b"AEGIS_REQUEST_MARKER_4be2c32fd924\n" * 1500
REPLY = b"AEGIS_RESPONSE_MARKER_31f00c480ffc\n" * 1500


def receive_all(conn):
    result = bytearray()
    while part := conn.recv(65536):
        result.extend(part)
    return bytes(result)


def server():
    with socket.socket() as listener, socket.socket() as unselected:
        listener.bind(("10.42.0.2", 8080))
        unselected.bind(("10.42.0.2", 8081))
        listener.listen()
        unselected.listen()
        print("listening", flush=True)
        with listener.accept()[0] as conn:
            conn.settimeout(8)
            assert receive_all(conn) == REQUEST
            conn.sendall(REPLY)


def client():
    with socket.create_connection(("10.42.0.2", 8080), timeout=8) as conn:
        conn.sendall(REQUEST)
        conn.shutdown(socket.SHUT_WR)
        assert receive_all(conn) == REPLY
    print("PASS exact request and response bytes")


def blocked(port):
    try:
        with socket.create_connection(("10.42.0.2", port), timeout=1):
            raise AssertionError(f"Port {port} unexpectedly reachable")
    except (TimeoutError, OSError) as exc:
        if isinstance(exc, ConnectionRefusedError):
            raise AssertionError(f"Port {port} forwarded a TCP reset") from exc


def packets(path):
    with open(path, "rb") as capture:
        header = capture.read(24)
        magic = header[:4]
        assert magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
        endian = "<" if magic[0] == 0xd4 else ">"
        assert struct.unpack(endian + "I", header[20:])[0] & 0xffff == 1
        while record := capture.read(16):
            _, _, captured, _ = struct.unpack(endian + "IIII", record)
            frame = capture.read(captured)
            ip = frame[14:]
            ihl = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], "big")
            tcp = ip[ihl:total]
            thl = (tcp[12] >> 4) * 4
            assert frame[12:14] == b"\x08\x00" and ip[9] == 6
            canonical_ip = ip[:2] + ip[4:10] + ip[12:ihl]
            canonical_tcp = tcp[:16] + tcp[18:thl]
            yield (frame[:14], canonical_ip, canonical_tcp), tcp[thl:], ip[15]


def captures(lan_path, wan_path):
    lan = list(packets(lan_path))
    wan = list(packets(wan_path))
    assert lan and wan
    for marker in (REQUEST.splitlines()[0], REPLY.splitlines()[0]):
        assert any(marker in payload for _, payload, _ in lan), "LAN plaintext evidence missing"
        assert all(marker not in payload for _, payload, _ in wan), "Plaintext found on transit"
    for source in (1, 2):
        assert sum(bool(payload) and sender == source for _, payload, sender in lan) >= 2
    lan_lengths = {(header, len(payload)) for header, payload, _ in lan}
    for header, payload, _ in wan:
        assert (header, len(payload) - 16) in lan_lengths, "Unexpected header or wire expansion"
    print("PASS capture shows matching headers and exactly 16 added bytes per packet")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "server":
        server()
    elif mode == "client":
        client()
    elif mode == "blocked":
        blocked(int(sys.argv[2]))
    elif mode == "captures":
        captures(*sys.argv[2:])
    else:
        raise SystemExit(f"Unknown test mode: {mode}")
