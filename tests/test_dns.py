from __future__ import annotations

import contextlib
import socket
import struct
import threading

import pytest

from conftest import QuietHTTPServer, server_tls_context
from netdoctor.checks import dns
from netdoctor.config import Config
from netdoctor.target import parse_target


def _qtype(query: bytes) -> int:
    off = 12
    while query[off]:
        off += 1 + query[off]
    return struct.unpack_from("!H", query, off + 1)[0]


def _response(query: bytes, rcode: int = 0, ips: tuple[str, ...] = (), ips6: tuple[str, ...] = ()) -> bytes:
    qtype = _qtype(query)
    records = b""
    if qtype == 1:
        for ip in ips:
            records += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    elif qtype == 28:
        for ip in ips6:
            records += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, ip)
    count = len(ips) if qtype == 1 else len(ips6)
    return query[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1, count, 0, 0) + query[12:] + records


@pytest.fixture()
def fake_dns():
    """UDP DNS server: behaviour is chosen via the returned dict."""
    state = {"rcode": 0, "ips": ("203.0.113.7",), "ips6": (), "mode": "answer"}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except (TimeoutError, socket.timeout):
                continue
            except ConnectionResetError:
                continue  # Windows: stray ICMP port-unreachable surfaces on recv
            except OSError:
                return
            if state["mode"] == "silent":
                continue
            if state["mode"] == "aaaa_silent" and _qtype(data) == 28:
                continue
            if state["mode"] == "wrong_id":
                sock.sendto(bytes([data[0] ^ 0xFF]) + data[1:2] + _response(data)[2:], addr)
            elif state["mode"] == "garbage":
                sock.sendto(b"\x00\x01", addr)
            else:
                sock.sendto(_response(data, state["rcode"], state["ips"], state["ips6"]), addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield state, sock.getsockname()[1]
    stop.set()
    sock.close()


def test_build_and_parse_roundtrip():
    q = dns.build_query("example.com", 0x1234)
    assert q[:2] == b"\x12\x34"
    rcode, ips = dns.parse_response(_response(q, 0, ("1.2.3.4", "5.6.7.8")), 0x1234)
    assert (rcode, ips) == (0, ["1.2.3.4", "5.6.7.8"])


def test_build_rejects_bad_label():
    with pytest.raises(ValueError):
        dns.build_query("a" * 64 + ".com", 1)
    with pytest.raises(ValueError):
        dns.build_query("a..com", 1)


@pytest.mark.parametrize("data", [b"", b"\x00" * 5, b"\x12\x34" + b"\x81\x80" + b"\x00\x01" * 4 + b"\xc0"])
def test_parse_rejects_malformed(data):
    with pytest.raises(ValueError):
        dns.parse_response(data, 0x1234)


def test_parse_rejects_wrong_id_and_non_response():
    q = dns.build_query("example.com", 1)
    with pytest.raises(ValueError, match="id"):
        dns.parse_response(_response(q), 2)
    with pytest.raises(ValueError, match="response"):
        dns.parse_response(q, 1)


def test_pointer_loop_is_bounded():
    pkt = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x01a" * 200
    with pytest.raises(ValueError):
        dns.parse_response(pkt, 1)


def test_query_resolver_ok(fake_dns):
    _state, port = fake_dns
    r = dns.query_resolver("127.0.0.1", "example.com", 1.0, port=port)
    assert r.ok and r.addresses == ["203.0.113.7"] and r.latency_ms is not None


def test_query_resolver_nxdomain(fake_dns):
    state, port = fake_dns
    state.update(rcode=3, ips=())
    r = dns.query_resolver("127.0.0.1", "nope.example", 1.0, port=port)
    assert not r.ok and r.error_kind == "nxdomain" and r.rcode == 3


def test_query_resolver_nodata(fake_dns):
    state, port = fake_dns
    state.update(rcode=0, ips=())
    assert dns.query_resolver("127.0.0.1", "x.example", 1.0, port=port).error_kind == "nodata"


@pytest.mark.parametrize(("mode", "kind"), [("silent", "timeout"), ("garbage", "error"), ("wrong_id", "error")])
def test_query_resolver_failures(fake_dns, mode, kind):
    state, port = fake_dns
    state["mode"] = mode
    r = dns.query_resolver("127.0.0.1", "x.example", 0.4, port=port)
    assert not r.ok and r.error_kind == kind


def test_check_dns_ip_literal_skips_lookup():
    r = dns.check_dns(parse_target("192.0.2.1"), Config())
    assert r.ok and r.skipped and r.addresses == ["192.0.2.1"] and not r.public


def test_check_dns_localhost_without_compare():
    r = dns.check_dns(parse_target("localhost"), Config(dns_compare=False))
    assert r.ok and any(a in ("127.0.0.1", "::1") for a in r.addresses) and r.public == []


def test_check_dns_nxdomain_without_compare():
    r = dns.check_dns(parse_target("does-not-exist.invalid"), Config(dns_compare=False, timeout=3))
    assert not r.ok and r.error_kind in ("nxdomain", "temporary", "timeout")


# ------------------------------------------------------------------ AAAA / IPv6
def test_aaaa_roundtrip():
    q = dns.build_query("example.com", 7, dns.QTYPE_AAAA)
    assert _qtype(q) == 28
    assert dns.parse_response(_response(q, 0, (), ("2001:db8::1", "2606:4700::1111")), 7) == (
        0,
        ["2001:db8::1", "2606:4700::1111"],
    )


def test_query_resolver_merges_ipv4_and_ipv6(fake_dns):
    state, port = fake_dns
    state["ips6"] = ("2001:db8::7",)
    r = dns.query_resolver("127.0.0.1", "example.com", 1.0, port=port)
    assert r.ok and r.addresses == ["203.0.113.7", "2001:db8::7"] and r.transport == "udp"


def test_ipv6_only_host_is_ok(fake_dns):
    state, port = fake_dns
    state.update(ips=(), ips6=("2001:db8::9",))
    r = dns.query_resolver("127.0.0.1", "v6only.example", 1.0, port=port)
    assert r.ok and r.addresses == ["2001:db8::9"]


def test_missing_aaaa_does_not_fail_the_answer(fake_dns):
    state, port = fake_dns
    state["mode"] = "aaaa_silent"  # AAAA query times out, A works
    r = dns.query_resolver("127.0.0.1", "example.com", 0.4, port=port)
    assert r.ok and r.addresses == ["203.0.113.7"]


def test_query_resolver_rejects_non_ip_server():
    r = dns.query_resolver("not-an-ip", "example.com", 0.2)
    assert not r.ok and r.error_kind == "error"


# ------------------------------------------------------------------ DNS-over-HTTPS
@pytest.fixture()
def doh_server(tls_cert):
    import http.server

    state = {"mode": "ok", "ips": ("198.51.100.20",), "ips6": ("2001:db8::20",), "rcode": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            state["last_headers"] = dict(self.headers)
            state["last_id"] = body[:2]
            mode = state["mode"]
            if mode == "status500":
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = _response(body, state["rcode"], state["ips"], state["ips6"])
            ctype = "text/html" if mode == "badtype" else "application/dns-message"
            if mode == "huge":
                payload = payload + b"\x00" * 70_000
            if mode == "garbage":
                payload = b"\x00\x01"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    ctx = server_tls_context(tls_cert)
    srv = QuietHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield state, f"https://localhost:{srv.server_address[1]}/dns-query", str(tls_cert / "c.pem")
    srv.shutdown()
    srv.server_close()


def test_doh_success(doh_server):
    state, url, ca = doh_server
    r = dns.query_doh(url, "example.com", 3.0, ca_bundle=ca)
    assert r.ok and r.transport == "doh" and r.server == "doh:localhost"
    assert r.addresses == ["198.51.100.20", "2001:db8::20"]
    assert state["last_id"] == b"\x00\x00"  # RFC 8484: ID SHOULD be 0
    assert state["last_headers"]["Content-Type"] == "application/dns-message"


@pytest.mark.parametrize("mode", ["status500", "badtype", "huge", "garbage"])
def test_doh_bad_server_behaviour_is_a_failure_not_a_crash(doh_server, mode):
    state, url, ca = doh_server
    state["mode"] = mode
    r = dns.query_doh(url, "example.com", 3.0, ca_bundle=ca)
    assert not r.ok and r.transport == "doh" and r.error_kind == "error"


def test_doh_nxdomain(doh_server):
    state, url, ca = doh_server
    state.update(rcode=3, ips=(), ips6=())
    assert dns.query_doh(url, "gone.example", 3.0, ca_bundle=ca).error_kind == "nxdomain"


def test_doh_requires_valid_tls(doh_server):
    _state, url, _ca = doh_server  # default trust store does not know the test CA
    r = dns.query_doh(url, "example.com", 3.0)
    assert not r.ok and r.error_kind in ("self_signed", "untrusted_issuer")


def test_doh_refuses_plain_http_url():
    r = dns.query_doh("http://localhost/dns-query", "example.com", 1.0)
    assert not r.ok and r.error_kind == "error"


def test_doh_connection_refused(closed_port):
    r = dns.query_doh(f"https://127.0.0.1:{closed_port}/dns-query", "example.com", 6.0)
    assert not r.ok and r.error_kind == "refused"


def test_check_dns_includes_doh_and_respects_no_compare(doh_server):
    _state, url, ca = doh_server
    cfg = Config(resolvers=(), doh_servers=(url,), ca_bundle=ca, timeout=3.0)
    r = dns.check_dns(parse_target("localhost"), cfg)
    assert r.ok and [a.transport for a in r.public] == ["doh"] and r.public[0].ok
    off = dns.check_dns(parse_target("localhost"), Config(resolvers=(), doh_servers=(url,), dns_compare=False))
    assert off.public == []  # --no-dns-compare also disables DoH (no third-party lookups)


def test_config_rejects_non_https_doh():
    with pytest.raises(ValueError, match="https"):
        Config(doh_servers=("http://dns.example/dns-query",))


# ------------------------------------------------------------------ robustness: hostile bytes
def _valid_packets():
    out = []
    for qt in (1, 28):
        q = dns.build_query("example.com", 0x1234, qt)
        out.append(_response(q, 0, ("1.2.3.4", "5.6.7.8"), ("2001:db8::1",)))
    return out


def test_parser_never_crashes_on_random_bytes():
    import random

    rng = random.Random(1234)
    for _ in range(4000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 200)))
        try:
            rcode, addrs = dns.parse_response(data, rng.getrandbits(16))
        except ValueError:
            continue
        assert isinstance(rcode, int) and isinstance(addrs, list)


def test_parser_never_crashes_on_mutated_valid_packets():
    import random

    rng = random.Random(99)
    for base in _valid_packets():
        for _ in range(3000):
            data = bytearray(base)
            for _ in range(rng.randrange(1, 6)):
                data[rng.randrange(len(data))] = rng.getrandbits(8)
            if rng.random() < 0.3:
                data = data[: rng.randrange(len(data))]
            with contextlib.suppress(ValueError):  # rejecting malformed input is correct; any other error is a bug
                dns.parse_response(bytes(data), 0x1234)


def test_parser_never_follows_compression_pointers():
    # pointers are skipped, never followed, so a self-referencing name cannot loop
    pkt = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    assert dns.parse_response(pkt, 1) == (0, [])
