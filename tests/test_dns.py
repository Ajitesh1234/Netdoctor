from __future__ import annotations

import socket
import struct
import threading

import pytest

from netdoctor.checks import dns
from netdoctor.config import Config
from netdoctor.target import parse_target


def _response(query: bytes, rcode: int = 0, ips: tuple[str, ...] = ()) -> bytes:
    qid = query[:2]
    flags = 0x8180 | rcode
    question = query[12:]
    out = qid + struct.pack("!HHHHH", flags, 1, len(ips), 0, 0) + question
    for ip in ips:
        out += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return out


@pytest.fixture()
def fake_dns():
    """UDP DNS server: behaviour is chosen via the returned dict."""
    state = {"rcode": 0, "ips": ("203.0.113.7",), "mode": "answer"}
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
            if state["mode"] == "wrong_id":
                sock.sendto(bytes([data[0] ^ 0xFF]) + data[1:2] + _response(data)[2:], addr)
            elif state["mode"] == "garbage":
                sock.sendto(b"\x00\x01", addr)
            else:
                sock.sendto(_response(data, state["rcode"], state["ips"]), addr)

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
