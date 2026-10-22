"""DNS: system-resolver lookup plus an independent cross-check against public resolvers.

The cross-check speaks raw DNS over UDP (stdlib only) so a tampering/blocking local
resolver can be distinguished from a genuinely non-existent domain.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from ..config import Config
from ..models import DnsResult, ResolverAnswer
from ..target import Target
from .util import classify_exception, classify_gaierror, ms, run_with_timeout, short_error

log = logging.getLogger(__name__)

RCODE_NXDOMAIN = 3


def build_query(host: str, qid: int) -> bytes:
    """Build a recursive DNS ``A`` query packet."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in host.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        qname += bytes([len(raw)]) + raw
    return header + qname + b"\x00" + struct.pack("!HH", 1, 1)


def _skip_name(data: bytes, offset: int) -> int:
    for _ in range(128):  # guard against malicious pointer loops
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    raise ValueError("name too long")


def parse_response(data: bytes, qid: int) -> tuple[int, list[str]]:
    """Parse a DNS response, returning ``(rcode, [ipv4 addresses])``.

    Raises ``ValueError`` on malformed or mismatched packets.
    """
    if len(data) < 12:
        raise ValueError("short packet")
    rid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    if rid != qid:
        raise ValueError("transaction id mismatch")
    if not flags & 0x8000:
        raise ValueError("not a response")
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qd):
        offset = _skip_name(data, offset) + 4
    addresses: list[str] = []
    for _ in range(an):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("truncated record")
        rtype, rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + rdlen > len(data):
            raise ValueError("truncated rdata")
        if rtype == 1 and rclass == 1 and rdlen == 4:
            addresses.append(socket.inet_ntoa(data[offset : offset + 4]))
        offset += rdlen
    return rcode, addresses


def query_resolver(server: str, host: str, timeout: float, port: int = 53) -> ResolverAnswer:
    """Ask ``server`` for ``host``'s A records over UDP."""
    start = time.perf_counter()
    try:
        family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
        qid = secrets.randbits(16)
        packet = build_query(host, qid)
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, port))  # connected UDP drops datagrams from other sources
            sock.send(packet)
            data = sock.recv(4096)
        rcode, addresses = parse_response(data, qid)
        latency = ms(time.perf_counter() - start)
        if rcode == 0 and addresses:
            return ResolverAnswer(server, True, addresses, rcode, latency)
        kind = "nxdomain" if rcode == RCODE_NXDOMAIN else ("nodata" if rcode == 0 else "rcode")
        return ResolverAnswer(server, False, addresses, rcode, latency, f"DNS rcode {rcode}", kind)
    except Exception as exc:  # noqa: BLE001 - convert every failure into data
        return ResolverAnswer(
            server,
            False,
            error=short_error(exc),
            error_kind=classify_exception(exc),
            latency_ms=ms(time.perf_counter() - start),
        )


def _system_lookup(host: str, timeout: float) -> DnsResult:
    start = time.perf_counter()
    try:
        infos = run_with_timeout(lambda: socket.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout)
    except socket.gaierror as exc:
        return DnsResult(
            False,
            latency_ms=ms(time.perf_counter() - start),
            error=short_error(exc),
            error_kind=classify_gaierror(exc),
        )
    except Exception as exc:  # noqa: BLE001
        return DnsResult(
            False,
            latency_ms=ms(time.perf_counter() - start),
            error=short_error(exc),
            error_kind=classify_exception(exc) if not isinstance(exc, TimeoutError) else "timeout",
        )
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if addr not in addresses:
            addresses.append(addr)
    return DnsResult(True, addresses, ms(time.perf_counter() - start))


def check_dns(target: Target, cfg: Config) -> DnsResult:
    if target.is_ip:
        return DnsResult(True, [target.host], skipped=True)
    with ThreadPoolExecutor(max_workers=1 + len(cfg.resolvers)) as pool:
        system_future = pool.submit(_system_lookup, target.host, cfg.timeout)
        public_futures = (
            [pool.submit(query_resolver, s, target.host, cfg.timeout) for s in cfg.resolvers] if cfg.dns_compare else []
        )
        result = system_future.result()
        result.public = [f.result() for f in public_futures]
    log.debug("dns %s -> %s", target.host, result)
    return result
