"""DNS: system-resolver lookup plus independent cross-checks.

Two independent channels are used to tell a tampering/blocking local resolver apart from a
genuinely non-existent domain:

* plain DNS over UDP to public resolvers (raw wire format, stdlib only), and
* optionally **DNS-over-HTTPS** (RFC 8484), which a network device cannot rewrite the way it can
  rewrite port-53 traffic. Disagreement between the two channels is evidence of interference.

Both A and AAAA records are queried, so IPv4 and IPv6 answers are compared separately.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import secrets
import socket
import ssl
import struct
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Union
from urllib.parse import urlsplit

from .. import __version__
from ..config import Config
from ..models import DnsResult, ResolverAnswer
from ..target import Target
from .util import classify_exception, classify_gaierror, ms, run_with_timeout, short_error

log = logging.getLogger(__name__)

RCODE_NXDOMAIN = 3
QTYPE_A, QTYPE_AAAA = 1, 28
MAX_DOH_BYTES = 65535  # DNS messages cannot exceed this; refuse anything larger

Exchange = tuple[int, list[str]]  # (rcode, addresses)
Outcome = Union[Exchange, Exception]


def build_query(host: str, qid: int, qtype: int = QTYPE_A) -> bytes:
    """Build a recursive DNS query packet (default ``A``; pass ``QTYPE_AAAA`` for IPv6)."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in host.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        qname += bytes([len(raw)]) + raw
    return header + qname + b"\x00" + struct.pack("!HH", qtype, 1)


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
    """Parse a DNS response, returning ``(rcode, [IPv4 and IPv6 addresses])``.

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
        if rtype == QTYPE_A and rclass == 1 and rdlen == 4:
            addresses.append(socket.inet_ntoa(data[offset : offset + 4]))
        elif rtype == QTYPE_AAAA and rclass == 1 and rdlen == 16:
            addresses.append(socket.inet_ntop(socket.AF_INET6, data[offset : offset + 16]))
        offset += rdlen
    return rcode, addresses


def _udp_exchange(server: str, host: str, qtype: int, timeout: float, port: int) -> tuple[int, list[str]]:
    family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
    qid = secrets.randbits(16)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, port))  # connected UDP drops datagrams from other sources
        sock.send(build_query(host, qid, qtype))
        data = sock.recv(4096)
    return parse_response(data, qid)


def _doh_exchange(url: str, host: str, qtype: int, timeout: float, ca_bundle: str | None) -> tuple[int, list[str]]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"DoH URL must be https://: {url!r}")
    ctx = ssl.create_default_context(cafile=ca_bundle)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=ctx)
    try:
        conn.request(
            "POST",
            (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
            body=build_query(host, 0, qtype),  # RFC 8484 section 4.1: ID SHOULD be 0
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": f"netdoctor/{__version__}",
            },
        )
        resp = conn.getresponse()
        if resp.status != 200:
            raise ValueError(f"DoH server returned HTTP {resp.status}")
        ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/dns-message":
            raise ValueError(f"unexpected DoH content type {ctype!r}")
        data = resp.read(MAX_DOH_BYTES + 1)
        if len(data) > MAX_DOH_BYTES:
            raise ValueError("DoH response too large")
    finally:
        conn.close()
    return parse_response(data, 0)


def _answer(server: str, transport: str, started: float, a: Outcome, aaaa: Outcome) -> ResolverAnswer:
    """Merge the A and AAAA exchanges into one answer. The A result decides success or failure."""
    latency = ms(time.perf_counter() - started)
    if isinstance(a, Exception):
        return ResolverAnswer(
            server,
            False,
            error=short_error(a),
            error_kind=classify_exception(a),
            latency_ms=latency,
            transport=transport,
        )
    rcode, addresses = a[0], list(a[1])
    if not isinstance(aaaa, Exception) and aaaa[0] == 0:
        addresses += [x for x in aaaa[1] if x not in addresses]
    if rcode == 0 and addresses:
        return ResolverAnswer(server, True, addresses, rcode, latency, transport=transport)
    kind = "nxdomain" if rcode == RCODE_NXDOMAIN else ("nodata" if rcode == 0 else "rcode")
    return ResolverAnswer(server, False, addresses, rcode, latency, f"DNS rcode {rcode}", kind, transport=transport)


def _both(fn: Callable[[int], Exchange]) -> tuple[Outcome, Outcome]:
    """Run ``fn(qtype)`` for A and AAAA concurrently, capturing exceptions as values."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fn, qt) for qt in (QTYPE_A, QTYPE_AAAA)]
        out: list[Outcome] = []
        for f in futures:
            try:
                out.append(f.result())
            except Exception as exc:  # noqa: BLE001 - convert every failure into data
                out.append(exc)
    return out[0], out[1]


def query_resolver(server: str, host: str, timeout: float, port: int = 53) -> ResolverAnswer:
    """Ask ``server`` for ``host``'s A and AAAA records over plain UDP DNS."""
    started = time.perf_counter()
    try:
        ipaddress.ip_address(server)
    except ValueError as exc:
        return ResolverAnswer(server, False, error=short_error(exc), error_kind="error")
    a, aaaa = _both(lambda qt: _udp_exchange(server, host, qt, timeout, port))
    return _answer(server, "udp", started, a, aaaa)


def query_doh(url: str, host: str, timeout: float, ca_bundle: str | None = None) -> ResolverAnswer:
    """Ask a DNS-over-HTTPS server (RFC 8484, POST) for ``host``'s A and AAAA records."""
    started = time.perf_counter()
    label = f"doh:{urlsplit(url).hostname or url}"
    a, aaaa = _both(lambda qt: _doh_exchange(url, host, qt, timeout, ca_bundle))
    return _answer(label, "doh", started, a, aaaa)


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
    doh = cfg.doh_servers if cfg.dns_compare else ()
    udp = cfg.resolvers if cfg.dns_compare else ()
    with ThreadPoolExecutor(max_workers=1 + len(udp) + len(doh)) as pool:
        system_future = pool.submit(_system_lookup, target.host, cfg.timeout)
        public_futures = [pool.submit(query_resolver, s, target.host, cfg.timeout) for s in udp]
        public_futures += [pool.submit(query_doh, u, target.host, cfg.timeout, cfg.ca_bundle) for u in doh]
        result = system_future.result()
        result.public = [f.result() for f in public_futures]
    log.debug("dns %s -> %s", target.host, result)
    return result
