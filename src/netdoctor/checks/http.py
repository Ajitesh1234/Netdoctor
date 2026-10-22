"""HTTP(S) probing with manual redirect handling and per-hop timing."""

from __future__ import annotations

import http.client
import logging
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .. import __version__
from ..config import Config
from ..models import HttpHop, HttpResult
from ..target import Target
from .util import CERT_ERROR_KINDS, classify_exception, ms, short_error

log = logging.getLogger(__name__)

_REDIRECTS = {301, 302, 303, 307, 308}
_HEADERS = {
    "User-Agent": f"netdoctor/{__version__} (+https://github.com/Ajitesh1234/netdoctor)",
    "Accept": "*/*",
    "Connection": "close",
}


def _format_url(scheme: str, host: str, port: int, path: str) -> str:
    default = 443 if scheme == "https" else 80
    shown_host = f"[{host}]" if ":" in host else host
    netloc = shown_host if port == default else f"{shown_host}:{port}"
    return f"{scheme}://{netloc}{path}"


def _request(scheme: str, host: str, port: int, path: str, timeout: float) -> tuple[HttpHop, str | None]:
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        t0 = time.perf_counter()
        conn.connect()
        connect_ms = ms(time.perf_counter() - t0)
        t1 = time.perf_counter()
        conn.request("GET", path, headers=_HEADERS)
        resp = conn.getresponse()  # headers only; the body is never downloaded
        ttfb_ms = ms(time.perf_counter() - t1)
        location = resp.getheader("Location")
        hop = HttpHop(
            url=_format_url(scheme, host, port, path),
            status=resp.status,
            reason=resp.reason,
            connect_ms=connect_ms,
            ttfb_ms=ttfb_ms,
            server=resp.getheader("Server"),
            location=location,
        )
        resp.close()
        return hop, location
    finally:
        conn.close()


def fetch(scheme: str, host: str, port: int, path: str, cfg: Config) -> HttpResult:
    """GET a URL, following up to ``cfg.max_redirects`` redirects."""
    hops: list[HttpHop] = []
    seen: set[str] = set()
    started = time.perf_counter()
    cur = (scheme, host, port, path)
    for _ in range(cfg.max_redirects + 1):
        url = _format_url(*cur)
        if url in seen:
            return _fail(hops, started, "redirect loop detected", "redirect_loop", cur[0])
        seen.add(url)
        try:
            hop, location = _request(*cur, cfg.timeout)
        except Exception as exc:  # noqa: BLE001
            return _fail(hops, started, short_error(exc), classify_exception(exc), cur[0])
        hops.append(hop)
        if hop.status in _REDIRECTS and location:
            nxt = urlsplit(urljoin(url, location))
            if nxt.scheme not in ("http", "https") or not nxt.hostname:
                return _fail(hops, started, f"unsupported redirect to {location!r}", "bad_redirect", cur[0])
            try:
                nport = nxt.port or (443 if nxt.scheme == "https" else 80)
            except ValueError:
                return _fail(hops, started, "invalid redirect port", "bad_redirect", cur[0])
            npath = (nxt.path or "/") + (f"?{nxt.query}" if nxt.query else "")
            cur = (nxt.scheme, nxt.hostname, nport, npath)
            continue
        break
    else:
        return _fail(hops, started, f"more than {cfg.max_redirects} redirects", "too_many_redirects", cur[0])

    first, last = hops[0], hops[-1]
    return HttpResult(
        ok=True,
        scheme=scheme,
        final_url=last.url,
        status=last.status,
        reason=last.reason,
        connect_ms=first.connect_ms,
        ttfb_ms=first.ttfb_ms,
        total_ms=ms(time.perf_counter() - started),
        hops=hops,
    )


def _fail(hops: list[HttpHop], started: float, error: str, kind: str, scheme: str) -> HttpResult:
    return HttpResult(
        ok=False,
        scheme=scheme,
        hops=hops,
        total_ms=ms(time.perf_counter() - started),
        error=error,
        error_kind=kind,
        connect_ms=hops[0].connect_ms if hops else None,
        ttfb_ms=hops[0].ttfb_ms if hops else None,
    )


def check_http(target: Target, cfg: Config) -> HttpResult:
    """Probe ``target``. Without an explicit scheme, try HTTPS then fall back to HTTP."""
    if target.scheme:
        return fetch(target.scheme, target.host, target.default_port(target.scheme), target.path, cfg)

    https = fetch("https", target.host, target.default_port("https"), target.path, cfg)
    # Certificate errors mean TLS *works*; falling back to HTTP would hide a real problem.
    if https.ok or https.error_kind in CERT_ERROR_KINDS:
        return https
    http_port = target.port if target.port and target.port != 443 else 80
    plain = fetch("http", target.host, http_port, target.path, cfg)
    if plain.ok:
        plain.fell_back_from_https = True
        plain.https_error = https.error
        plain.https_error_kind = https.error_kind
        return plain
    return https
