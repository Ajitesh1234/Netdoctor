"""Parsing and strict validation of user-supplied targets.

Validation is a security boundary: a hostname beginning with ``-`` could otherwise be
interpreted as an option by the external ``ping``/``traceroute`` binaries.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_LABEL = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


class TargetError(ValueError):
    """Raised when a target string cannot be parsed or is unsafe."""


@dataclass(frozen=True)
class Target:
    raw: str
    host: str
    scheme: str | None
    port: int | None
    path: str
    is_ip: bool

    @property
    def tcp_ports(self) -> list[int]:
        if self.port is not None:
            return [self.port]
        if self.scheme == "http":
            return [80]
        if self.scheme == "https":
            return [443]
        return [443, 80]

    @property
    def tls_port(self) -> int | None:
        """Port to run a TLS handshake against, or ``None`` for plain HTTP targets."""
        if self.scheme == "http":
            return None
        return self.port or 443

    def default_port(self, scheme: str) -> int:
        return self.port or (443 if scheme == "https" else 80)


def _validate_hostname(host: str) -> str:
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"invalid hostname: {host!r}") from exc
    ascii_host = ascii_host.rstrip(".")
    if not ascii_host or len(ascii_host) > 253:
        raise TargetError(f"invalid hostname length: {host!r}")
    for label in ascii_host.split("."):
        if not _LABEL.match(label):
            raise TargetError(f"invalid hostname label {label!r} in {host!r}")
    return ascii_host.lower()


def parse_target(raw: str) -> Target:
    """Parse ``example.com``, ``example.com:8443/path`` or ``https://example.com/x``."""
    text = (raw or "").strip()
    if not text:
        raise TargetError("empty target")
    if any(c.isspace() or ord(c) < 32 for c in text):
        raise TargetError(f"whitespace/control characters not allowed: {raw!r}")

    scheme: str | None = None
    if "://" in text:
        scheme = text.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise TargetError(f"unsupported scheme {scheme!r} (use http or https)")
        parts = urlsplit(text)
    else:
        parts = urlsplit("//" + text)

    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"invalid port in {raw!r}") from exc
    if port is not None and not 1 <= port <= 65535:
        raise TargetError(f"port out of range in {raw!r}")
    if parts.username is not None or parts.password is not None:
        raise TargetError("credentials in target are not supported")

    hostname = parts.hostname
    if not hostname:
        raise TargetError(f"no hostname in {raw!r}")

    is_ip = False
    try:
        host = str(ipaddress.ip_address(hostname))
        is_ip = True
    except ValueError:
        host = _validate_hostname(hostname)

    if scheme is None and port == 80:
        scheme = "http"

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(raw=text, host=host, scheme=scheme, port=port, path=path, is_ip=is_ip)
