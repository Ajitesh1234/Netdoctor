"""TLS handshake with full certificate and hostname verification.

IP-literal targets are verified against IP subjectAltName entries (no SNI is sent).
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any, cast

from ..models import TlsResult
from .util import classify_exception, ms, short_error


def _flatten_name(rdns: object) -> str | None:
    pairs = {k: v for rdn in (rdns or ()) for k, v in rdn}  # type: ignore[attr-defined]
    return pairs.get("commonName") or pairs.get("organizationName")


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def check_tls(host: str, port: int, timeout: float, ca_bundle: str | None = None) -> TlsResult:
    ctx = ssl.create_default_context(cafile=ca_bundle)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    start = time.perf_counter()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            handshake = ms(time.perf_counter() - start)
            cert = cast("dict[str, Any]", tls.getpeercert() or {})
            cipher = tls.cipher()
            version = tls.version()
    except Exception as exc:  # noqa: BLE001
        return TlsResult(
            False,
            port=port,
            error=short_error(exc),
            error_kind=classify_exception(exc),
        )

    not_after = ssl.cert_time_to_seconds(cert["notAfter"]) if "notAfter" in cert else None
    not_before = ssl.cert_time_to_seconds(cert["notBefore"]) if "notBefore" in cert else None
    return TlsResult(
        True,
        port=port,
        handshake_ms=handshake,
        version=version,
        cipher=cipher[0] if cipher else None,
        subject=_flatten_name(cert.get("subject")),
        issuer=_flatten_name(cert.get("issuer")),
        not_before=_iso(not_before) if not_before else None,
        not_after=_iso(not_after) if not_after else None,
        days_to_expiry=round((not_after - time.time()) / 86400, 1) if not_after else None,
        san=[v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")],
    )
