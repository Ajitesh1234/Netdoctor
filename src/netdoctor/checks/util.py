from __future__ import annotations

import errno
import http.client
import socket
import ssl
import threading
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

_CERT_KINDS = {
    9: "cert_not_yet_valid",
    10: "cert_expired",
    18: "self_signed",
    19: "self_signed",
    20: "untrusted_issuer",
    21: "untrusted_issuer",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
}

CERT_ERROR_KINDS = frozenset(_CERT_KINDS.values()) | {"cert_invalid"}


def run_with_timeout(fn: Callable[[], T], timeout: float) -> T:
    """Run a blocking call (e.g. ``getaddrinfo``) with a hard deadline.

    The worker is a daemon thread so a hung resolver can never block interpreter exit.
    """
    box: dict[str, object] = {}

    def _target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in caller
            box["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"timed out after {timeout:g}s")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]  # type: ignore[return-value]


def classify_exception(exc: BaseException) -> str:
    """Map an exception to a stable, machine-readable ``error_kind``."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return _CERT_KINDS.get(getattr(exc, "verify_code", 0) or 0, "cert_invalid")
    if isinstance(exc, (ssl.SSLEOFError, http.client.RemoteDisconnected)):
        return "reset"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    if isinstance(exc, socket.gaierror):
        return classify_gaierror(exc)
    if isinstance(exc, ssl.SSLError):
        return "tls_error"
    if isinstance(exc, OSError) and exc.errno in {
        getattr(errno, n, -1) for n in ("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN")
    }:
        return "unreachable"
    return "error"


def classify_gaierror(exc: socket.gaierror) -> str:
    code = exc.errno
    nonames = {getattr(socket, n, None) for n in ("EAI_NONAME", "EAI_NODATA")} | {11001}
    if code in nonames:
        return "nxdomain"
    if code == getattr(socket, "EAI_AGAIN", None) or code == 11002:
        return "temporary"
    return "error"


def short_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}".strip()
    return text if len(text) <= 240 else text[:237] + "..."


def ms(seconds: float) -> float:
    return round(seconds * 1000.0, 2)
