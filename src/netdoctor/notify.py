"""Webhook notifications for watch mode.

Security properties (see docs/THREAT_MODEL.md):

* **SSRF-safe by default.** The destination must resolve *only* to globally routable addresses.
  Loopback, RFC 1918, link-local (including the cloud metadata address 169.254.169.254),
  carrier-grade NAT and other special ranges are refused unless ``allow_private`` is set.
* **DNS-rebinding resistant.** The hostname is resolved exactly once; the connection is then
  pinned to the validated IPs (tried in order, so one broken IP family does not break delivery)
  while TLS still verifies the original hostname.
* **No redirects** are followed, and HTTPS is required unless ``allow_http`` is set.
* **Signed.** With a secret configured, every request carries
  ``X-NetDoctor-Signature: sha256=HMAC(secret, "<timestamp>." + body)`` and a timestamp header so the
  receiver can authenticate the sender and reject replays.
* **Never blocks monitoring.** Delivery runs on a worker thread behind a bounded queue
  (oldest dropped on overflow); failures are retried with backoff and never raised to the caller.
* **No secret leakage.** URLs are logged only as ``scheme://host/...``.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import queue
import random
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import __version__
from .checks.util import classify_exception, run_with_timeout, short_error
from .models import to_plain
from .watch import WatchEvent, format_duration

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 65536
MAX_RETRY_AFTER_S = 30.0
DEFAULT_EVENTS = frozenset({"change", "recovered", "error"})
KINDS = ("generic", "slack")


class NotifyError(ValueError):
    """Invalid webhook configuration or a destination that violates the safety policy."""


@dataclass(frozen=True)
class WebhookConfig:
    url: str
    secret: str | None = None
    kind: str = "generic"
    events: frozenset[str] = DEFAULT_EVENTS
    allow_private: bool = False
    allow_http: bool = False
    include_report: bool = False
    timeout: float = 5.0
    retries: int = 3
    ca_bundle: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise NotifyError(f"webhook kind must be one of {', '.join(KINDS)}")
        if not 1 <= self.retries <= 10:
            raise NotifyError("webhook retries must be between 1 and 10")
        if self.timeout <= 0:
            raise NotifyError("webhook timeout must be > 0")
        valid = {"initial", "change", "recovered", "heartbeat", "error"}
        unknown = set(self.events) - valid
        if unknown:
            raise NotifyError(f"unknown notify event(s): {', '.join(sorted(unknown))}")
        parse_webhook_url(self.url, allow_http=self.allow_http)  # fail fast


# --------------------------------------------------------------------------- url + SSRF policy
def parse_webhook_url(url: str, *, allow_http: bool = False) -> tuple[str, str, int, str]:
    """Validate ``url`` and return ``(scheme, host, port, path_with_query)``."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http"):
        raise NotifyError("webhook URL must start with https://")
    if parts.scheme == "http" and not allow_http:
        raise NotifyError("webhook URL must use https:// (use --webhook-allow-http to permit plain http)")
    if not parts.hostname:
        raise NotifyError("webhook URL has no host")
    if parts.username is not None or parts.password is not None:
        raise NotifyError("credentials inside the webhook URL are not supported")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise NotifyError("invalid port in webhook URL") from exc
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return parts.scheme, parts.hostname, port, path


def redact_url(url: str) -> str:
    """``https://hooks.example.com/services/T000/B000/SECRET`` -> ``https://hooks.example.com/...``"""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.hostname or '?'}/..."


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_public_ip(str(addr.ipv4_mapped))
        if addr in _NAT64:  # may embed a private IPv4 address; refuse conservatively
            return False
    return addr.is_global and not addr.is_multicast


def resolve_destination(host: str, port: int, *, allow_private: bool, timeout: float) -> list[str]:
    """Resolve once and enforce the SSRF policy on *every* returned address."""
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            infos = run_with_timeout(lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout)
        except (OSError, TimeoutError) as exc:
            raise NotifyError(f"cannot resolve webhook host: {short_error(exc)}") from exc
        addresses = list(dict.fromkeys(str(i[4][0]).split("%", 1)[0] for i in infos))
    if not addresses:
        raise NotifyError("webhook host resolved to no addresses")
    if not allow_private:
        blocked = [a for a in addresses if not is_public_ip(a)]
        if blocked:
            raise NotifyError(
                f"webhook destination resolves to a non-public address ({blocked[0]}); "
                "refusing (SSRF protection). Use --webhook-allow-private only for trusted internal receivers."
            )
    return addresses


# --------------------------------------------------------------------------- pinned HTTP(S) connection
MAX_ADDRESSES_TRIED = 4


def _connect_pinned(ips: list[str], port: int, timeout: float | None) -> socket.socket:
    """TCP-connect to the first reachable address among the **already validated** ``ips``.

    Every address here passed the SSRF policy, so falling back from one to the next is as safe as using
    one; it keeps delivery working when, say, IPv6 is broken but IPv4 is fine (what browsers do).
    Only the TCP step falls through: TLS errors are never retried against another address.
    """
    last: OSError | None = None
    for ip in ips[:MAX_ADDRESSES_TRIED]:
        try:
            return socket.create_connection((ip, port), timeout)
        except OSError as exc:
            last = exc
    raise last or OSError("no addresses to connect to")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ips: list[str], timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ips = ips

    def connect(self) -> None:
        self.sock = _connect_pinned(self._ips, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to pre-validated IPs but verifies the certificate against the original hostname."""

    def __init__(self, host: str, port: int, ips: list[str], timeout: float, ca_bundle: str | None) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ips = ips
        self._tls = ssl.create_default_context(cafile=ca_bundle)
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_2

    def connect(self) -> None:
        sock = _connect_pinned(self._ips, self.port, self.timeout)
        try:
            self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


# --------------------------------------------------------------------------- payloads
def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_SLACK_ICON = {"healthy": ":white_check_mark:", "degraded": ":warning:", "failing": ":rotating_light:"}


def slack_payload(event: WatchEvent) -> dict[str, object]:
    """Slack-compatible message (also accepted by Mattermost and most Slack-style webhooks)."""
    if event.event == "error":
        return {"text": f":x: *NetDoctor watch cycle failed:* {_slack_escape(event.error or 'unknown error')}"}
    if event.status is None:
        return {"text": f":information_source: NetDoctor event: {_slack_escape(event.event)}"}
    icon = _SLACK_ICON.get(event.status.value, ":information_source:")
    target = _slack_escape(event.target or "?")
    if event.event == "recovered":
        detail = f"recovered after {format_duration(event.in_previous_state_s or 0)}"
    elif event.previous_status is not None:
        detail = f"{event.previous_status.value} -> {event.status.value} after {format_duration(event.in_previous_state_s or 0)}"
    else:
        detail = event.event
    lines = [f"{icon} *{target}* is *{event.status.value.upper()}* ({detail})"]
    lines += [f"• {_slack_escape(f.message)}" for f in event.added]
    lines += [f"• _{_slack_escape(c)} cleared_" for c in event.removed]
    if not event.added and not event.removed and event.summary:
        lines.append(_slack_escape(event.summary))
    return {"text": "\n".join(lines)}


def generic_payload(event: WatchEvent, *, include_report: bool) -> dict[str, object]:
    data = to_plain(event)
    if not include_report:
        data.pop("report", None)
    data["tool"] = "netdoctor"
    data["tool_version"] = __version__
    return data  # type: ignore[no-any-return]


# --------------------------------------------------------------------------- delivery
@dataclass
class Attempt:
    status: int | None
    error: str | None = None
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def retryable(self) -> bool:
        if self.status is None:  # network-level failure
            return True
        return self.status == 429 or self.status >= 500


def post_once(cfg: WebhookConfig, body: bytes, headers: dict[str, str]) -> Attempt:
    """One POST attempt with SSRF checks, IP pinning and no redirect following."""
    try:
        scheme, host, port, path = parse_webhook_url(cfg.url, allow_http=cfg.allow_http)
        ips = resolve_destination(host, port, allow_private=cfg.allow_private, timeout=cfg.timeout)
    except NotifyError as exc:
        # Policy violations are permanent: report as a non-retryable 4xx-style failure.
        return Attempt(400, str(exc))
    conn: http.client.HTTPConnection
    if scheme == "https":
        conn = _PinnedHTTPSConnection(host, port, ips, cfg.timeout, cfg.ca_bundle)
    else:
        conn = _PinnedHTTPConnection(host, port, ips, cfg.timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read(MAX_RESPONSE_BYTES)
        retry_after = None
        raw = resp.getheader("Retry-After")
        if raw and raw.strip().isdigit():
            retry_after = min(float(raw.strip()), MAX_RETRY_AFTER_S)
        return Attempt(resp.status, retry_after=retry_after)
    except Exception as exc:  # noqa: BLE001 - network failures are data
        return Attempt(None, f"{classify_exception(exc)}: {short_error(exc)}")
    finally:
        conn.close()


_STOP = object()


class WebhookNotifier:
    """Non-blocking, retrying webhook sender. Safe to share; never raises from :meth:`submit`."""

    def __init__(
        self,
        cfg: WebhookConfig,
        *,
        send: Callable[[WebhookConfig, bytes, dict[str, str]], Attempt] = post_once,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = lambda: random.uniform(0.8, 1.2),  # noqa: S311  # nosec B311 - retry jitter, not security-sensitive
        queue_size: int = 100,
        backoff_base: float = 1.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self._send, self._sleep, self._jitter, self._clock = send, sleep, jitter, clock
        self._backoff_base = backoff_base
        self._q: queue.Queue[object] = queue.Queue(maxsize=queue_size)
        self._lock = threading.Lock()
        self._closed = False
        self.sent = self.failed = self.dropped = 0
        self._thread = threading.Thread(target=self._run, name="netdoctor-webhook", daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------ public API
    def submit(self, event: WatchEvent) -> bool:
        """Queue ``event`` if it matches the configured event kinds. Never blocks, never raises."""
        if event.event not in self.cfg.events or self._closed:
            return False
        try:
            self._q.put_nowait(event)
        except queue.Full:
            try:  # drop the oldest so the newest (most relevant) state change still goes out
                self._q.get_nowait()
                self._q.put_nowait(event)
            except (queue.Empty, queue.Full):
                pass
            with self._lock:
                self.dropped += 1
            log.warning("webhook queue full; dropped the oldest notification")
        return True

    def close(self, timeout: float = 15.0) -> bool:
        """Flush queued notifications (up to ``timeout`` seconds). Returns True if fully drained."""
        self._closed = True
        with contextlib.suppress(queue.Full):  # worker is busy; the bounded join below still limits the wait
            self._q.put(_STOP, timeout=1.0)
        self._thread.join(timeout)
        return not self._thread.is_alive()

    # ------------------------------------------------------------------ internals
    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is _STOP:
                return
            if not isinstance(item, WatchEvent):  # defensive: the queue only ever carries events or _STOP
                continue
            try:
                ok = self._deliver(item)
            except Exception:
                log.exception("unexpected webhook failure")
                ok = False
            with self._lock:
                if ok:
                    self.sent += 1
                else:
                    self.failed += 1

    def _body(self, event: WatchEvent) -> bytes:
        payload = (
            slack_payload(event)
            if self.cfg.kind == "slack"
            else generic_payload(event, include_report=self.cfg.include_report)
        )
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _deliver(self, event: WatchEvent) -> bool:
        body = self._body(event)
        where = redact_url(self.cfg.url)
        for attempt_no in range(1, self.cfg.retries + 1):
            ts = str(int(self._clock()))
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"netdoctor/{__version__}",
                "X-NetDoctor-Event": event.event,
                "X-NetDoctor-Timestamp": ts,
            }
            if self.cfg.secret:
                headers["X-NetDoctor-Signature"] = sign(self.cfg.secret, ts, body)
            result = self._send(self.cfg, body, headers)
            if result.ok:
                return True
            log.warning(
                "webhook %s attempt %d/%d failed: %s",
                where,
                attempt_no,
                self.cfg.retries,
                result.error or f"HTTP {result.status}",
            )
            if not result.retryable or attempt_no == self.cfg.retries:
                return False
            delay = result.retry_after
            if delay is None:
                delay = self._backoff_base * (2 ** (attempt_no - 1)) * self._jitter()
            self._sleep(delay)
        return False  # pragma: no cover - loop always returns
