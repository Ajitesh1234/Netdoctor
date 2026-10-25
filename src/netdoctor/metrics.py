"""Prometheus / OpenMetrics-compatible exposition and a tiny, hardened ``/metrics`` server.

* :func:`render_prometheus` is a pure function: one-shot runs can write its output to a file for
  the node_exporter *textfile collector*, and watch mode serves it live.
* Units follow Prometheus conventions (seconds, ratios) and every sample of a metric is grouped
  under a single ``# HELP`` / ``# TYPE`` header, as the text format requires.
* Label values come from user input (target names), so they are fully escaped.
* :class:`MetricsServer` binds to loopback by default, supports an optional bearer token
  (constant-time comparison) and applies a socket timeout to every connection.
"""

from __future__ import annotations

import hmac
import http.server
import ipaddress
import logging
import os
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from . import __version__
from .models import SessionReport, Severity, Status, TargetReport

log = logging.getLogger(__name__)

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
Labels = tuple[tuple[str, str], ...]


def escape_label(value: str) -> str:
    """Escape a label value per the Prometheus text format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(value: float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if float(value).is_integer() and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


@dataclass
class _Family:
    kind: str
    help: str
    samples: list[tuple[Labels, float]] = field(default_factory=list)


class _Registry:
    def __init__(self) -> None:
        self._families: dict[str, _Family] = {}

    def add(self, name: str, kind: str, help_: str, value: float | None, **labels: str) -> None:
        if value is None:
            return
        fam = self._families.setdefault(name, _Family(kind, help_))
        fam.samples.append((tuple(labels.items()), value))

    def render(self) -> str:
        out: list[str] = []
        for name, fam in self._families.items():
            out.append(f"# HELP {name} {fam.help}")
            out.append(f"# TYPE {name} {fam.kind}")
            for labels, value in fam.samples:
                lab = ",".join(f'{k}="{escape_label(v)}"' for k, v in labels)
                out.append(f"{name}{{{lab}}} {_fmt(value)}" if lab else f"{name} {_fmt(value)}")
        return "\n".join(out) + "\n"


def _add_target(reg: _Registry, rep: TargetReport) -> None:
    t = rep.target
    for st in Status:
        reg.add(
            "netdoctor_target_status",
            "gauge",
            "1 for the target's current overall status, else 0.",
            float(rep.status is st),
            target=t,
            status=st.value,
        )
    reg.add(
        "netdoctor_target_healthy",
        "gauge",
        "1 if the target is healthy (no warnings or failures).",
        float(rep.status is Status.HEALTHY),
        target=t,
    )
    reg.add(
        "netdoctor_check_duration_seconds",
        "gauge",
        "Wall time of the last full diagnosis.",
        rep.duration_ms / 1000,
        target=t,
    )
    if rep.dns:
        reg.add("netdoctor_dns_ok", "gauge", "1 if the system resolver answered.", float(rep.dns.ok), target=t)
        if rep.dns.latency_ms is not None:
            reg.add(
                "netdoctor_dns_resolution_seconds",
                "gauge",
                "System resolver lookup time.",
                rep.dns.latency_ms / 1000,
                target=t,
            )
    for tc in rep.tcp:
        lab = {"target": t, "port": str(tc.port), "family": tc.family}
        reg.add("netdoctor_tcp_ok", "gauge", "1 if at least one TCP handshake succeeded.", float(tc.ok), **lab)
        reg.add("netdoctor_tcp_loss_ratio", "gauge", "Share of failed TCP handshakes (0..1).", tc.loss_pct / 100, **lab)
        if tc.avg_ms is not None:
            reg.add("netdoctor_tcp_connect_seconds", "gauge", "Average TCP handshake time.", tc.avg_ms / 1000, **lab)
        if tc.jitter_ms is not None:
            reg.add(
                "netdoctor_tcp_jitter_seconds",
                "gauge",
                "Mean absolute difference of consecutive handshake times.",
                tc.jitter_ms / 1000,
                **lab,
            )
    if rep.tls:
        reg.add(
            "netdoctor_tls_ok",
            "gauge",
            "1 if the TLS handshake and certificate verification succeeded.",
            float(rep.tls.ok),
            target=t,
        )
        if rep.tls.days_to_expiry is not None:
            reg.add(
                "netdoctor_tls_cert_expiry_days",
                "gauge",
                "Days until the served certificate expires.",
                rep.tls.days_to_expiry,
                target=t,
            )
        if rep.tls.handshake_ms is not None:
            reg.add(
                "netdoctor_tls_handshake_seconds", "gauge", "TLS handshake time.", rep.tls.handshake_ms / 1000, target=t
            )
    if rep.http:
        reg.add("netdoctor_http_ok", "gauge", "1 if an HTTP response was received.", float(rep.http.ok), target=t)
        if rep.http.status is not None:
            reg.add("netdoctor_http_status_code", "gauge", "Final HTTP status code.", float(rep.http.status), target=t)
        if rep.http.ttfb_ms is not None:
            reg.add(
                "netdoctor_http_ttfb_seconds",
                "gauge",
                "Time to first byte of the first request.",
                rep.http.ttfb_ms / 1000,
                target=t,
            )
    if rep.icmp and rep.icmp.available:
        reg.add("netdoctor_icmp_ok", "gauge", "1 if ping received a reply.", float(rep.icmp.ok), target=t)
        if rep.icmp.loss_pct is not None:
            reg.add(
                "netdoctor_icmp_loss_ratio",
                "gauge",
                "Share of lost ICMP echo requests (0..1).",
                rep.icmp.loss_pct / 100,
                target=t,
            )
        if rep.icmp.avg_ms is not None:
            reg.add(
                "netdoctor_icmp_rtt_seconds", "gauge", "Average ICMP round-trip time.", rep.icmp.avg_ms / 1000, target=t
            )
    for f in rep.findings:
        if f.severity >= Severity.WARNING:
            reg.add(
                "netdoctor_finding",
                "gauge",
                "1 for each active warning-or-worse finding.",
                1.0,
                target=t,
                code=f.code,
                severity=f.severity.name.lower(),
            )


def render_prometheus(
    session: SessionReport | None,
    *,
    runs: int | None = None,
    errors: int | None = None,
    last_success_ts: float | None = None,
    notifications: tuple[int, int, int] | None = None,
) -> str:
    """Render ``session`` (and optional watch-mode counters) in the Prometheus text format.

    ``notifications`` is ``(sent, failed, dropped)``.
    """
    reg = _Registry()
    reg.add("netdoctor_build_info", "gauge", "NetDoctor version information.", 1.0, version=__version__)
    if runs is not None:
        reg.add("netdoctor_runs_total", "counter", "Diagnostic cycles started since the watcher began.", float(runs))
    if errors is not None:
        reg.add("netdoctor_run_errors_total", "counter", "Cycles that failed with an internal error.", float(errors))
    if last_success_ts is not None:
        reg.add(
            "netdoctor_last_success_timestamp_seconds",
            "gauge",
            "Unix time of the last successful cycle.",
            last_success_ts,
        )
    if notifications is not None:
        sent, failed, dropped = notifications
        reg.add("netdoctor_notifications_sent_total", "counter", "Webhook notifications delivered.", float(sent))
        reg.add(
            "netdoctor_notifications_failed_total",
            "counter",
            "Webhook notifications that failed after all retries.",
            float(failed),
        )
        reg.add(
            "netdoctor_notifications_dropped_total",
            "counter",
            "Webhook notifications dropped because the queue was full.",
            float(dropped),
        )
    if session is not None:
        for rep in session.reports:
            _add_target(reg, rep)
    return reg.render()


# --------------------------------------------------------------------------- server
def _is_loopback(bind: str) -> bool:
    if bind == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


class MetricsServer:
    """Serve ``provider()`` at ``/metrics`` (plus ``/healthz``) on a background thread."""

    def __init__(
        self,
        provider: Callable[[], str],
        *,
        bind: str = "127.0.0.1",
        port: int = 9877,
        token: str | None = None,
        request_timeout: float = 10.0,
    ) -> None:
        self._provider = provider
        self._token = token
        self.bind = bind
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = request_timeout  # slow-client protection
            server_version = "netdoctor"
            sys_version = ""

            def log_message(self, fmt: str, *args: object) -> None:
                log.debug("metrics: " + fmt, *args)

            def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                if not outer._token:
                    return True
                header = self.headers.get("Authorization") or ""
                if not header.startswith("Bearer "):
                    return False
                return hmac.compare_digest(header[7:].strip().encode(), outer._token.encode())

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == "/healthz":
                    self._send(200, b"ok\n")
                elif path == "/metrics":
                    if not self._authorized():
                        self.send_response(401)
                        self.send_header("WWW-Authenticate", 'Bearer realm="netdoctor"')
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    try:
                        body = outer._provider().encode("utf-8")
                    except Exception:
                        log.exception("metrics provider failed")
                        self._send(500, b"internal error\n")
                        return
                    self._send(200, body, CONTENT_TYPE)
                else:
                    self._send(404, b"not found\n")

            def _method_not_allowed(self) -> None:
                self.send_response(405)
                self.send_header("Allow", "GET")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_PUT = do_DELETE = do_PATCH = _method_not_allowed  # noqa: N815

        class _Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            # On Windows SO_REUSEADDR lets another process bind a port that is already in use, i.e. hijack it.
            allow_reuse_address = os.name != "nt"

            def handle_error(self, request: object, client_address: object) -> None:
                # A scraper that disconnects mid-response is routine (and surfaces as a reset error on
                # Windows). The stdlib default prints a traceback to stderr; log quietly instead.
                log.debug("metrics: client %s disconnected or errored", client_address, exc_info=True)

            address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET

        self._httpd = _Server((bind, port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="netdoctor-metrics", daemon=True)

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def start(self) -> int:
        if not _is_loopback(self.bind) and not self._token:
            log.warning(
                "metrics endpoint is bound to %s without a bearer token: anyone who can reach it can read it. "
                "Set a token or put it behind a TLS-terminating proxy.",
                self.bind,
            )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(5)
