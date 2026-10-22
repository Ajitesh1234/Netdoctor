"""Root-cause analysis: turn raw check results into ranked, actionable findings.

Design rules
------------
* Report the *root cause*, suppress downstream noise (a TCP timeout explains the HTTP
  timeout; an expired certificate explains the failed HTTPS request).
* Be honest about uncertainty. Anything that could have an innocent explanation (CDN
  geo-DNS, bot protection, blocked ICMP) is worded as a possibility, never a verdict.
"""

from __future__ import annotations

import ipaddress

from .checks.util import CERT_ERROR_KINDS
from .config import Config
from .models import Finding, Severity, Status, TargetReport, TcpResult

CRIT, WARN, INFO, OK = Severity.CRITICAL, Severity.WARNING, Severity.INFO, Severity.OK


def analyze(rep: TargetReport, cfg: Config, *, is_ip: bool = False) -> None:
    """Populate ``rep.findings``, ``rep.status`` and ``rep.summary`` in place."""
    findings: list[Finding] = []
    if not _dns(rep, cfg, findings, is_ip):
        _finish(rep, findings)
        return
    tcp_dead = _tcp(rep, cfg, findings)
    if not tcp_dead:
        _tls(rep, cfg, findings)
        _http(rep, cfg, findings)
    _icmp(rep, cfg, findings, tcp_ok=not tcp_dead)
    _finish(rep, findings)


# --------------------------------------------------------------------------- DNS
def _dns(rep: TargetReport, cfg: Config, out: list[Finding], is_ip: bool) -> bool:
    dns = rep.dns
    assert dns is not None
    public_ok = [r for r in dns.public if r.ok]
    public_names = ", ".join(r.server for r in public_ok)

    if not dns.ok:
        kind = dns.error_kind
        if kind == "nxdomain" and public_ok:
            out.append(
                Finding(
                    CRIT,
                    "DNS_BLOCKED_LOCALLY",
                    f"Your system resolver says '{rep.host}' does not exist, but public resolvers "
                    f"({public_names}) return addresses for it.",
                    "Likely DNS-level blocking or a faulty local/ISP resolver. Try switching your "
                    "DNS server (e.g. 1.1.1.1 or 8.8.8.8) or using DNS-over-HTTPS.",
                )
            )
        elif kind == "nxdomain":
            out.append(
                Finding(
                    CRIT,
                    "DNS_NXDOMAIN",
                    f"The domain '{rep.host}' does not exist.",
                    "Check for typos; the domain may be unregistered or expired.",
                )
            )
        elif kind in ("temporary", "timeout"):
            msg = "The system DNS resolver did not answer."
            hint = "Check your network connection and DNS server settings."
            if public_ok:
                msg += f" Public resolvers ({public_names}) work, so the problem is your local resolver."
                hint = "Switch DNS servers or restart your router/resolver."
            out.append(Finding(CRIT, "DNS_UNAVAILABLE", msg, hint))
        else:
            out.append(Finding(CRIT, "DNS_FAILED", f"DNS resolution failed: {dns.error}", None))
        return False

    if not is_ip:
        for addr in dns.addresses:
            ip = ipaddress.ip_address(addr)
            if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
                out.append(
                    Finding(
                        WARN,
                        "DNS_SINKHOLE",
                        f"'{rep.host}' resolves to {addr}, a non-routable address.",
                        "This is a classic DNS-blocking signature (sinkholing) unless the name is intentionally local.",
                    )
                )
                break
            if ip.is_private:
                out.append(
                    Finding(
                        INFO,
                        "DNS_PRIVATE",
                        f"'{rep.host}' resolves to private address {addr}.",
                        "Expected for internal/VPN hosts; unexpected for public sites.",
                    )
                )
                break

        sys_v4 = {a for a in dns.addresses if ":" not in a}
        pub_v4 = {a for r in public_ok for a in r.addresses}
        if sys_v4 and pub_v4 and sys_v4.isdisjoint(pub_v4):
            out.append(
                Finding(
                    INFO,
                    "DNS_MISMATCH",
                    f"System resolver answered {', '.join(sorted(sys_v4))} while public resolvers "
                    f"answered {', '.join(sorted(pub_v4))}.",
                    "Common with CDNs and geo-aware DNS. If the site is also unreachable, this may "
                    "indicate DNS tampering.",
                )
            )

    if dns.latency_ms is not None and dns.latency_ms > cfg.dns_warn_ms and not dns.skipped:
        out.append(
            Finding(
                WARN,
                "DNS_SLOW",
                f"DNS lookup took {dns.latency_ms:.0f} ms.",
                "A slow resolver delays every first connection. Consider a faster DNS provider.",
            )
        )
    return True


# --------------------------------------------------------------------------- TCP
_TCP_KIND_TEXT = {
    "refused": ("actively refused", "Nothing is listening there, or a firewall is rejecting connections."),
    "timeout": ("timed out", "Packets are being dropped: the server is down, or a firewall/ISP is filtering."),
    "unreachable": ("had no route", "A network or routing problem exists between you and the server."),
    "reset": ("was reset", "A middlebox or the server is terminating connections."),
}


def _tcp(rep: TargetReport, cfg: Config, out: list[Finding]) -> bool:
    """Return True when no endpoint was reachable (downstream checks are suppressed)."""
    by_port: dict[int, list[TcpResult]] = {}
    for r in rep.tcp:
        by_port.setdefault(r.port, []).append(r)
    ok_ports = [p for p, rs in by_port.items() if any(r.ok for r in rs)]

    if not ok_ports:
        first = rep.tcp[0] if rep.tcp else None
        verb, hint = _TCP_KIND_TEXT.get(
            (first.error_kind if first else None) or "", ("failed", "The server may be down or blocked.")
        )
        ports = ", ".join(str(p) for p in by_port) or "?"
        out.append(
            Finding(
                CRIT,
                "TCP_UNREACHABLE",
                f"Cannot open a TCP connection to {rep.host} (port {ports}); the attempt {verb}.",
                hint,
            )
        )
        return True

    for port, rs in by_port.items():
        if port in ok_ports:
            if any(not r.ok for r in rs):
                bad = next(r for r in rs if not r.ok)
                out.append(
                    Finding(
                        WARN,
                        "IP_FAMILY_BROKEN",
                        f"{bad.family.replace('ipv', 'IPv')} ({bad.address}) is unreachable on port {port}, but the other IP family works.",
                        "Browsers may stall before falling back. Fix or disable the broken IP family.",
                    )
                )
        elif port == 443:
            out.append(
                Finding(
                    WARN,
                    "TCP_443_UNREACHABLE",
                    "Port 443 (HTTPS) is unreachable although another port answers.",
                    "The site may not offer HTTPS, or HTTPS is being filtered.",
                )
            )
        else:
            out.append(Finding(INFO, "TCP_PORT_CLOSED", f"Port {port} is not reachable (other ports are)."))

    primary = ok_ports[0]
    for r in (x for x in by_port[primary] if x.ok):
        label = f"{r.address}:{r.port}"
        if r.loss_pct >= 50:
            out.append(
                Finding(
                    CRIT,
                    "TCP_HEAVY_LOSS",
                    f"{r.loss_pct:.0f}% of connection attempts to {label} failed.",
                    "Severe packet loss or an overloaded server; the connection is barely usable.",
                )
            )
        elif r.loss_pct > 0:
            out.append(
                Finding(
                    WARN,
                    "TCP_PACKET_LOSS",
                    f"{r.loss_pct:.0f}% of connection attempts to {label} failed ({r.successes}/{r.attempts} succeeded).",
                    "Intermittent loss causes retries and stalls. Check Wi-Fi/ISP quality.",
                )
            )
        if r.avg_ms is not None and r.avg_ms > cfg.latency_warn_ms:
            out.append(
                Finding(
                    WARN,
                    "HIGH_LATENCY",
                    f"Connection latency to {label} is high ({r.avg_ms:.0f} ms average).",
                    "Expect sluggish browsing. Distance, congestion or a poor route may be the cause.",
                )
            )
        if r.jitter_ms is not None and r.jitter_ms > cfg.jitter_warn_ms:
            out.append(
                Finding(
                    WARN,
                    "HIGH_JITTER",
                    f"Latency to {label} is unstable (jitter {r.jitter_ms:.0f} ms).",
                    "Calls and games suffer most. Look for congestion or a flaky Wi-Fi link.",
                )
            )
    return False


# --------------------------------------------------------------------------- TLS
def _tls(rep: TargetReport, cfg: Config, out: list[Finding]) -> None:
    tls = rep.tls
    if tls is None:
        return
    if not tls.ok and rep.http and rep.http.fell_back_from_https:
        return  # reported once, as HTTPS_UNAVAILABLE
    if tls.ok:
        if tls.days_to_expiry is not None and tls.days_to_expiry <= cfg.cert_expiry_warn_days:
            out.append(
                Finding(
                    WARN,
                    "TLS_EXPIRING_SOON",
                    f"The certificate expires in {tls.days_to_expiry:.0f} day(s) ({tls.not_after}).",
                    "The site owner must renew it before browsers start rejecting the site.",
                )
            )
        return
    kind = tls.error_kind
    table = {
        "cert_expired": (
            CRIT,
            "TLS_CERT_EXPIRED",
            "The server's certificate has expired.",
            "Browsers will block the site. The owner must renew it (also check that your system clock is correct).",
        ),
        "cert_not_yet_valid": (
            CRIT,
            "TLS_CERT_NOT_YET_VALID",
            "The certificate is not valid yet.",
            "Check that your system clock and date are correct.",
        ),
        "hostname_mismatch": (
            CRIT,
            "TLS_HOSTNAME_MISMATCH",
            f"The certificate is not valid for '{rep.host}'.",
            "Misconfigured server, or you are being redirected/intercepted.",
        ),
        "self_signed": (
            CRIT,
            "TLS_SELF_SIGNED",
            "The server presents a self-signed certificate.",
            "Browsers will warn or block. Expected only for internal/dev hosts.",
        ),
        "untrusted_issuer": (
            WARN,
            "TLS_UNTRUSTED_ISSUER",
            "The certificate was issued by an unknown authority.",
            "Common behind corporate proxies or antivirus TLS inspection, or with an outdated CA store.",
        ),
        "cert_invalid": (CRIT, "TLS_CERT_INVALID", f"Certificate verification failed: {tls.error}", None),
    }
    if kind in table:
        sev, code, msg, hint = table[kind]
        out.append(Finding(sev, code, msg, hint))
    elif kind in ("reset", "timeout"):
        out.append(
            Finding(
                WARN,
                "TLS_INTERFERENCE",
                f"TCP connects fine but the TLS handshake {'was reset' if kind == 'reset' else 'timed out'}.",
                "Possible SNI-based filtering, a firewall or an overloaded server. Compare from another network.",
            )
        )
    else:
        out.append(
            Finding(
                WARN,
                "TLS_HANDSHAKE_FAILED",
                f"TLS handshake failed: {tls.error}",
                "Possible protocol/cipher incompatibility (TLS 1.2+ is required) or server misconfiguration.",
            )
        )


# --------------------------------------------------------------------------- HTTP
def _http(rep: TargetReport, cfg: Config, out: list[Finding]) -> None:
    http = rep.http
    if http is None:
        return
    if http.fell_back_from_https:
        out.append(
            Finding(
                WARN,
                "HTTPS_UNAVAILABLE",
                f"HTTPS failed ({http.https_error_kind}) but plain HTTP works.",
                "Traffic would be unencrypted; the site may lack HTTPS or HTTPS is being blocked.",
            )
        )

    if not http.ok:
        if http.error_kind in CERT_ERROR_KINDS or (
            rep.tls and not rep.tls.ok and http.error_kind == rep.tls.error_kind
        ):
            return  # already explained by the TLS finding
        explain = {
            "timeout": "The server accepts connections but never answers (overloaded, hung, or tar-pitting).",
            "reset": "The connection was reset after it was established.",
            "redirect_loop": "The site redirects in a loop.",
            "too_many_redirects": "The site redirects too many times.",
        }.get(http.error_kind or "", f"The HTTP request failed: {http.error}")
        out.append(
            Finding(WARN, "HTTP_FAILED", explain, "Retry later; if it persists the server or a middlebox is at fault.")
        )
        return

    s = http.status or 0
    if s == 451:
        out.append(
            Finding(
                CRIT,
                "HTTP_LEGAL_BLOCK",
                "HTTP 451: unavailable for legal reasons.",
                "This is deliberate blocking (court order or government request).",
            )
        )
    elif s == 403:
        out.append(
            Finding(
                WARN,
                "HTTP_FORBIDDEN",
                "HTTP 403: the server refused the request.",
                "Could be geo-blocking, IP reputation, or bot protection (this probe is not a browser). If it works in your browser, it is likely bot protection.",
            )
        )
    elif s == 429:
        out.append(
            Finding(WARN, "HTTP_RATE_LIMITED", "HTTP 429: you are being rate limited.", "Wait a while before retrying.")
        )
    elif s == 401:
        out.append(Finding(INFO, "HTTP_AUTH_REQUIRED", "HTTP 401: the page requires authentication."))
    elif s == 404:
        out.append(
            Finding(
                WARN,
                "HTTP_NOT_FOUND",
                "HTTP 404: the page was not found.",
                "The server is up, but this path does not exist.",
            )
        )
    elif s >= 500:
        out.append(
            Finding(
                CRIT,
                "HTTP_SERVER_ERROR",
                f"HTTP {s} {http.reason}: the server is reachable but failing.",
                "The problem is on the server side, not your network.",
            )
        )
    elif s >= 400:
        out.append(Finding(WARN, "HTTP_CLIENT_ERROR", f"HTTP {s} {http.reason}: the server rejected the request."))
    elif 300 <= s < 400:
        out.append(Finding(INFO, "HTTP_REDIRECT_UNFOLLOWED", f"HTTP {s}: redirect without a usable Location header."))

    if len(http.hops) > 1 and s < 400:
        out.append(Finding(INFO, "HTTP_REDIRECTED", f"Followed {len(http.hops) - 1} redirect(s) to {http.final_url}."))
    if http.ttfb_ms is not None and http.ttfb_ms > cfg.ttfb_warn_ms:
        out.append(
            Finding(
                WARN,
                "SLOW_RESPONSE",
                f"The server took {http.ttfb_ms:.0f} ms to start responding.",
                "A slow server (not your network) is the likely cause if TCP latency is low.",
            )
        )


# --------------------------------------------------------------------------- ICMP
def _icmp(rep: TargetReport, cfg: Config, out: list[Finding], *, tcp_ok: bool) -> None:
    icmp = rep.icmp
    if icmp is None or not icmp.available:
        return
    if not icmp.ok:
        if tcp_ok:
            out.append(
                Finding(
                    INFO,
                    "ICMP_BLOCKED",
                    "Ping got no reply, but TCP works.",
                    "Many servers and networks drop ICMP; this is usually harmless.",
                )
            )
        return
    if icmp.loss_pct and icmp.loss_pct > 0:
        out.append(
            Finding(
                WARN,
                "ICMP_PACKET_LOSS",
                f"Ping shows {icmp.loss_pct:.0f}% packet loss.",
                "Genuine path loss is likely; check your link and ISP.",
            )
        )


# --------------------------------------------------------------------------- verdict
def _finish(rep: TargetReport, findings: list[Finding]) -> None:
    findings.sort(key=lambda f: -int(f.severity))
    worst = max((f.severity for f in findings), default=OK)
    if worst >= CRIT:
        rep.status = Status.FAILING
    elif worst == WARN:
        rep.status = Status.DEGRADED
    else:
        rep.status = Status.HEALTHY
    if worst < WARN:
        findings.append(Finding(OK, "ALL_CLEAR", "No problems detected."))
    top = next((f for f in findings if f.severity >= WARN), None)
    rep.summary = top.message if top else "No problems detected."
    rep.findings = findings
