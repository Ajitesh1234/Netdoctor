"""Table-driven tests of the diagnosis engine using hand-built check results."""

from __future__ import annotations

from netdoctor.analysis import analyze
from netdoctor.config import Config
from netdoctor.models import (
    DnsResult,
    HttpHop,
    HttpResult,
    IcmpResult,
    ResolverAnswer,
    Status,
    TargetReport,
    TcpResult,
    TlsResult,
)

CFG = Config()


def tcp(port=443, ok=True, avg=20.0, jitter=2.0, loss=0.0, addr="93.184.216.34", kind="timeout"):
    n = 5
    succ = round(n * (1 - loss / 100)) if ok else 0
    return TcpResult(
        port,
        addr,
        "ipv6" if ":" in addr else "ipv4",
        n,
        succ,
        loss,
        avg_ms=avg if succ else None,
        jitter_ms=jitter if succ else None,
        error=None if succ else "err",
        error_kind=None if succ else kind,
    )


def good_tls(days=60.0):
    return TlsResult(True, version="TLSv1.3", days_to_expiry=days, not_after="2030-01-01T00:00:00Z")


def good_http(status=200, ttfb=80.0, hops=1):
    return HttpResult(
        True,
        "https",
        "https://x/",
        status,
        "OK",
        10,
        ttfb,
        ttfb + 10,
        hops=[HttpHop("https://x/", status, "OK", 10, ttfb)] * hops,
    )


def report(**kw):
    rep = TargetReport("x", "x.test")
    rep.dns = kw.pop(
        "dns", DnsResult(True, ["93.184.216.34"], 20.0, public=[ResolverAnswer("1.1.1.1", True, ["93.184.216.34"])])
    )
    rep.tcp = kw.pop("tcp", [tcp(443), tcp(80)])
    rep.tls = kw.pop("tls", good_tls())
    rep.http = kw.pop("http", good_http())
    rep.icmp = kw.pop("icmp", None)
    for k, v in kw.items():
        setattr(rep, k, v)
    analyze(rep, CFG)
    return rep


def codes(rep):
    return {f.code for f in rep.findings}


def test_healthy():
    r = report()
    assert r.status is Status.HEALTHY and codes(r) == {"ALL_CLEAR"} and r.summary == "No problems detected."


def test_dns_nxdomain_everywhere():
    r = report(
        dns=DnsResult(
            False,
            error="x",
            error_kind="nxdomain",
            public=[ResolverAnswer("1.1.1.1", False, rcode=3, error_kind="nxdomain")],
        )
    )
    assert r.status is Status.FAILING and codes(r) == {"DNS_NXDOMAIN"}


def test_dns_blocked_locally():
    r = report(
        dns=DnsResult(False, error="x", error_kind="nxdomain", public=[ResolverAnswer("1.1.1.1", True, ["1.2.3.4"])])
    )
    assert codes(r) == {"DNS_BLOCKED_LOCALLY"} and "1.1.1.1" in r.findings[0].message


def test_dns_resolver_down_but_public_works():
    r = report(
        dns=DnsResult(False, error="x", error_kind="timeout", public=[ResolverAnswer("8.8.8.8", True, ["1.2.3.4"])])
    )
    assert codes(r) == {"DNS_UNAVAILABLE"} and "local resolver" in r.findings[0].message


def test_dns_failure_short_circuits():
    r = report(dns=DnsResult(False, error="x", error_kind="nxdomain"), http=good_http(), tls=good_tls())
    assert codes(r) == {"DNS_NXDOMAIN"}


def test_dns_sinkhole():
    r = report(dns=DnsResult(True, ["0.0.0.0"], 10.0))
    assert "DNS_SINKHOLE" in codes(r) and r.status is Status.DEGRADED


def test_dns_private_is_only_info():
    r = report(dns=DnsResult(True, ["10.0.0.5"], 10.0))
    assert "DNS_PRIVATE" in codes(r) and r.status is Status.HEALTHY


def test_dns_mismatch_is_info_only():
    r = report(dns=DnsResult(True, ["93.184.216.34"], 10.0, public=[ResolverAnswer("1.1.1.1", True, ["151.101.1.69"])]))
    assert "DNS_MISMATCH" in codes(r) and r.status is Status.HEALTHY


def test_dns_slow():
    assert "DNS_SLOW" in codes(report(dns=DnsResult(True, ["93.184.216.34"], 900.0)))


def test_tcp_dead_suppresses_downstream_noise():
    r = report(
        tcp=[tcp(443, ok=False), tcp(80, ok=False)],
        tls=TlsResult(False, error="t", error_kind="timeout"),
        http=HttpResult(False, error="t", error_kind="timeout"),
        icmp=IcmpResult(False, error="none"),
    )
    assert r.status is Status.FAILING and codes(r) == {"TCP_UNREACHABLE"}


def test_tcp_refused_message():
    r = report(tcp=[tcp(443, ok=False, kind="refused")])
    assert "refused" in r.findings[0].message


def test_port_80_closed_is_info():
    r = report(tcp=[tcp(443), tcp(80, ok=False)])
    assert "TCP_PORT_CLOSED" in codes(r) and r.status is Status.HEALTHY


def test_port_443_closed_warns():
    r = report(tcp=[tcp(443, ok=False), tcp(80)])
    assert "TCP_443_UNREACHABLE" in codes(r) and r.status is Status.DEGRADED


def test_ipv6_broken():
    r = report(tcp=[tcp(443), tcp(443, ok=False, addr="2001:db8::1")])
    assert "IP_FAMILY_BROKEN" in codes(r)


def test_loss_latency_jitter_thresholds():
    r = report(tcp=[tcp(443, avg=400, jitter=80, loss=40)])
    assert {"TCP_PACKET_LOSS", "HIGH_LATENCY", "HIGH_JITTER"} <= codes(r)
    assert report(tcp=[tcp(443, loss=60)]).status is Status.FAILING


def test_tls_expiring():
    assert "TLS_EXPIRING_SOON" in codes(report(tls=good_tls(days=3)))


def test_tls_failures_by_kind():
    for kind, code, status in [
        ("cert_expired", "TLS_CERT_EXPIRED", Status.FAILING),
        ("hostname_mismatch", "TLS_HOSTNAME_MISMATCH", Status.FAILING),
        ("self_signed", "TLS_SELF_SIGNED", Status.FAILING),
        ("untrusted_issuer", "TLS_UNTRUSTED_ISSUER", Status.DEGRADED),
        ("reset", "TLS_INTERFERENCE", Status.DEGRADED),
        ("tls_error", "TLS_HANDSHAKE_FAILED", Status.DEGRADED),
    ]:
        r = report(tls=TlsResult(False, error="e", error_kind=kind), http=HttpResult(False, error="e", error_kind=kind))
        assert code in codes(r) and r.status is status, kind
        assert "HTTP_FAILED" not in codes(r), "http failure must be explained by the TLS finding"


def test_https_fallback_reported_once():
    http = good_http()
    http.fell_back_from_https, http.https_error_kind = True, "tls_error"
    r = report(tls=TlsResult(False, error="e", error_kind="tls_error"), http=http)
    assert "HTTPS_UNAVAILABLE" in codes(r) and "TLS_HANDSHAKE_FAILED" not in codes(r)


def test_http_statuses():
    expect = {
        403: ("HTTP_FORBIDDEN", Status.DEGRADED),
        404: ("HTTP_NOT_FOUND", Status.DEGRADED),
        429: ("HTTP_RATE_LIMITED", Status.DEGRADED),
        451: ("HTTP_LEGAL_BLOCK", Status.FAILING),
        503: ("HTTP_SERVER_ERROR", Status.FAILING),
        401: ("HTTP_AUTH_REQUIRED", Status.HEALTHY),
        418: ("HTTP_CLIENT_ERROR", Status.DEGRADED),
    }
    for status, (code, st) in expect.items():
        r = report(http=good_http(status))
        assert code in codes(r) and r.status is st, status


def test_http_redirect_info_and_slow():
    r = report(http=good_http(ttfb=3000, hops=3))
    assert {"HTTP_REDIRECTED", "SLOW_RESPONSE"} <= codes(r)


def test_http_failed_without_tls_explanation():
    r = report(http=HttpResult(False, error="e", error_kind="timeout"))
    assert (
        "HTTP_FAILED" in codes(r) and "never answers" in next(f for f in r.findings if f.code == "HTTP_FAILED").message
    )


def test_icmp_blocked_is_info_and_loss_warns():
    assert report(icmp=IcmpResult(False, error="x")).status is Status.HEALTHY
    assert "ICMP_BLOCKED" in codes(report(icmp=IcmpResult(False, error="x")))
    assert "ICMP_PACKET_LOSS" in codes(report(icmp=IcmpResult(True, loss_pct=20.0)))
    assert not codes(report(icmp=IcmpResult(False, available=False))) - {"ALL_CLEAR"}


def test_findings_sorted_worst_first_and_summary_is_worst():
    r = report(tcp=[tcp(443, loss=40)], http=good_http(503))
    assert r.findings[0].severity >= r.findings[-1].severity
    assert r.summary == r.findings[0].message and r.status is Status.FAILING
