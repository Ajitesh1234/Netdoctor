"""Prometheus exposition and the /metrics server."""

from __future__ import annotations

import http.client
import logging
import re

import pytest

from netdoctor import __version__
from netdoctor.metrics import MetricsServer, escape_label, render_prometheus
from netdoctor.models import (
    DnsResult,
    Finding,
    HttpResult,
    IcmpResult,
    SessionReport,
    Severity,
    Status,
    TargetReport,
    TcpResult,
    TlsResult,
)

SAMPLE = re.compile(
    r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?:[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\.)*",?)*\})? (-?[0-9.e+-]+|NaN|\+Inf|-Inf)$'
)


def full_report(target="shop.example") -> TargetReport:
    return TargetReport(
        target,
        target,
        dns=DnsResult(True, ["1.2.3.4"], 12.5),
        tcp=[
            TcpResult(443, "1.2.3.4", "ipv4", 5, 4, 20.0, 10, 12.5, 15, 2.5),
            TcpResult(443, "2001:db8::1", "ipv6", 5, 0, 100.0, error="t", error_kind="timeout"),
        ],
        tls=TlsResult(True, version="TLSv1.3", days_to_expiry=40.5, handshake_ms=30.0),
        http=HttpResult(True, "https", "https://x/", 200, "OK", 10, 250.0, 300),
        icmp=IcmpResult(True, sent=5, received=4, loss_pct=20.0, avg_ms=11.0),
        findings=[Finding(Severity.WARNING, "TCP_PACKET_LOSS", "m"), Finding(Severity.INFO, "DNS_MISMATCH", "m")],
        status=Status.DEGRADED,
        duration_ms=1500.0,
    )


def parse_exposition(text: str):
    """Minimal validator for the Prometheus text format: returns {name: [(labels_str, value)]}."""
    families: dict[str, list[tuple[str, str]]] = {}
    typed: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()
    current = None
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ", 3)
            assert name not in typed, f"duplicate TYPE for {name}"
            typed[name] = kind
            current = name
        elif line.startswith("# HELP "):
            continue
        else:
            m = SAMPLE.match(line)
            assert m, f"not valid exposition syntax: {line!r}"
            name, labels = m.group(1), m.group(2) or ""
            assert name == current, f"{name} sample is not grouped under its own TYPE header"
            assert (name, labels) not in seen, f"duplicate series {name}{labels}"
            seen.add((name, labels))
            families.setdefault(name, []).append((labels, m.group(3)))
    assert text.endswith("\n")
    return families


def test_escape_label():
    assert escape_label('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


def test_output_is_valid_exposition_format():
    fams = parse_exposition(render_prometheus(SessionReport("t", "n", [full_report("a.test"), full_report("b.test")])))
    assert len(fams["netdoctor_target_status"]) == 6  # 2 targets x 3 states
    assert fams["netdoctor_build_info"] == [(f'{{version="{__version__}"}}', "1")]


def test_values_use_base_units_and_ratios():
    fams = parse_exposition(render_prometheus(SessionReport("t", "n", [full_report()])))
    one = lambda name: dict(fams[name])  # noqa: E731
    assert one("netdoctor_dns_resolution_seconds")['{target="shop.example"}'] == "0.0125"
    assert one("netdoctor_tcp_loss_ratio")['{target="shop.example",port="443",family="ipv4"}'] == "0.2"
    assert one("netdoctor_tcp_loss_ratio")['{target="shop.example",port="443",family="ipv6"}'] == "1"
    assert one("netdoctor_http_ttfb_seconds")['{target="shop.example"}'] == "0.25"
    assert one("netdoctor_tls_cert_expiry_days")['{target="shop.example"}'] == "40.5"
    assert one("netdoctor_icmp_loss_ratio")['{target="shop.example"}'] == "0.2"
    assert one("netdoctor_check_duration_seconds")['{target="shop.example"}'] == "1.5"


def test_exactly_one_status_is_active_and_findings_are_exported():
    fams = parse_exposition(render_prometheus(SessionReport("t", "n", [full_report()])))
    active = [labels for labels, v in fams["netdoctor_target_status"] if v == "1"]
    assert active == ['{target="shop.example",status="degraded"}']
    assert fams["netdoctor_target_healthy"] == [('{target="shop.example"}', "0")]
    # only warning-or-worse findings: INFO findings are not exported
    assert fams["netdoctor_finding"] == [('{target="shop.example",code="TCP_PACKET_LOSS",severity="warning"}', "1")]


def test_missing_checks_produce_no_series():
    bare = TargetReport("x.test", "x.test", status=Status.HEALTHY)
    text = render_prometheus(SessionReport("t", "n", [bare]))
    assert "netdoctor_tls" not in text and "netdoctor_http" not in text and "netdoctor_tcp" not in text
    parse_exposition(text)


def test_hostile_target_names_cannot_break_the_format():
    evil = 'x"} 1\n# TYPE injected gauge\ninjected{a="b'
    text = render_prometheus(SessionReport("t", "n", [full_report(evil)]))
    parse_exposition(text)  # still syntactically valid
    assert "\ninjected" not in text and "\n# TYPE injected" not in text


def test_watch_counters():
    text = render_prometheus(None, runs=7, errors=2, last_success_ts=1700000000.0, notifications=(5, 1, 3))
    fams = parse_exposition(text)
    assert fams["netdoctor_runs_total"][0][1] == "7" and fams["netdoctor_run_errors_total"][0][1] == "2"
    assert fams["netdoctor_last_success_timestamp_seconds"][0][1] == "1700000000"
    assert [fams[f"netdoctor_notifications_{k}_total"][0][1] for k in ("sent", "failed", "dropped")] == ["5", "1", "3"]


def test_no_counters_unless_requested():
    assert "netdoctor_runs_total" not in render_prometheus(None)


# ------------------------------------------------------------------ server
def get(port, path="/metrics", headers=None, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, headers=headers or {})
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        conn.close()


@pytest.fixture()
def server():
    created: list[MetricsServer] = []

    def make(provider=lambda: "up 1\n", **kw):
        srv = MetricsServer(provider, port=0, **kw)
        srv.start()
        created.append(srv)
        return srv

    yield make
    for s in created:
        s.stop()


def test_serves_metrics_health_and_404(server):
    srv = server(lambda: "netdoctor_x 1\n")
    status, headers, body = get(srv.port)
    assert status == 200 and body == b"netdoctor_x 1\n"
    assert (
        headers["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8" and headers["Cache-Control"] == "no-store"
    )
    assert get(srv.port, "/metrics?x=1")[0] == 200
    assert get(srv.port, "/healthz")[:1] == (200,) and get(srv.port, "/healthz")[2] == b"ok\n"
    assert get(srv.port, "/nope")[0] == 404


def test_only_get_is_allowed(server):
    srv = server()
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        status, headers, _ = get(srv.port, method=method)
        assert status == 405 and headers["Allow"] == "GET"


def test_bearer_token_protects_metrics_but_not_healthz(server):
    srv = server(token="s3cret")
    assert get(srv.port)[0] == 401
    assert get(srv.port, headers={"Authorization": "Bearer wrong"})[0] == 401
    assert get(srv.port, headers={"Authorization": "s3cret"})[0] == 401  # the Bearer scheme is required
    status, _, body = get(srv.port, headers={"Authorization": "Bearer s3cret"})
    assert status == 200 and body == b"up 1\n"
    assert get(srv.port, "/healthz")[0] == 200
    assert "WWW-Authenticate" in get(srv.port)[1]


def test_provider_failure_returns_500_and_the_server_survives(server):
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return "ok 1\n"

    srv = server(flaky)
    assert get(srv.port)[0] == 500
    assert get(srv.port)[0] == 200


def test_stop_releases_the_port(server):
    srv = server()
    port = srv.port
    srv.stop()
    with pytest.raises(OSError):
        get(port)


def test_warns_when_exposed_without_a_token(caplog):
    caplog.set_level(logging.WARNING)
    srv = MetricsServer(lambda: "", bind="0.0.0.0", port=0)
    srv.start()
    try:
        assert "without a bearer token" in caplog.text
    finally:
        srv.stop()
    caplog.clear()
    quiet = MetricsServer(lambda: "", bind="127.0.0.1", port=0)
    quiet.start()
    try:
        assert "without a bearer token" not in caplog.text
    finally:
        quiet.stop()


def test_client_disconnects_are_logged_quietly_not_printed(server, caplog, capsys):
    """The stdlib default prints a traceback banner to stderr (noisy under systemd/Windows); we use debug logs."""
    srv = server()
    caplog.set_level(logging.DEBUG, logger="netdoctor.metrics")
    try:
        raise ConnectionResetError("client went away")
    except ConnectionResetError:
        srv._httpd.handle_error(None, ("127.0.0.1", 12345))
    out = capsys.readouterr()
    assert out.err == "" and out.out == "" and "disconnected or errored" in caplog.text
