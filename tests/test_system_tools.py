"""ICMP / traceroute wrappers and renderers, with the OS binaries mocked out."""

from __future__ import annotations

import subprocess
import sys

import pytest

from netdoctor import report
from netdoctor.checks import icmp, traceroute
from netdoctor.models import (
    DnsResult,
    IcmpResult,
    ResolverAnswer,
    SessionReport,
    TargetReport,
    TcpResult,
    TlsResult,
    TracerouteResult,
)

LINUX = "5 packets transmitted, 5 received, 0% packet loss, time 4006ms\nrtt min/avg/max/mdev = 10.1/12.3/15.5/1.8 ms\n"


def _proc(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


# ------------------------------------------------------------------ icmp
@pytest.mark.parametrize(
    ("platform", "needle"),
    [("linux", "-W"), ("darwin", "-W"), ("win32", "-w"), ("freebsd13", "-c")],
)
def test_ping_command_per_platform(monkeypatch, platform, needle):
    monkeypatch.setattr(sys, "platform", platform)
    cmd = icmp._command("192.0.2.1", 3, 2.0)
    assert needle in cmd and cmd[-1] == "192.0.2.1"
    if platform == "darwin":
        assert cmd[cmd.index("-W") + 1] == "2000"  # macOS takes milliseconds
    if platform == "linux":
        assert cmd[cmd.index("-W") + 1] == "2"  # Linux takes seconds


def test_icmp_missing_binary(monkeypatch):
    monkeypatch.setattr(icmp.shutil, "which", lambda _: None)
    r = icmp.check_icmp("192.0.2.1", 2, 1.0)
    assert not r.ok and not r.available


def test_icmp_success_and_failures(monkeypatch):
    monkeypatch.setattr(icmp.shutil, "which", lambda _: "/bin/ping")
    monkeypatch.setattr(icmp.subprocess, "run", lambda *a, **k: _proc(LINUX))
    assert icmp.check_icmp("192.0.2.1", 5, 1.0).avg_ms == 12.3

    monkeypatch.setattr(icmp.subprocess, "run", lambda *a, **k: _proc("junk", "ping: bad", 2))
    r = icmp.check_icmp("192.0.2.1", 5, 1.0)
    assert not r.ok and r.error == "ping: bad"

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("ping", 1)

    monkeypatch.setattr(icmp.subprocess, "run", boom)
    assert icmp.check_icmp("192.0.2.1", 5, 1.0).error == "ping timed out"

    def oserr(*a, **k):
        raise PermissionError("nope")

    monkeypatch.setattr(icmp.subprocess, "run", oserr)
    assert not icmp.check_icmp("192.0.2.1", 5, 1.0).available


# ------------------------------------------------------------------ traceroute
def test_traceroute_parses_hops(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(traceroute.shutil, "which", lambda _: "/usr/bin/traceroute")
    out = b"traceroute to 192.0.2.1\n 1  10.0.0.1  1.2 ms\n 2  * \n 3  192.0.2.1  9.9 ms\n"
    monkeypatch.setattr(traceroute.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, out, b""))
    r = traceroute.check_traceroute("192.0.2.1")
    assert r.ok and len(r.hops) == 3 and not r.truncated


def test_traceroute_missing_failed_and_truncated(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(traceroute.shutil, "which", lambda _: None)
    assert not traceroute.check_traceroute("192.0.2.1").available

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(traceroute.shutil, "which", lambda _: "/usr/bin/traceroute")
    monkeypatch.setattr(
        traceroute.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, b"", b"network down")
    )
    assert traceroute.check_traceroute("192.0.2.1").error == "network down"

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("traceroute", 1, output=b" 1  10.0.0.1  1 ms\n")

    monkeypatch.setattr(traceroute.subprocess, "run", slow)
    r = traceroute.check_traceroute("192.0.2.1")
    assert r.ok and r.truncated and r.hops == [" 1  10.0.0.1  1 ms"]


# ------------------------------------------------------------------ renderers (full detail)
@pytest.fixture()
def rich_session() -> SessionReport:
    rep = TargetReport("example.com", "example.com")
    rep.dns = DnsResult(True, ["93.184.216.34"], 12.0, public=[ResolverAnswer("1.1.1.1", True, ["93.184.216.34"])])
    rep.tcp = [
        TcpResult(443, "93.184.216.34", "ipv4", 5, 4, 20.0, 10, 12, 15, 2),
        TcpResult(80, "93.184.216.34", "ipv4", 5, 0, 100.0, error="t", error_kind="timeout"),
    ]
    rep.tls = TlsResult(True, version="TLSv1.3", issuer="Example CA", days_to_expiry=40.0, handshake_ms=20)
    rep.icmp = IcmpResult(True, sent=5, received=5, loss_pct=0.0, avg_ms=11, jitter_ms=1)
    rep.traceroute = TracerouteResult(True, hops=[" 1  10.0.0.1  1 ms"], truncated=True)
    return SessionReport("1.0.0", "2026-01-01T00:00:00Z", [rep])


def test_all_rows_render(rich_session):
    text = report.render_text(rich_session, ascii_only=True)
    for needle in ("DNS", "TCP 443/v4", "TCP 80/v4", "TLS", "ICMP", "TRACE", "(truncated)", "Traceroute:"):
        assert needle in text, needle
    md = report.render_markdown(rich_session)
    assert "### Traceroute" in md and "```text" in md


def test_failure_rows_render():
    rep = TargetReport("x.test", "x.test")
    rep.dns = DnsResult(False, error="boom", error_kind="nxdomain")
    rep.tcp = [TcpResult(443, "1.1.1.1", "ipv4", 2, 0, 100.0, error="t", error_kind="timeout")]
    rep.tls = TlsResult(False, error="t", error_kind="timeout")
    rep.icmp = IcmpResult(False, error="no reply")
    rep.traceroute = TracerouteResult(False, error="failed")
    text = report.render_text(SessionReport("1", "now", [rep]), ascii_only=True)
    assert "nxdomain" in text and "(follows from TCP failure)" in text and "no reply" in text


def test_unavailable_tools_are_reported_not_hidden():
    rep = TargetReport("x.test", "x.test")
    rep.icmp = IcmpResult(False, available=False, error="ping executable not found")
    rep.traceroute = TracerouteResult(False, available=False, error="traceroute executable not found")
    text = report.render_text(SessionReport("1", "now", [rep]), ascii_only=True)
    assert "not run: ping executable not found" in text
    assert "not run: traceroute executable not found" in text
