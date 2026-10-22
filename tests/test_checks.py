from __future__ import annotations

import ssl

import pytest

from netdoctor.checks import http as http_check
from netdoctor.checks import tcp, tls
from netdoctor.checks.util import classify_exception, run_with_timeout
from netdoctor.config import Config
from netdoctor.target import parse_target

CFG = Config(timeout=2.0, samples=3)


# ------------------------------------------------------------------ tcp
def test_tcp_ok(http_server):
    r = tcp.probe("127.0.0.1", http_server, 4, 1.0)
    assert r.ok and r.successes == 4 and r.loss_pct == 0.0 and r.family == "ipv4"
    assert r.min_ms <= r.avg_ms <= r.max_ms and r.jitter_ms is not None


def test_tcp_refused(closed_port):
    r = tcp.probe("127.0.0.1", closed_port, 2, 1.0)
    assert not r.ok and r.loss_pct == 100.0 and r.error_kind == "refused" and r.avg_ms is None


def test_tcp_single_sample_has_no_jitter(http_server):
    assert tcp.probe("127.0.0.1", http_server, 1, 1.0).jitter_ms is None


# ------------------------------------------------------------------ http
def _fetch(port, path, scheme="http"):
    return http_check.fetch(scheme, "127.0.0.1", port, path, CFG)


def test_http_ok(http_server):
    r = _fetch(http_server, "/ok")
    assert r.ok and r.status == 200 and len(r.hops) == 1 and r.ttfb_ms is not None


def test_http_follows_redirect_chain(http_server):
    r = _fetch(http_server, "/redir2")
    assert r.ok and r.status == 200 and [h.status for h in r.hops] == [301, 302, 200]
    assert r.final_url.endswith("/ok")


def test_http_redirect_loop(http_server):
    r = _fetch(http_server, "/loop")
    assert not r.ok and r.error_kind == "redirect_loop"


def test_http_too_many_redirects(http_server):
    r = http_check.fetch("http", "127.0.0.1", http_server, "/redir2", Config(max_redirects=1))
    assert not r.ok and r.error_kind == "too_many_redirects"


def test_http_bad_redirect_scheme(http_server):
    assert _fetch(http_server, "/badscheme").error_kind == "bad_redirect"


@pytest.mark.parametrize(("path", "status"), [("/forbidden", 403), ("/gone", 451), ("/boom", 503), ("/nope", 404)])
def test_http_error_statuses_are_results_not_failures(http_server, path, status):
    r = _fetch(http_server, path)
    assert r.ok and r.status == status


def test_http_connection_refused(closed_port):
    r = _fetch(closed_port, "/")
    assert not r.ok and r.error_kind == "refused"


def test_http_fallback_from_https(http_server):
    r = http_check.check_http(parse_target(f"127.0.0.1:{http_server}/ok"), CFG)
    assert r.ok and r.scheme == "http" and r.fell_back_from_https and r.https_error_kind


# ------------------------------------------------------------------ tls
def test_tls_untrusted_self_signed(tls_server, monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    r = tls.check_tls("localhost", tls_server, 2.0)
    assert not r.ok and r.error_kind in ("self_signed", "untrusted_issuer")


def test_tls_success_when_trusted(tls_server, tls_cert, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_cert / "c.pem"))
    r = tls.check_tls("localhost", tls_server, 2.0)
    assert r.ok, r.error
    assert r.version in ("TLSv1.2", "TLSv1.3") and r.subject == "localhost"
    assert 3 < r.days_to_expiry <= 5 and "localhost" in r.san and r.handshake_ms > 0


def test_tls_ip_literal_is_verified_against_ip_san(tls_server, tls_cert, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_cert / "c.pem"))
    r = tls.check_tls("127.0.0.1", tls_server, 2.0)
    assert r.ok, r.error


def test_tls_against_plain_http_server_fails_cleanly(http_server):
    r = tls.check_tls("127.0.0.1", http_server, 2.0)
    assert not r.ok and r.error_kind in ("tls_error", "reset", "timeout")


def test_https_http_check_end_to_end(tls_server, tls_cert, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_cert / "c.pem"))
    r = http_check.check_http(parse_target(f"https://localhost:{tls_server}/ok"), CFG)
    assert r.ok and r.scheme == "https" and not r.fell_back_from_https


def test_cert_error_does_not_fall_back_to_http(tls_server, monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    r = http_check.check_http(parse_target(f"localhost:{tls_server}"), CFG)
    assert not r.ok and r.error_kind in ("self_signed", "untrusted_issuer") and not r.fell_back_from_https


# ------------------------------------------------------------------ util
@pytest.mark.parametrize(
    ("code", "kind"),
    [
        (10, "cert_expired"),
        (9, "cert_not_yet_valid"),
        (62, "hostname_mismatch"),
        (18, "self_signed"),
        (20, "untrusted_issuer"),
        (999, "cert_invalid"),
    ],
)
def test_cert_verify_codes(code, kind):
    exc = ssl.SSLCertVerificationError(1, "x")
    exc.verify_code = code
    assert classify_exception(exc) == kind


def test_classify_misc():
    assert classify_exception(TimeoutError()) == "timeout"
    assert classify_exception(ConnectionResetError()) == "reset"
    assert classify_exception(ValueError()) == "error"


def test_run_with_timeout():
    import time

    assert run_with_timeout(lambda: 5, 1) == 5
    with pytest.raises(TimeoutError):
        run_with_timeout(lambda: time.sleep(2), 0.1)
    with pytest.raises(KeyError):
        run_with_timeout(lambda: {}["x"], 1)
