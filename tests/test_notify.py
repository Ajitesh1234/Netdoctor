"""Webhook notifier: SSRF policy, DNS pinning, signing, retries, queue behaviour. No internet."""

from __future__ import annotations

import http.server
import json
import socket
import threading

import pytest

from conftest import QuietHTTPServer, server_tls_context
from netdoctor import notify
from netdoctor.models import Finding, Severity, Status
from netdoctor.notify import Attempt, NotifyError, WebhookConfig, WebhookNotifier
from netdoctor.watch import WatchEvent

TS = "2026-01-01T00:00:00Z"


def cfg(port: int, **kw) -> WebhookConfig:
    kw.setdefault("timeout", 3.0)
    return WebhookConfig(url=f"http://127.0.0.1:{port}/hook", allow_http=True, allow_private=True, **kw)


def change_event(**kw) -> WatchEvent:
    base = {
        "event": "change",
        "timestamp": TS,
        "target": "shop.example",
        "status": Status.FAILING,
        "previous_status": Status.HEALTHY,
        "summary": "down",
        "in_previous_state_s": 270.0,
        "added": [Finding(Severity.CRITICAL, "TCP_UNREACHABLE", "server <is> down & out", "check it")],
    }
    base.update(kw)
    return WatchEvent(**base)


# ------------------------------------------------------------------ configuration & URL policy
@pytest.mark.parametrize(
    "url",
    [
        "ftp://x.example/h",
        "http://x.example/h",
        "https://",
        "https://u:p@x.example/h",
        "https://x.example:99999/h",
        "x.example",
    ],
)
def test_bad_urls_rejected(url):
    with pytest.raises(NotifyError):
        WebhookConfig(url=url)


def test_good_urls_and_http_opt_in():
    assert notify.parse_webhook_url("https://hooks.example.com/a?b=1") == ("https", "hooks.example.com", 443, "/a?b=1")
    assert notify.parse_webhook_url("http://x.example:8080", allow_http=True) == ("http", "x.example", 8080, "/")


def test_config_validation():
    for kw in ({"kind": "teams"}, {"retries": 0}, {"retries": 11}, {"timeout": 0}, {"events": frozenset({"bogus"})}):
        with pytest.raises(NotifyError):
            WebhookConfig(url="https://x.example/h", **kw)


def test_redact_url_hides_path_and_token():
    shown = notify.redact_url("https://hooks.slack.com/services/T000/B000/SECRETTOKEN")
    assert shown == "https://hooks.slack.com/..." and "SECRET" not in shown


@pytest.mark.parametrize(
    ("ip", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700::1111", True),
        ("::ffff:8.8.8.8", True),
        ("10.0.0.1", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("192.168.1.1", False),
        ("172.16.0.1", False),
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("fe80::1", False),
        ("fc00::1", False),
        ("::ffff:127.0.0.1", False),
        ("::ffff:10.0.0.1", False),
        ("64:ff9b::7f00:1", False),
    ],
)
def test_is_public_ip(ip, public):
    assert notify.is_public_ip(ip) is public


def test_resolve_blocks_private_literals_but_allows_when_opted_in():
    for ip in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1"):
        with pytest.raises(NotifyError, match="non-public"):
            notify.resolve_destination(ip, 443, allow_private=False, timeout=1)
    assert notify.resolve_destination("127.0.0.1", 443, allow_private=True, timeout=1) == ["127.0.0.1"]


def test_resolve_blocks_hostnames_that_point_inside():
    with pytest.raises(NotifyError, match="non-public"):
        notify.resolve_destination("localhost", 443, allow_private=False, timeout=3)


def test_one_private_answer_poisons_the_whole_set(monkeypatch):
    def fake(host, port, **kw):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port)),
        ]

    monkeypatch.setattr(notify.socket, "getaddrinfo", fake)
    with pytest.raises(NotifyError, match=r"10\.0\.0\.5"):
        notify.resolve_destination("mixed.example", 443, allow_private=False, timeout=1)


def test_unresolvable_host_is_a_clean_error():
    with pytest.raises(NotifyError, match="cannot resolve"):
        notify.resolve_destination("does-not-exist.invalid", 443, allow_private=False, timeout=3)


# ------------------------------------------------------------------ a single POST
def test_post_once_success_and_headers(hook_server):
    state, port = hook_server
    r = notify.post_once(cfg(port), b'{"a":1}', {"Content-Type": "application/json", "X-Test": "1"})
    assert r.ok and r.status == 200
    path, headers, body = state["requests"][0]
    assert path == "/hook" and body == b'{"a":1}' and headers["X-Test"] == "1"


def test_ssrf_policy_is_enforced_before_any_connection(hook_server):
    state, port = hook_server
    strict = WebhookConfig(url=f"http://127.0.0.1:{port}/hook", allow_http=True)  # allow_private left False
    r = notify.post_once(strict, b"{}", {})
    assert r.status == 400 and "SSRF" in (r.error or "") and not r.retryable
    assert state["requests"] == []  # nothing was sent


@pytest.mark.parametrize(
    ("code", "retryable"), [(503, True), (500, True), (429, True), (400, False), (404, False), (302, False)]
)
def test_status_classification_and_no_redirect_following(hook_server, code, retryable):
    state, port = hook_server
    state["responses"] = [code]
    state["extra"] = {"Location": "http://169.254.169.254/latest/meta-data/"} if code == 302 else {}
    r = notify.post_once(cfg(port), b"{}", {})
    assert not r.ok and r.status == code and r.retryable is retryable
    assert len(state["requests"]) == 1  # the redirect target was never contacted


def test_retry_after_is_parsed_and_capped(hook_server):
    state, port = hook_server
    state["responses"], state["extra"] = [429], {"Retry-After": "7"}
    assert notify.post_once(cfg(port), b"{}", {}).retry_after == 7.0
    state["extra"] = {"Retry-After": "99999"}
    assert notify.post_once(cfg(port), b"{}", {}).retry_after == notify.MAX_RETRY_AFTER_S
    state["extra"] = {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
    assert notify.post_once(cfg(port), b"{}", {}).retry_after is None


def test_connection_failure_is_retryable(closed_port):
    r = notify.post_once(cfg(closed_port, timeout=6.0), b"{}", {})
    assert r.status is None and r.retryable and "refused" in (r.error or "")


def test_dns_is_resolved_once_and_the_connection_is_pinned(hook_server, monkeypatch):
    state, port = hook_server
    hostname_lookups: list[str] = []

    def rebinding_resolver(host, p, *args, **kw):
        if host == "rebind.test":  # behaves like a hostile resolver: the second answer points inside
            hostname_lookups.append(host)
            ip = "127.0.0.1" if len(hostname_lookups) == 1 else "10.255.255.1"
        else:  # IP literals resolve to themselves, exactly like the real resolver
            ip = host
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p))]

    monkeypatch.setattr(notify.socket, "getaddrinfo", rebinding_resolver)
    c = WebhookConfig(url=f"http://rebind.test:{port}/hook", allow_http=True, allow_private=True, timeout=3)
    assert notify.post_once(c, b"{}", {}).ok
    assert hostname_lookups == ["rebind.test"]  # looked up exactly once, then pinned to the validated IP
    assert state["requests"][0][1]["Host"] == f"rebind.test:{port}"


@pytest.fixture()
def tls_hook(tls_cert):
    seen: list = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            seen.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

    ctx = server_tls_context(tls_cert)
    srv = QuietHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], str(tls_cert / "c.pem"), seen
    srv.shutdown()
    srv.server_close()


def test_https_delivery_verifies_the_hostname_against_the_pinned_ip(tls_hook):
    port, ca, seen = tls_hook
    c = WebhookConfig(url=f"https://localhost:{port}/hook", allow_private=True, ca_bundle=ca, timeout=3)
    assert notify.post_once(c, b'{"x":1}', {}).ok and seen == [b'{"x":1}']


def test_https_with_untrusted_certificate_is_refused(tls_hook):
    port, _ca, seen = tls_hook
    c = WebhookConfig(url=f"https://localhost:{port}/hook", allow_private=True, timeout=3)
    r = notify.post_once(c, b"{}", {})
    assert r.status is None and ("self_signed" in r.error or "untrusted_issuer" in r.error) and seen == []


# ------------------------------------------------------------------ the notifier (fake transport)
def make(send, **kw):
    kw.setdefault("sleep", lambda s: None)
    kw.setdefault("jitter", lambda: 1.0)
    return WebhookNotifier(WebhookConfig(url="https://x.example/h", **kw.pop("cfg", {})), send=send, **kw)


def test_success_signing_and_headers():
    got = []

    def send(c, body, headers):
        got.append((body, headers))
        return Attempt(200)

    n = make(send, clock=lambda: 1_700_000_000, cfg={"secret": "s3cr3t"})
    queued = n.submit(change_event())
    assert queued
    drained = n.close()
    assert drained and n.sent == 1 and n.failed == 0
    body, headers = got[0]
    assert headers["X-NetDoctor-Timestamp"] == "1700000000" and headers["X-NetDoctor-Event"] == "change"
    assert headers["X-NetDoctor-Signature"] == notify.sign("s3cr3t", "1700000000", body)
    assert json.loads(body)["tool"] == "netdoctor"


def test_no_signature_header_without_a_secret():
    got = []
    n = make(lambda c, b, h: (got.append(h), Attempt(200))[1])
    n.submit(change_event())
    n.close()
    assert "X-NetDoctor-Signature" not in got[0]


def test_signature_depends_on_secret_timestamp_and_body():
    base = notify.sign("k", "1", b"body")
    assert base.startswith("sha256=") and len(base) == 71
    assert (
        len({base, notify.sign("k2", "1", b"body"), notify.sign("k", "2", b"body"), notify.sign("k", "1", b"BODY")})
        == 4
    )


def test_retries_with_exponential_backoff_then_succeeds():
    results = iter([Attempt(503), Attempt(None, "reset"), Attempt(200)])
    slept: list[float] = []
    n = make(lambda c, b, h: next(results), sleep=slept.append)
    n.submit(change_event())
    drained = n.close()
    assert drained and n.sent == 1 and slept == [1.0, 2.0]


def test_gives_up_after_configured_retries():
    calls = []
    n = make(lambda c, b, h: (calls.append(1), Attempt(503))[1], cfg={"retries": 3})
    n.submit(change_event())
    drained = n.close()
    assert drained and len(calls) == 3 and n.failed == 1 and n.sent == 0


def test_permanent_errors_are_not_retried():
    calls: list[int] = []
    n = make(lambda c, b, h: (calls.append(1), Attempt(404))[1])
    n.submit(change_event())
    n.close()
    assert len(calls) == 1 and n.failed == 1


def test_retry_after_overrides_backoff():
    results = iter([Attempt(429, retry_after=7.0), Attempt(200)])
    slept: list[float] = []
    n = make(lambda c, b, h: next(results), sleep=slept.append)
    n.submit(change_event())
    n.close()
    assert slept == [7.0] and n.sent == 1


def test_only_configured_event_kinds_are_sent():
    got = []
    n = make(lambda c, b, h: (got.append(h["X-NetDoctor-Event"]), Attempt(200))[1])
    initial_queued = n.submit(change_event(event="initial"))
    heartbeat_queued = n.submit(change_event(event="heartbeat"))
    assert not initial_queued and not heartbeat_queued
    recovered_queued = n.submit(change_event(event="recovered"))
    error_queued = n.submit(change_event(event="error", target=None, status=None, error="x"))
    assert recovered_queued and error_queued
    n.close()
    assert got == ["recovered", "error"]
    n2 = make(lambda c, b, h: Attempt(200), cfg={"events": frozenset({"initial"})})
    initial_ok = n2.submit(change_event(event="initial"))
    change_ok = n2.submit(change_event())
    assert initial_ok and not change_ok
    n2.close()


def test_queue_overflow_drops_oldest_and_keeps_newest():
    started, release = threading.Event(), threading.Event()
    delivered: list[str] = []

    def send(c, body, h):
        started.set()
        release.wait(5)
        delivered.append(json.loads(body)["target"])
        return Attempt(200)

    n = make(send, queue_size=2)
    n.submit(change_event(target="t1"))
    assert started.wait(5)  # worker is now busy with t1
    for name in ("t2", "t3", "t4", "t5"):
        n.submit(change_event(target=name))
    assert n.dropped == 2  # t2 and t3 were displaced
    release.set()
    drained = n.close()
    assert drained and delivered == ["t1", "t4", "t5"] and n.sent == 3


def test_worker_survives_a_crashing_transport():
    calls = {"n": 0}

    def send(c, body, h):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return Attempt(200)

    n = make(send)
    n.submit(change_event())
    n.submit(change_event())
    drained = n.close()
    assert drained and n.failed == 1 and n.sent == 1


def test_submit_after_close_is_refused_and_never_raises():
    n = make(lambda c, b, h: Attempt(200))
    drained = n.close()
    assert drained
    queued = n.submit(change_event())
    assert queued is False


def test_end_to_end_through_a_real_socket(hook_server):
    state, port = hook_server
    n = WebhookNotifier(cfg(port, secret="k"))
    n.submit(change_event())
    drained = n.close()
    assert drained and n.sent == 1
    _path, headers, body = state["requests"][0]
    assert headers["X-NetDoctor-Signature"] == notify.sign("k", headers["X-NetDoctor-Timestamp"], body)


# ------------------------------------------------------------------ payloads
def test_slack_payload_escapes_markup_and_describes_the_change():
    text = notify.slack_payload(change_event())["text"]
    assert ":rotating_light:" in text and "*shop.example*" in text and "FAILING" in text
    assert "server &lt;is&gt; down &amp; out" in text and "<is>" not in text
    assert "healthy -> failing after 4m 30s" in text


def test_slack_payload_for_recovery_and_error():
    rec = notify.slack_payload(
        change_event(
            event="recovered",
            status=Status.HEALTHY,
            previous_status=Status.FAILING,
            added=[],
            removed=["TCP_UNREACHABLE"],
        )
    )["text"]
    assert ":white_check_mark:" in rec and "recovered after 4m 30s" in rec and "TCP_UNREACHABLE cleared" in rec
    err = notify.slack_payload(WatchEvent("error", TS, error="<boom>"))["text"]
    assert "&lt;boom&gt;" in err and ":x:" in err


def test_generic_payload_report_is_opt_in():
    ev = change_event()
    assert "report" not in notify.generic_payload(ev, include_report=False)
    p = notify.generic_payload(ev, include_report=True)
    assert "report" in p and p["event"] == "change" and p["tool_version"]


def test_slack_payload_survives_an_event_without_a_status():
    text = notify.slack_payload(WatchEvent("change", TS))["text"]
    assert "NetDoctor event: change" in text


def test_worker_ignores_foreign_queue_items_and_keeps_delivering():
    delivered = []
    n = make(lambda c, b, h: (delivered.append(1), Attempt(200))[1])
    n._q.put("not an event")  # defensive path: must be skipped, not crash the worker
    n.submit(change_event())
    drained = n.close()
    assert drained and delivered == [1] and n.sent == 1


def test_delivery_falls_back_to_the_next_validated_address(hook_server, monkeypatch):
    """Windows resolves `localhost` to ::1 first; a dead first address must not break delivery."""
    state, port = hook_server

    def resolver(host, p, *args, **kw):
        if host == "dualstack.test":
            return [  # ::1 first (nothing listens there), then the working IPv4 loopback
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", p, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p)),
            ]
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (host, p) + ((0, 0) if ":" in host else ()))]

    monkeypatch.setattr(notify.socket, "getaddrinfo", resolver)
    c = WebhookConfig(url=f"http://dualstack.test:{port}/hook", allow_http=True, allow_private=True, timeout=3)
    assert notify.post_once(c, b"{}", {}).ok and len(state["requests"]) == 1


def test_only_validated_addresses_are_ever_tried(monkeypatch):
    attempted: list[str] = []

    def fake_connect(address, timeout=None, *a, **k):
        attempted.append(address[0])
        raise ConnectionRefusedError("no")

    monkeypatch.setattr(notify.socket, "create_connection", fake_connect)
    with pytest.raises(OSError, match="no"):
        notify._connect_pinned(["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4", "5.5.5.5"], 443, 1.0)
    assert attempted == ["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4"]  # capped; nothing outside the list


def test_connect_pinned_with_no_addresses_is_a_clean_error():
    with pytest.raises(OSError, match="no addresses"):
        notify._connect_pinned([], 443, 1.0)
