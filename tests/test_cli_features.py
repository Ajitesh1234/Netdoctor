"""CLI integration for config files, new formats, notifications and metrics (local servers only)."""

from __future__ import annotations

import io
import json
import re
import socket
import sys
from typing import ClassVar

import pytest

from netdoctor import cli, notify

FAST = ["--no-icmp", "--no-dns-compare", "--samples", "1", "--timeout", "6"]


def ok_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/ok"


# ------------------------------------------------------------------ formats
def test_html_and_prometheus_one_shot(http_server, capsys):
    assert cli.main([ok_url(http_server), "-f", "html", *FAST]) == 0
    html = capsys.readouterr().out
    assert html.startswith("<!doctype html>") and "NetDoctor report" in html and "<script" not in html
    assert cli.main([ok_url(http_server), "-f", "prometheus", *FAST]) == 0
    prom = capsys.readouterr().out
    assert "# TYPE netdoctor_target_healthy gauge" in prom
    assert re.search(r'netdoctor_target_healthy\{target="http://127\.0\.0\.1:\d+/ok"\} 1', prom)


def test_report_files_are_written_atomically_and_replaced(http_server, tmp_path, capsys):
    out = tmp_path / "netdoctor.prom"
    out.write_text("OLD")
    assert cli.main([ok_url(http_server), "-f", "prometheus", "-o", str(out), *FAST]) == 0
    assert out.read_text().startswith("# HELP netdoctor_build_info")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["netdoctor.prom"]  # no temp files
    assert "Report written" in capsys.readouterr().err


def test_session_report_json_carries_run_metadata(http_server, capsys):
    cli.main([ok_url(http_server), "--json", *FAST])
    data = json.loads(capsys.readouterr().out)
    assert re.fullmatch(r"[0-9a-f]{32}", data["run_id"]) and set(data["environment"]) == {"python", "platform"}


def test_stdout_with_a_legacy_codepage_degrades_instead_of_crashing(monkeypatch):
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="ascii", newline="\n"))
    cli._write_stdout("status ✔ ok\n")
    sys.stdout.flush()
    assert raw.getvalue() == b"status ? ok\n"


# ------------------------------------------------------------------ config file through the CLI
def test_print_config_shows_effective_redacted_settings_without_touching_the_network(tmp_path, capsys):
    pytest.importorskip("tomllib" if sys.version_info >= (3, 11) else "tomli")
    cfg = tmp_path / "nd.toml"
    cfg.write_text(
        'targets = ["a.test"]\n[checks]\ntimeout = 2\n[watch]\nenabled = true\n[webhook]\nurl = "https://hooks.example/TOPSECRET"\n'
    )
    assert cli.main(["--config", str(cfg), "--timeout", "7", "--print-config"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["timeout"] == 7.0 and data["watch"] is True and data["targets"] == ["a.test"]
    assert "TOPSECRET" not in out and "explicit" not in data


def test_config_file_can_drive_a_whole_watch_run(http_server, tmp_path, capsys):
    pytest.importorskip("tomllib" if sys.version_info >= (3, 11) else "tomli")
    cfg = tmp_path / "nd.toml"
    cfg.write_text(
        f'targets = ["{ok_url(http_server)}"]\n[checks]\nicmp = false\ndns_compare = false\nsamples = 1\ntimeout = 6\n[watch]\nenabled = true\nmax_runs = 1\ninterval = 1\n[output]\nformat = "json"\nascii = true\n'
    )
    assert cli.main(["--config", str(cfg)]) == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [e["event"] for e in events] == ["initial", "summary"]


def test_a_typo_in_the_config_file_fails_loudly(tmp_path, capsys):
    pytest.importorskip("tomllib" if sys.version_info >= (3, 11) else "tomli")
    cfg = tmp_path / "nd.toml"
    cfg.write_text('targets = ["a.test"]\n[watch]\nintervall = 5\n')
    assert cli.main(["--config", str(cfg)]) == 2
    assert "did you mean 'interval'" in capsys.readouterr().err


def test_missing_config_file(capsys):
    assert cli.main(["a.test", "--config", "/definitely/not/here.toml"]) == 2
    assert "cannot read config file" in capsys.readouterr().err


def test_no_targets_anywhere_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--print-config"])
    assert e.value.code == 2


# ------------------------------------------------------------------ webhooks through the CLI
WATCH = ["--watch", "--max-runs", "1", "--interval", "1", "--ascii", *FAST]


def test_webhook_receives_a_signed_event_before_the_process_exits(http_server, hook_server, monkeypatch, capsys):
    state, hook_port = hook_server
    monkeypatch.setenv("NETDOCTOR_WEBHOOK_SECRET", "topsecret")
    rc = cli.main(
        [
            ok_url(http_server),
            *WATCH,
            "--webhook",
            f"http://127.0.0.1:{hook_port}/hook",
            "--webhook-allow-http",
            "--webhook-allow-private",
            "--notify-on",
            "initial",
        ]
    )
    assert rc == 0 and len(state["requests"]) == 1  # delivered (flushed) before main() returned
    path, headers, body = state["requests"][0]
    assert path == "/hook" and headers["X-NetDoctor-Event"] == "initial"
    assert headers["X-NetDoctor-Signature"] == notify.sign("topsecret", headers["X-NetDoctor-Timestamp"], body)
    payload = json.loads(body)
    assert payload["tool"] == "netdoctor" and payload["status"] == "healthy" and "report" not in payload
    err = capsys.readouterr().err
    assert "notifying http://127.0.0.1/..." in err and "topsecret" not in err and "/hook" not in err


def test_webhook_url_can_come_from_the_environment(http_server, hook_server, monkeypatch):
    state, hook_port = hook_server
    monkeypatch.setenv("MY_HOOK", f"http://127.0.0.1:{hook_port}/from-env")
    rc = cli.main(
        [
            ok_url(http_server),
            *WATCH,
            "--webhook",
            "env:MY_HOOK",
            "--webhook-allow-http",
            "--webhook-allow-private",
            "--notify-on",
            "initial",
            "--webhook-format",
            "slack",
        ]
    )
    assert rc == 0 and state["requests"][0][0] == "/from-env"
    assert "text" in json.loads(state["requests"][0][2])  # slack format


def test_webhook_env_reference_must_exist(http_server, monkeypatch, capsys):
    monkeypatch.delenv("NOPE_HOOK", raising=False)
    assert cli.main([ok_url(http_server), *WATCH, "--webhook", "env:NOPE_HOOK"]) == 2
    assert "NOPE_HOOK is not set" in capsys.readouterr().err


def test_explicit_secret_env_must_exist(http_server, monkeypatch, capsys):
    monkeypatch.delenv("NOPE_SECRET", raising=False)
    assert (
        cli.main(
            [
                ok_url(http_server),
                *WATCH,
                "--webhook",
                "https://hooks.example.com/h",
                "--webhook-secret-env",
                "NOPE_SECRET",
            ]
        )
        == 2
    )
    assert "NOPE_SECRET is not set" in capsys.readouterr().err


def test_plain_http_webhooks_need_an_explicit_opt_in(http_server, capsys):
    assert cli.main([ok_url(http_server), *WATCH, "--webhook", "http://hooks.example.com/h"]) == 2
    assert "must use https" in capsys.readouterr().err


def test_ssrf_protection_blocks_internal_webhook_destinations_but_never_stops_monitoring(
    http_server, hook_server, capsys
):
    state, hook_port = hook_server
    rc = cli.main(
        [
            ok_url(http_server),
            *WATCH,
            "--webhook",
            f"http://127.0.0.1:{hook_port}/hook",
            "--webhook-allow-http",
            "--notify-on",
            "initial",
        ]
    )
    assert rc == 0  # monitoring is unaffected by the failed notification
    assert state["requests"] == []  # nothing reached the loopback receiver
    assert "1 notification(s) failed" in capsys.readouterr().err


# ------------------------------------------------------------------ metrics through the CLI
class FakeMetrics:
    instances: ClassVar[list[FakeMetrics]] = []

    def __init__(self, provider, *, bind, port, token):
        self.provider, self.bind, self.token, self.requested_port = provider, bind, token, port
        self.port = 49999
        self.started = self.stopped = False
        FakeMetrics.instances.append(self)

    def start(self):
        self.started = True
        return self.port

    def stop(self):
        self.stopped = True


def test_metrics_provider_reflects_the_live_watcher(http_server, monkeypatch, capsys):
    FakeMetrics.instances.clear()
    monkeypatch.setattr(cli, "MetricsServer", FakeMetrics)
    monkeypatch.setenv("NETDOCTOR_METRICS_TOKEN", "tok")
    assert cli.main([ok_url(http_server), *WATCH, "--metrics-port", "9100"]) == 0
    (srv,) = FakeMetrics.instances
    assert srv.started and srv.stopped and srv.token == "tok" and srv.bind == "127.0.0.1" and srv.requested_port == 9100
    text = srv.provider()
    assert "netdoctor_runs_total 1" in text and "netdoctor_run_errors_total 0" in text
    assert re.search(r'netdoctor_target_healthy\{target="[^"]+"\} 1', text)
    assert "netdoctor_notifications" not in text  # no webhook configured
    assert "metrics on 127.0.0.1:49999" in capsys.readouterr().err


def test_metrics_token_env_must_exist_when_named(http_server, monkeypatch, capsys):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    assert cli.main([ok_url(http_server), *WATCH, "--metrics-port", "0", "--metrics-token-env", "NOPE_TOKEN"]) == 2
    assert "NOPE_TOKEN is not set" in capsys.readouterr().err


def test_metrics_port_already_in_use_is_a_clear_error(http_server, capsys):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        assert cli.main([ok_url(http_server), *WATCH, "--metrics-port", str(busy)]) == 2
    assert "cannot start the metrics server" in capsys.readouterr().err


def test_real_metrics_server_end_to_end(http_server, monkeypatch):
    """Scrape the real server while a real watch is running."""
    import http.client
    import threading
    import time

    scraped: dict = {}
    real = cli.MetricsServer

    class Spy(real):
        def start(self):
            port = super().start()

            def scrape():
                time.sleep(0.6)
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/metrics")
                scraped["body"] = conn.getresponse().read().decode()
                conn.close()

            threading.Thread(target=scrape, daemon=True).start()
            return port

    monkeypatch.setattr(cli, "MetricsServer", Spy)
    rc = cli.main([ok_url(http_server), "--watch", "--max-runs", "2", "--interval", "1", "--metrics-port", "0", *FAST])
    time.sleep(0.3)
    assert rc == 0 and "netdoctor_target_healthy" in scraped["body"] and "netdoctor_runs_total" in scraped["body"]


# ------------------------------------------------------------------ closed pipes (`| head`, `| jq`)
class ClosedPipe(io.StringIO):
    encoding = "utf-8"

    def write(self, s):
        raise BrokenPipeError(32, "Broken pipe")

    def fileno(self):
        raise io.UnsupportedOperation


def test_a_closed_pipe_exits_quietly_for_one_shot_runs(http_server, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdout", ClosedPipe())
    assert cli.main([ok_url(http_server), *FAST]) == cli.EXIT_PIPE
    assert "Traceback" not in capsys.readouterr().err


def test_a_closed_pipe_exits_quietly_for_print_config(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdout", ClosedPipe())
    assert cli.main(["a.test", "--print-config"]) == cli.EXIT_PIPE
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX pipes")
def test_real_pipe_to_head_has_no_traceback(http_server):
    import subprocess

    proc = subprocess.run(
        f"{sys.executable} -m netdoctor --config /dev/null a.test --print-config 2>&1 >/dev/null | head -c 0; "
        f"{sys.executable} -m netdoctor a.test --print-config 2>&1 | head -c 5",
        shell=True, capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert "Traceback" not in proc.stdout + proc.stderr
