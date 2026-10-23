"""`netdoctor --watch` end to end (local servers only; intervals kept at the 1 s minimum)."""

from __future__ import annotations

import json

import pytest

from netdoctor import cli
from netdoctor.models import Finding, SessionReport, Severity, Status, TargetReport

FAST = ["--no-icmp", "--no-dns-compare", "--samples", "1", "--timeout", "6"]


def _ok(port: int) -> str:
    return f"http://127.0.0.1:{port}/ok"


def test_watch_text_initial_then_silence_then_summary(http_server, capsys):
    rc = cli.main([_ok(http_server), "--watch", "--interval", "1", "--max-runs", "2", "--ascii", *FAST])
    out, err = capsys.readouterr()
    assert rc == 0
    assert out.count("HEALTHY") >= 2  # the initial line + the summary line
    assert "Stopped after 2 run(s)" in out and "checks 2: healthy 2" in out
    assert "watching 1 target(s) every 1s" in err  # chatter goes to stderr, stdout stays clean


def test_watch_json_lines(http_server, capsys):
    rc = cli.main([_ok(http_server), "--watch", "--interval", "1", "--max-runs", "2", "--json", *FAST])
    out, _ = capsys.readouterr()
    events = [json.loads(line) for line in out.splitlines()]
    assert rc == 0 and [e["event"] for e in events] == ["initial", "summary"]
    assert events[0]["status"] == "healthy" and events[0]["report"]["http"]["status"] == 200
    assert events[1]["runs"] == 2 and events[1]["targets"][0]["healthy_pct"] == 100.0


def test_watch_exit_code_reflects_last_status(closed_port, capsys):
    rc = cli.main([f"127.0.0.1:{closed_port}", "--watch", "--max-runs", "1", "--ascii", *FAST])
    out, _ = capsys.readouterr()
    assert rc == 3 and "FAILING" in out and "TCP_UNREACHABLE" not in out  # message shown, code only on clear
    assert "Cannot open a TCP connection" in out


def test_watch_out_file_is_appended_not_truncated(http_server, tmp_path, capsys):
    log = tmp_path / "watch.log"
    args = [_ok(http_server), "--watch", "--interval", "1", "--max-runs", "1", "-o", str(log), "--json", *FAST]
    assert cli.main(args) == 0 and cli.main(args) == 0
    lines = log.read_text(encoding="utf-8").splitlines()
    assert [json.loads(x)["event"] for x in lines] == ["initial", "summary", "initial", "summary"]
    assert capsys.readouterr().out == ""  # nothing on stdout when writing to a file


def test_watch_keyboard_interrupt_prints_summary_and_returns_130(monkeypatch, capsys):
    good = SessionReport("t", "n", [TargetReport("a.test", "a.test", status=Status.HEALTHY, summary="ok")])
    calls = {"n": 0}

    def fake_run(targets, cfg):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return good

    monkeypatch.setattr(cli, "run", fake_run)
    monkeypatch.setattr("netdoctor.watch._sleep", lambda s, stop: None)
    rc = cli.main(["a.test", "--watch", "--interval", "1", "--ascii"])
    out, _ = capsys.readouterr()
    assert rc == 130 and "Stopped after 1 run(s)" in out and "HEALTHY" in out


def test_watch_when_every_cycle_crashes(monkeypatch, capsys):
    def boom(targets, cfg):
        raise RuntimeError("kaput")

    monkeypatch.setattr(cli, "run", boom)
    rc = cli.main(["a.test", "--watch", "--max-runs", "1", "--ascii"])
    out, _ = capsys.readouterr()
    assert rc == 3 and "watch cycle failed: RuntimeError: kaput" in out


def test_watch_reports_a_change_through_the_cli(monkeypatch, capsys):
    bad = Finding(Severity.CRITICAL, "TCP_UNREACHABLE", "server is down", "check it")
    seq = [
        SessionReport("t", "n", [TargetReport("a.test", "a.test", status=Status.HEALTHY, summary="fine")]),
        SessionReport(
            "t", "n", [TargetReport("a.test", "a.test", findings=[bad], status=Status.FAILING, summary="down")]
        ),
    ]
    it = iter(seq)
    monkeypatch.setattr(cli, "run", lambda t, c: next(it))
    monkeypatch.setattr("netdoctor.watch._sleep", lambda s, stop: None)
    rc = cli.main(["a.test", "--watch", "--max-runs", "2", "--ascii"])
    out, _ = capsys.readouterr()
    assert rc == 3 and "was HEALTHY for" in out and "+ server is down" in out and "-> check it" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["a.test", "--interval", "5"],
        ["a.test", "--max-runs", "3"],
        ["a.test", "--heartbeat", "10"],
        ["a.test", "--watch", "-f", "markdown"],
    ],
)
def test_watch_option_misuse_is_a_usage_error(argv):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2


@pytest.mark.parametrize("extra", [["--interval", "0.5"], ["--max-runs", "0"], ["--heartbeat", "-1"]])
def test_watch_bad_values_are_rejected_before_any_traffic(extra, capsys):
    assert cli.main(["a.test", "--watch", *extra]) == 2
    assert "error" in capsys.readouterr().err


def test_watch_unwritable_out_path(tmp_path, capsys):
    bad = tmp_path / "no" / "such" / "dir" / "w.log"
    assert cli.main(["a.test", "--watch", "--max-runs", "1", "-o", str(bad)]) == 2
    assert "cannot open" in capsys.readouterr().err
