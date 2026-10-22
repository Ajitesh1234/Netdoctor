from __future__ import annotations

import json

import pytest

from netdoctor import Config, cli, diagnose, report, run
from netdoctor.models import Status
from netdoctor.target import TargetError

CFG = Config(timeout=2.0, samples=2, icmp=False, dns_compare=False)


def test_diagnose_healthy_local(http_server):
    rep = diagnose(f"http://127.0.0.1:{http_server}/ok", CFG)
    assert rep.status is Status.HEALTHY and rep.http.status == 200 and rep.tls is None
    assert rep.duration_ms > 0


def test_diagnose_closed_port_is_failing(closed_port):
    rep = diagnose(f"127.0.0.1:{closed_port}", CFG)
    assert rep.status is Status.FAILING and "refused" in rep.summary


def test_run_preserves_order_and_validates_upfront(http_server, closed_port):
    targets = [f"127.0.0.1:{closed_port}", f"http://127.0.0.1:{http_server}"]
    s = run(targets, CFG)
    assert [r.target for r in s.reports] == targets and s.worst_status is Status.FAILING
    with pytest.raises(TargetError):
        run(["ok.example", "-bad"], CFG)


def test_config_validation():
    for bad in ({"timeout": 0}, {"samples": 0}, {"workers": 99}, {"max_redirects": -1}):
        with pytest.raises(ValueError):
            Config(**bad)


@pytest.fixture()
def session(http_server):
    return run([f"http://127.0.0.1:{http_server}/ok", f"http://127.0.0.1:{http_server}/boom"], CFG)


def test_json_schema(session):
    data = json.loads(report.render_json(session))
    assert data["schema_version"] == 1 and len(data["reports"]) == 2
    r = data["reports"][1]
    assert r["status"] == "failing" and r["findings"][0]["severity"] == "critical"
    assert isinstance(r["http"]["hops"], list) and r["dns"]["ok"] is True


def test_text_renderers(session):
    uni = report.render_text(session)
    asc = report.render_text(session, ascii_only=True)
    col = report.render_text(session, color=True)
    assert "HEALTHY" in uni and "FAILING" in uni
    asc.encode("ascii")  # must be pure ASCII
    assert "\033[" in col and "\033[" not in uni


def test_markdown_renderer(session):
    md = report.render_markdown(session)
    assert md.startswith("# NetDoctor Report") and "| Check | Result |" in md and "`HTTP_SERVER_ERROR`" in md


# ------------------------------------------------------------------ CLI
def test_cli_no_targets_is_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2


@pytest.mark.parametrize("arg", ["-oProxyCommand=x", "ftp://x.com", "a b"])
def test_cli_rejects_bad_targets_without_traffic(arg, capsys):
    assert cli.main(["--", arg]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_bad_option_values(capsys):
    assert cli.main(["x.com", "--samples", "0"]) == 2


def test_cli_exit_codes_and_json(http_server, closed_port, capsys):
    base = ["--no-icmp", "--no-dns-compare", "--timeout", "2", "--samples", "2"]
    assert cli.main([f"http://127.0.0.1:{http_server}/ok", *base]) == 0
    assert cli.main([f"http://127.0.0.1:{http_server}/forbidden", *base]) == 1
    capsys.readouterr()
    assert cli.main([f"127.0.0.1:{closed_port}", "--json", *base]) == 3
    assert json.loads(capsys.readouterr().out)["reports"][0]["status"] == "failing"


def test_cli_sites_alias_and_positional(http_server, capsys):
    a = f"http://127.0.0.1:{http_server}/ok"
    assert cli.main(["--sites", a, "--no-icmp", "--no-dns-compare", "-f", "markdown"]) == 0
    assert "# NetDoctor Report" in capsys.readouterr().out


def test_cli_out_file_is_utf8(http_server, tmp_path, capsys):
    out = tmp_path / "r.md"
    rc = cli.main(
        [f"http://127.0.0.1:{http_server}/ok", "-f", "markdown", "-o", str(out), "--no-icmp", "--no-dns-compare"]
    )
    assert rc == 0 and "✔" in out.read_text(encoding="utf-8")
    assert cli.main(["x.com", "-o", str(tmp_path / "no" / "dir" / "f")]) == 2


def test_module_entrypoint():
    import runpy

    with pytest.raises(SystemExit) as e:
        runpy.run_module("netdoctor", run_name="__main__", alter_sys=True)
    assert e.value.code == 2  # no targets -> usage error, proves wiring
