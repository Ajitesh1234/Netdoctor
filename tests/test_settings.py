"""Settings precedence, strict config-file validation, secrets handling, atomic writes, logging."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
from pathlib import Path

import pytest

from netdoctor import cli, fsutil, logsetup, settings
from netdoctor.settings import Settings, SettingsError
from netdoctor.target import MAX_TARGETS, TargetError, parse_targets

pytest.importorskip(
    "tomllib" if sys.version_info >= (3, 11) else "tomli", reason="TOML support (tomli on Python < 3.11)"
)


def write(tmp_path: Path, text: str, name: str = "nd.toml") -> str:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def load(tmp_path: Path, text: str) -> Settings:
    path = write(tmp_path, text)
    s = Settings()
    data, base = settings.load_file(path)
    settings.apply_file(s, data, base, path=path)
    return s


def parse(argv: list[str]):
    return cli.build_parser().parse_args(argv)


# ------------------------------------------------------------------ file loading
def test_full_config_file_round_trip(tmp_path):
    (tmp_path / "ca.pem").write_text("x")
    s = load(
        tmp_path,
        """
targets = ["example.com", "https://api.example.com/health"]
[checks]
timeout = 3
samples = 7
workers = 2
icmp = false
traceroute = true
dns_compare = true
resolvers = ["9.9.9.9"]
doh_servers = ["https://dns.example/dns-query"]
ca_bundle = "ca.pem"
max_redirects = 2
[thresholds]
latency_warn_ms = 100
cert_expiry_warn_days = 30
[output]
format = "json"
color = "never"
ascii = true
file = "out/report.json"
[logging]
verbose = 1
format = "json"
file = "nd.log"
[watch]
enabled = true
interval = 45
max_runs = 3
heartbeat = 60
confirm = 2
[webhook]
url = "env:HOOK"
kind = "slack"
events = ["change"]
secret_env = "HOOK_SECRET"
allow_private = true
include_report = true
[metrics]
port = 9100
bind = "127.0.0.1"
token_env = "METRICS_TOKEN"
""",
    )
    assert s.targets == ["example.com", "https://api.example.com/health"]
    assert (s.timeout, s.samples, s.workers, s.icmp, s.traceroute) == (3.0, 7, 2, False, True)
    assert s.resolvers == ("9.9.9.9",) and s.doh_servers == ("https://dns.example/dns-query",)
    assert s.ca_bundle == str(tmp_path / "ca.pem")  # relative paths resolve against the file's directory
    assert s.out == str(tmp_path / "out" / "report.json") and s.log_file == str(tmp_path / "nd.log")
    assert (s.latency_warn_ms, s.cert_expiry_warn_days) == (100.0, 30)
    assert (s.format, s.color, s.ascii, s.verbose, s.log_format) == ("json", "never", True, 1, "json")
    assert (s.watch, s.interval, s.max_runs, s.heartbeat, s.confirm) == (True, 45.0, 3, 60.0, 2)
    assert (s.webhook_url, s.webhook_kind, s.webhook_events, s.webhook_allow_private) == (
        "env:HOOK",
        "slack",
        ("change",),
        True,
    )
    assert (s.metrics_port, s.metrics_token_env) == (9100, "METRICS_TOKEN")
    assert {"timeout", "webhook_url", "metrics_port"} <= s.explicit
    cfg = s.to_config()
    assert cfg.timeout == 3.0 and cfg.icmp is False and cfg.doh_servers == ("https://dns.example/dns-query",)


def test_empty_file_changes_nothing(tmp_path):
    s = load(tmp_path, "")
    assert s == Settings()


def test_unknown_section_suggests_the_right_one(tmp_path):
    with pytest.raises(SettingsError, match=r"unknown section 'chekcs'.*did you mean 'checks'"):
        load(tmp_path, "[chekcs]\ntimeout = 1\n")


def test_unknown_key_is_an_error_with_a_hint(tmp_path):
    with pytest.raises(SettingsError, match=r"key in \[watch\] 'intervall'.*did you mean 'interval'"):
        load(tmp_path, "[watch]\nintervall = 5\n")
    with pytest.raises(SettingsError, match="valid:"):
        load(tmp_path, "[watch]\nzzzzzzzz = 5\n")


@pytest.mark.parametrize(
    ("toml", "fragment"),
    [
        ('[checks]\ntimeout = "fast"', "checks.timeout: expected a number"),
        ("[checks]\nsamples = true", "checks.samples: expected an integer"),
        ("[checks]\nsamples = 1.5", "checks.samples: expected an integer"),
        ('[checks]\nicmp = "yes"', "checks.icmp: expected true or false"),
        ("[checks]\nresolvers = [1, 2]", "checks.resolvers: expected a list"),
        ('[checks]\nca_bundle = ""', "checks.ca_bundle: expected a non-empty string"),
        ('[output]\nformat = "pdf"', "output.format: must be one of"),
        ('[webhook]\nkind = "teams"', "webhook.kind: must be one of"),
        ("targets = 'a.test'", "targets: expected a list"),
        ("checks = 3", "[checks] must be a table"),
    ],
)
def test_type_and_choice_errors_name_the_offending_key(tmp_path, toml, fragment):
    with pytest.raises(SettingsError, match=fragment.replace("[", r"\[").replace("]", r"\]")):
        load(tmp_path, toml)


def test_file_problems(tmp_path):
    with pytest.raises(SettingsError, match="cannot read"):
        settings.load_file(str(tmp_path / "missing.toml"))
    with pytest.raises(SettingsError, match="invalid TOML"):
        settings.load_file(write(tmp_path, "[checks\ntimeout ="))
    big = write(tmp_path, "# " + "x" * (settings.MAX_CONFIG_BYTES + 10), "big.toml")
    with pytest.raises(SettingsError, match="too large"):
        settings.load_file(big)
    bad = tmp_path / "bin.toml"
    bad.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(SettingsError, match="UTF-8"):
        settings.load_file(str(bad))


# ------------------------------------------------------------------ precedence
def test_flags_override_the_file_which_overrides_defaults(tmp_path):
    path = write(tmp_path, '[checks]\ntimeout = 9\nicmp = false\nsamples = 8\n[output]\nformat = "markdown"\n')
    args = parse(["a.test", "--config", path, "--timeout", "3", "--icmp", "--json"])
    s = cli.resolve_settings(args)
    assert s.timeout == 3.0  # flag beat file
    assert s.icmp is True  # --icmp can re-enable what the file disabled
    assert s.samples == 8  # file beat default
    assert s.format == "json"  # --json beat the file's format
    assert s.workers == Settings().workers  # untouched default


def test_cli_targets_replace_file_targets_but_file_targets_are_the_fallback(tmp_path):
    path = write(tmp_path, 'targets = ["from-file.test"]\n')
    assert cli.resolve_settings(parse(["--config", path])).targets == ["from-file.test"]
    assert cli.resolve_settings(parse(["cli.test", "--config", path])).targets == ["cli.test"]
    assert cli.resolve_settings(parse(["--sites", "alias.test", "--config", path])).targets == ["alias.test"]


def test_doh_flags(tmp_path):
    assert cli.resolve_settings(parse(["a.test", "--doh"])).doh_servers == settings.DEFAULT_DOH
    s = cli.resolve_settings(
        parse(["a.test", "--doh", "--doh-server", "https://x.example/q", "--doh-server", settings.DEFAULT_DOH[0]])
    )
    assert s.doh_servers == (*settings.DEFAULT_DOH, "https://x.example/q")  # de-duplicated, order kept
    assert cli.resolve_settings(parse(["a.test", "--doh-server", "https://x.example/q"])).doh_servers == (
        "https://x.example/q",
    )


# ------------------------------------------------------------------ cross-field validation
@pytest.mark.parametrize(
    ("argv", "fragment"),
    [
        (["a.test", "--doh", "--no-dns-compare"], "DNS-over-HTTPS needs"),
        (["a.test", "--watch", "-f", "html"], "watch mode supports formats"),
        (["a.test", "--watch", "-f", "prometheus"], "watch mode supports formats"),
        (["a.test", "--watch", "--max-runs", "0"], "max-runs"),
        (["a.test", "--webhook", "https://x.example/h"], "only valid in watch mode"),
        (["a.test", "--metrics-port", "9100"], "only valid in watch mode"),
        (["a.test", "--confirm", "2"], "only valid in watch mode"),
        (["a.test", "--ca-bundle", "/nope/ca.pem"], "ca_bundle file not found"),
        (["a.test", "--timeout", "0"], "timeout must be"),
        (["a.test", "--doh-server", "http://insecure.example/q"], "https://"),
    ],
)
def test_cross_field_validation(argv, fragment, capsys):
    assert cli.main(argv) == 2
    assert fragment in capsys.readouterr().err


def test_target_count_is_capped():
    parse_targets([f"h{i}.test" for i in range(MAX_TARGETS)])
    with pytest.raises(TargetError, match="too many targets"):
        parse_targets([f"h{i}.test" for i in range(MAX_TARGETS + 1)])
    with pytest.raises(TargetError, match="no targets"):
        parse_targets([])


# ------------------------------------------------------------------ secrets
def test_env_references():
    env = {"HOOK": "https://hooks.example/abc", "EMPTY": ""}
    assert settings.resolve_env_ref("env:HOOK", env) == "https://hooks.example/abc"
    assert settings.resolve_env_ref("https://plain.example/x", env) == "https://plain.example/x"
    for bad in ("env:NOPE", "env:EMPTY"):
        with pytest.raises(SettingsError, match="not set"):
            settings.resolve_env_ref(bad, env)


def test_secret_from_env_explicit_must_exist_default_is_optional():
    assert settings.secret_from_env("S", "DEFAULT", {"S": "x", "DEFAULT": "y"}) == "x"
    assert settings.secret_from_env(None, "DEFAULT", {"DEFAULT": "y"}) == "y"
    assert settings.secret_from_env(None, "DEFAULT", {}) is None
    with pytest.raises(SettingsError, match="S is not set"):
        settings.secret_from_env("S", "DEFAULT", {"DEFAULT": "y"})


def test_redacted_never_shows_inline_webhook_urls():
    s = Settings(webhook_url="https://hooks.slack.com/services/T0/B0/TOPSECRET", resolvers=("1.1.1.1",))
    text = json.dumps(s.redacted())
    assert "TOPSECRET" not in text and "redacted inline URL" in text
    assert "explicit" not in s.redacted() and s.redacted()["resolvers"] == ["1.1.1.1"]
    assert Settings(webhook_url="env:HOOK").redacted()["webhook_url"] == "env:HOOK"  # a reference is not a secret


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_warns_when_an_inline_webhook_url_sits_in_a_world_readable_file(tmp_path, caplog):
    path = write(tmp_path, '[webhook]\nurl = "https://hooks.example.com/secret"\n')
    os.chmod(path, 0o640)
    caplog.set_level(logging.WARNING)
    s = Settings()
    data, base = settings.load_file(path)
    settings.apply_file(s, data, base, path=path)
    assert "accessible to other users" in caplog.text
    caplog.clear()
    os.chmod(path, 0o600)
    settings.apply_file(Settings(), data, base, path=path)
    assert caplog.text == ""
    # an env: reference is not a secret: no warning even for a readable file
    path2 = write(tmp_path, '[webhook]\nurl = "env:HOOK"\n', "b.toml")
    os.chmod(path2, 0o640)
    settings.apply_file(Settings(), settings.load_file(path2)[0], base, path=path2)
    assert caplog.text == ""


# ------------------------------------------------------------------ atomic writes
def test_atomic_write_creates_and_overwrites(tmp_path):
    target = tmp_path / "r.txt"
    fsutil.atomic_write_text(str(target), "one ✔\n")
    fsutil.atomic_write_text(str(target), "two ✔\n")
    assert target.read_text(encoding="utf-8") == "two ✔\n"
    assert [p.name for p in tmp_path.iterdir()] == ["r.txt"]  # no temp files left behind


def test_atomic_write_failure_keeps_the_old_file_and_cleans_up(tmp_path, monkeypatch):
    target = tmp_path / "r.txt"
    target.write_text("original")

    def boom(*a, **k):
        raise OSError("disk exploded")

    monkeypatch.setattr(fsutil.os, "replace", boom)
    with pytest.raises(OSError, match="disk exploded"):
        fsutil.atomic_write_text(str(target), "new content")
    assert target.read_text() == "original" and [p.name for p in tmp_path.iterdir()] == ["r.txt"]


def test_atomic_write_to_missing_directory_raises(tmp_path):
    with pytest.raises(OSError):
        fsutil.atomic_write_text(str(tmp_path / "no" / "dir" / "f"), "x")


@contextlib.contextmanager
def umask(value: int):
    old = os.umask(value)
    try:
        yield
    finally:
        os.umask(old)


def perms(path) -> int:
    return Path(path).stat().st_mode & 0o777


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_atomic_write_default_is_owner_only(tmp_path):
    """Reports list internal hostnames and findings: least privilege unless the operator opts in."""
    with umask(0o000):  # even a wide-open umask must not widen the default
        fsutil.atomic_write_text(str(tmp_path / "r.txt"), "x")
    assert perms(tmp_path / "r.txt") == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_atomic_write_explicit_mode_and_umask_interplay(tmp_path):
    with umask(0o022):
        fsutil.atomic_write_text(str(tmp_path / "shared.prom"), "x", mode=0o644)
    assert perms(tmp_path / "shared.prom") == 0o644  # opt-in for a collector running as another user
    with umask(0o077):  # the umask still applies on top: it can only narrow, never widen
        fsutil.atomic_write_text(str(tmp_path / "narrowed.prom"), "x", mode=0o644)
    assert perms(tmp_path / "narrowed.prom") == 0o600


@pytest.mark.parametrize("value", ["600", "640", "644", "0644", "400", " 640 "])
def test_valid_modes(value):
    assert settings.parse_mode(value) == int(value.strip(), 8)


@pytest.mark.parametrize("value", ["6", "6400", "abc", "", "1777", "89", "-600", "6 00"])
def test_malformed_modes_are_rejected(value):
    with pytest.raises(SettingsError, match="3 octal digits"):
        settings.parse_mode(value)


@pytest.mark.parametrize("value", ["666", "602", "662", "777", "0666"])
def test_world_writable_modes_are_refused(value):
    with pytest.raises(SettingsError, match="world-writable"):
        settings.parse_mode(value)


def test_config_file_mode_must_be_a_quoted_string(tmp_path):
    assert load(tmp_path, '[output]\nmode = "640"\n').out_mode == "640"
    with pytest.raises(SettingsError, match="quoted octal string"):
        load(tmp_path, "[output]\nmode = 640\n")
    with pytest.raises(SettingsError, match="quoted octal string"):
        load(tmp_path, "[output]\nmode = 0o640\n")  # TOML reads this as the integer 416


@pytest.mark.parametrize("flag", ["666", "99", "abc"])
def test_cli_rejects_unsafe_or_malformed_out_mode_before_any_traffic(flag, capsys):
    assert cli.main(["a.test", "-o", "report.txt", "--out-mode", flag]) == 2
    assert "mode" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_cli_report_files_are_private_by_default_and_shareable_on_request(http_server, tmp_path):
    base = [f"http://127.0.0.1:{http_server}/ok", "--no-icmp", "--no-dns-compare", "--samples", "1", "-f", "prometheus"]
    with umask(0o022):
        assert cli.main([*base, "-o", str(tmp_path / "private.prom")]) == 0
        assert cli.main([*base, "-o", str(tmp_path / "shared.prom"), "--out-mode", "644"]) == 0
    assert perms(tmp_path / "private.prom") == 0o600 and perms(tmp_path / "shared.prom") == 0o644


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_watch_output_file_is_private_by_default(http_server, tmp_path):
    out = tmp_path / "watch.log"
    argv = [
        f"http://127.0.0.1:{http_server}/ok",
        "--watch",
        "--max-runs",
        "1",
        "--interval",
        "1",
        "--no-icmp",
        "--no-dns-compare",
        "--samples",
        "1",
        "-o",
        str(out),
    ]
    with umask(0o000):
        assert cli.main(argv) == 0
    assert perms(out) == 0o600


# ------------------------------------------------------------------ logging
def test_json_log_lines_are_machine_readable(tmp_path):
    path = tmp_path / "nd.log"
    logsetup.setup_logging(1, "json", str(path))
    log = logging.getLogger("netdoctor.test")
    log.info("hello %s", "world")
    log.debug("hidden at -v")
    try:
        raise RuntimeError("kaboom")
    except RuntimeError:
        log.exception("failed")
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert [(e["level"], e["message"]) for e in lines] == [("INFO", "hello world"), ("ERROR", "failed")]
    assert lines[0]["logger"] == "netdoctor.test" and lines[0]["ts"].endswith("Z")
    assert "kaboom" in lines[1]["exception"]


def test_setup_logging_replaces_its_handler_instead_of_stacking(tmp_path):
    for _ in range(3):
        logsetup.setup_logging(0, "text", None)
    mine = [h for h in logging.getLogger("netdoctor").handlers if getattr(h, "_netdoctor_handler", False)]
    assert len(mine) == 1


def test_log_levels_follow_verbosity():
    for verbose, level in ((0, logging.WARNING), (1, logging.INFO), (2, logging.DEBUG), (9, logging.DEBUG)):
        logsetup.setup_logging(verbose)
        assert logging.getLogger("netdoctor").level == level


def test_unwritable_log_file_is_a_usage_error(tmp_path, capsys):
    bad = tmp_path / "no" / "such" / "dir" / "x.log"
    assert cli.main(["a.test", "--log-file", str(bad)]) == 2
    assert "cannot open log file" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="log file stays open until handler closes on Windows")
def test_log_file_flag_end_to_end(http_server, tmp_path):
    log = tmp_path / "run.log"
    rc = cli.main(
        [
            f"http://127.0.0.1:{http_server}/ok",
            "--no-icmp",
            "--no-dns-compare",
            "--samples",
            "1",
            "-vv",
            "--log-format",
            "json",
            "--log-file",
            str(log),
        ]
    )
    assert rc == 0 and all(json.loads(line)["logger"].startswith("netdoctor") for line in log.read_text().splitlines())


def test_a_config_file_may_hold_watch_settings_for_one_shot_runs_too(http_server, tmp_path, capsys):
    """One shared file serves `netdoctor --config f` (cron) and `netdoctor --config f --watch`."""
    cfg = tmp_path / "nd.toml"
    cfg.write_text(
        f'targets = ["http://127.0.0.1:{http_server}/ok"]\n[checks]\nicmp = false\ndns_compare = false\nsamples = 1\ntimeout = 6\n'
        '[watch]\nenabled = false\ninterval = 60\nconfirm = 2\n[webhook]\nurl = "env:NETDOCTOR_HOOK_NOT_USED"\n'
        '[metrics]\nport = 9100\n[output]\nformat = "json"\n'
    )
    assert cli.main(["--config", str(cfg)]) == 0  # one-shot: watch/webhook/metrics keys are inert
    assert json.loads(capsys.readouterr().out)["reports"][0]["status"] == "healthy"


def test_the_shipped_example_config_is_valid():
    example = Path(__file__).resolve().parent.parent / "examples" / "netdoctor.toml"
    s = cli.resolve_settings(parse(["--config", str(example)]))
    cli.validate_settings(s)
    assert s.targets and s.doh_servers and s.webhook_kind == "slack" and s.confirm == 2


def test_stray_watch_flags_still_error_even_when_the_file_is_fine(tmp_path, capsys):
    cfg = tmp_path / "nd.toml"
    cfg.write_text('targets = ["a.test"]\n')
    assert cli.main(["--config", str(cfg), "--interval", "5"]) == 2
    assert "only valid in watch mode" in capsys.readouterr().err
