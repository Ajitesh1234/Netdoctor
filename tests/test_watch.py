"""Watch-mode engine: change detection, timing, resilience, rendering. No real waiting."""

from __future__ import annotations

import json
import threading

import pytest

from netdoctor import watch
from netdoctor.config import Config
from netdoctor.models import Finding, SessionReport, Severity, Status, TargetReport
from netdoctor.watch import Watcher

CFG = Config()
W, C, I = Severity.WARNING, Severity.CRITICAL, Severity.INFO  # noqa: E741


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def finding(code: str, sev: Severity = W, msg: str | None = None) -> Finding:
    return Finding(sev, code, msg or f"{code} happened", f"fix {code}")


def rep(target: str = "a.test", *findings: Finding) -> TargetReport:
    worst = max((f.severity for f in findings), default=Severity.OK)
    status = Status.FAILING if worst >= C else Status.DEGRADED if worst == W else Status.HEALTHY
    summary = next((f.message for f in findings if f.severity >= W), "No problems detected.")
    return TargetReport(target, target, findings=list(findings), status=status, summary=summary)


def sess(*reports: TargetReport) -> SessionReport:
    return SessionReport("t", "now", list(reports))


@pytest.fixture()
def clock() -> Clock:
    return Clock()


def make(clock: Clock, targets=("a.test",), **kw) -> Watcher:
    return Watcher(targets, CFG, clock=clock, stamp=lambda: "2026-01-01T00:00:00Z", **kw)


# ------------------------------------------------------------------ change detection
def test_first_observation_is_initial_and_lists_only_significant_findings(clock):
    w = make(clock)
    (ev,) = w.observe(sess(rep("a.test", finding("HIGH_LATENCY"), finding("DNS_MISMATCH", I))))
    assert ev.event == "initial" and ev.status is Status.DEGRADED
    assert [f.code for f in ev.added] == ["HIGH_LATENCY"]  # INFO is not significant
    assert ev.report is not None


def test_unchanged_state_is_silent_even_if_messages_differ(clock):
    w = make(clock)
    w.observe(sess(rep("a.test", finding("HIGH_LATENCY", msg="avg 300 ms"))))
    clock.t += 30
    assert w.observe(sess(rep("a.test", finding("HIGH_LATENCY", msg="avg 340 ms")))) == []


def test_info_only_changes_are_ignored(clock):
    w = make(clock)
    w.observe(sess(rep("a.test")))
    assert w.observe(sess(rep("a.test", finding("ICMP_BLOCKED", I)))) == []


def test_status_change_reports_time_in_previous_state(clock):
    w = make(clock)
    w.observe(sess(rep("a.test")))
    clock.t += 90
    (ev,) = w.observe(sess(rep("a.test", finding("TCP_PACKET_LOSS"))))
    assert ev.event == "change" and ev.previous_status is Status.HEALTHY and ev.status is Status.DEGRADED
    assert ev.in_previous_state_s == 90.0 and [f.code for f in ev.added] == ["TCP_PACKET_LOSS"]


def test_same_status_different_codes_is_a_change_without_duration(clock):
    w = make(clock)
    w.observe(sess(rep("a.test", finding("HIGH_LATENCY"))))
    clock.t += 10
    (ev,) = w.observe(sess(rep("a.test", finding("HIGH_JITTER"))))
    assert ev.event == "change" and ev.previous_status is None and ev.in_previous_state_s is None
    assert [f.code for f in ev.added] == ["HIGH_JITTER"] and ev.removed == ["HIGH_LATENCY"]


def test_recovery_event_and_duration_resets(clock):
    w = make(clock)
    w.observe(sess(rep("a.test")))
    clock.t += 5
    w.observe(sess(rep("a.test", finding("TCP_UNREACHABLE", C))))
    clock.t += 120
    (ev,) = w.observe(sess(rep("a.test")))
    assert ev.event == "recovered" and ev.previous_status is Status.FAILING
    assert ev.in_previous_state_s == 120.0 and ev.removed == ["TCP_UNREACHABLE"] and ev.added == []
    clock.t += 7  # a new problem measures from the *recovery*, not from the start
    (ev2,) = w.observe(sess(rep("a.test", finding("HIGH_LATENCY"))))
    assert ev2.in_previous_state_s == 7.0


def test_degraded_to_healthy_also_counts_as_recovered(clock):
    w = make(clock)
    w.observe(sess(rep("a.test", finding("HIGH_LATENCY"))))
    clock.t += 3
    assert w.observe(sess(rep("a.test")))[0].event == "recovered"


def test_failing_to_degraded_is_a_plain_change(clock):
    w = make(clock)
    w.observe(sess(rep("a.test", finding("TCP_UNREACHABLE", C))))
    clock.t += 3
    (ev,) = w.observe(sess(rep("a.test", finding("HIGH_LATENCY"))))
    assert ev.event == "change" and ev.status is Status.DEGRADED and ev.previous_status is Status.FAILING


def test_targets_are_tracked_independently(clock):
    w = make(clock, targets=("a.test", "b.test"))
    w.observe(sess(rep("a.test"), rep("b.test")))
    clock.t += 1
    events = w.observe(sess(rep("a.test"), rep("b.test", finding("HIGH_LATENCY"))))
    assert [(e.target, e.event) for e in events] == [("b.test", "change")]


# ------------------------------------------------------------------ heartbeat
def test_heartbeat_only_for_quiet_targets_and_never_on_first_observation(clock):
    w = make(clock, targets=("a.test", "b.test"), heartbeat=10)
    assert [e.event for e in w.observe(sess(rep("a.test"), rep("b.test")))] == ["initial", "initial"]
    clock.t += 5
    assert w.observe(sess(rep("a.test"), rep("b.test"))) == []
    clock.t += 5
    events = w.observe(sess(rep("a.test"), rep("b.test", finding("HIGH_LATENCY"))))
    assert sorted((e.target, e.event) for e in events) == [("a.test", "heartbeat"), ("b.test", "change")]
    clock.t += 3
    assert w.observe(sess(rep("a.test"), rep("b.test", finding("HIGH_LATENCY")))) == []  # timer was reset


def test_no_heartbeats_when_disabled(clock):
    w = make(clock)
    w.observe(sess(rep("a.test")))
    clock.t += 10_000
    assert w.observe(sess(rep("a.test"))) == []


# ------------------------------------------------------------------ summary / validation
def test_summary_counts_and_percentages(clock):
    w = make(clock)
    for r in (rep("a.test"), rep("a.test", finding("HIGH_LATENCY")), rep("a.test", finding("X", C)), rep("a.test")):
        w.observe(sess(r))
        clock.t += 10
    w.runs = 4
    s = w.summary()
    (t,) = s.targets
    assert (t.checks, t.healthy, t.degraded, t.failing) == (4, 2, 1, 1) and t.healthy_pct == 50.0
    assert t.status is Status.HEALTHY and t.in_state_s == 10.0 and s.runs == 4 and s.duration_s == 40.0


def test_targets_deduplicated_and_arguments_validated(clock):
    assert make(clock, targets=["a.test", "b.test", "a.test"]).targets == ["a.test", "b.test"]
    with pytest.raises(ValueError, match="interval"):
        make(clock, interval=0.5)
    with pytest.raises(ValueError, match="heartbeat"):
        make(clock, heartbeat=-1)


# ------------------------------------------------------------------ the loop
def scripted(*sessions_or_errors):
    calls = []
    it = iter(sessions_or_errors)

    def runner(targets, cfg):
        calls.append(list(targets))
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return item

    return runner, calls


def test_loop_runs_max_runs_and_sleeps_the_remaining_interval(clock):
    w = make(clock, interval=30)
    runner, calls = scripted(sess(rep()), sess(rep()), sess(rep()))
    slept: list[float] = []

    def fake_sleep(seconds, stop):
        slept.append(seconds)
        clock.t += seconds

    def slow_runner(targets, cfg):
        clock.t += 4  # each diagnostic cycle takes 4 s
        return runner(targets, cfg)

    events: list = []
    last = w.loop(events.append, max_runs=3, runner=slow_runner, sleep=fake_sleep)
    assert len(calls) == 3 and w.runs == 3 and last is not None
    assert slept == [26.0, 26.0]  # no sleep after the final run
    assert [e.event for e in events] == ["initial"]


def test_loop_does_not_sleep_when_cycle_overruns_interval(clock):
    w = make(clock, interval=5)
    runner, _ = scripted(sess(rep()), sess(rep()))
    slept: list[float] = []

    def slow(targets, cfg):
        clock.t += 9
        return runner(targets, cfg)

    w.loop(lambda e: None, max_runs=2, runner=slow, sleep=lambda s, st: slept.append(s))
    assert slept == []


def test_loop_survives_a_crashing_cycle(clock):
    w = make(clock, interval=1)
    good = sess(rep("a.test", finding("HIGH_LATENCY")))
    runner, _ = scripted(good, RuntimeError("boom"), good)
    events: list = []
    last = w.loop(events.append, max_runs=3, runner=runner, sleep=lambda s, st: None)
    assert [e.event for e in events] == ["initial", "error"]
    assert "boom" in (events[1].error or "") and w.runs == 3 and last is good


def test_loop_returns_none_when_every_cycle_fails(clock):
    w = make(clock, interval=1)
    runner, _ = scripted(RuntimeError("a"), RuntimeError("b"))
    events: list = []
    assert w.loop(events.append, max_runs=2, runner=runner, sleep=lambda s, st: None) is None
    assert [e.event for e in events] == ["error", "error"]


def test_loop_stops_when_stop_event_is_set(clock):
    w = make(clock, interval=1)
    stop = threading.Event()
    runner, calls = scripted(sess(rep()), sess(rep()), sess(rep()))
    w.loop(lambda e: stop.set(), runner=runner, stop=stop, sleep=lambda s, st: None)
    assert len(calls) == 1 and w.runs == 1


def test_real_sleep_is_interruptible():
    stop = threading.Event()
    threading.Timer(0.2, stop.set).start()
    import time

    t0 = time.monotonic()
    watch._sleep(30, stop)
    assert time.monotonic() - t0 < 3


# ------------------------------------------------------------------ rendering
@pytest.mark.parametrize(
    ("seconds", "text"),
    [(0, "0s"), (45, "45s"), (59.6, "1m 00s"), (270, "4m 30s"), (3600, "1h 00m"), (7980, "2h 13m"), (97200, "1d 03h")],
)
def test_format_duration(seconds, text):
    assert watch.format_duration(seconds) == text


def _events(clock):
    w = make(clock, heartbeat=1)
    out = list(w.observe(sess(rep())))
    clock.t += 270
    out += w.observe(sess(rep("a.test", finding("TCP_PACKET_LOSS"))))
    clock.t += 2
    out += w.observe(sess(rep("a.test", finding("TCP_PACKET_LOSS"))))  # heartbeat
    clock.t += 5
    out += w.observe(sess(rep()))
    return out


def test_text_rendering_of_every_event_kind(clock):
    out = [watch.render_event_text(e, ascii_only=True) for e in _events(clock)]
    joined = "\n".join(out)
    assert "HEALTHY" in out[0] and "No problems detected." in out[0]
    assert (
        "was HEALTHY for 4m 30s" in out[1]
        and "+ TCP_PACKET_LOSS happened" in out[1]
        and "-> fix TCP_PACKET_LOSS" in out[1]
    )
    assert "still degraded" in out[2]
    assert "recovered after 7s as DEGRADED" in out[3] and "- TCP_PACKET_LOSS cleared" in out[3]
    joined.encode("ascii")
    err = watch.WatchEvent("error", "2026-01-01T00:00:00Z", error="kaput")
    assert "watch cycle failed: kaput" in watch.render_event_text(err, ascii_only=True)
    assert "\033[" in watch.render_event_text(_events(clock)[1], color=True)
    assert "\033[" not in watch.render_event_text(_events(clock)[1])


def test_text_rendering_for_code_only_change(clock):
    w = make(clock)
    w.observe(sess(rep("a.test", finding("HIGH_LATENCY"))))
    (ev,) = w.observe(sess(rep("a.test", finding("HIGH_JITTER"))))
    text = watch.render_event_text(ev, ascii_only=True)
    assert "findings changed" in text and "HIGH_LATENCY cleared" in text


def test_json_lines_rendering(clock):
    for ev in _events(clock):
        line = watch.render_event_json(ev)
        assert "\n" not in line
        data = json.loads(line)
        assert data["event"] == ev.event and data["schema_version"] == 1 and data["report"]["target"] == "a.test"
    change = json.loads(watch.render_event_json(_events(clock)[1]))
    assert change["previous_status"] == "healthy" and change["added"][0]["severity"] == "warning"


def test_summary_rendering(clock):
    w = make(clock, targets=("a.test", "bb.test"))
    w.observe(sess(rep("a.test"), rep("bb.test", finding("HIGH_LATENCY"))))
    clock.t += 3725
    w.runs = 1
    s = w.summary()
    text = watch.render_summary_text(s)
    assert "Stopped after 1 run(s) over 1h 02m" in text and "DEGRADED for 1h 02m" in text and "(100% healthy)" in text
    data = json.loads(watch.render_event_json(s))
    assert (
        data["event"] == "summary"
        and data["targets"][0]["target"] == "a.test"
        and data["targets"][0]["healthy_pct"] == 100.0
    )


# ------------------------------------------------------------------ flap damping (--confirm)
def test_confirm_requires_n_consecutive_sightings(clock):
    w = make(clock, confirm=3)
    assert w.observe(sess(rep()))[0].event == "initial"  # the first observation is never delayed
    bad = sess(rep("a.test", finding("TCP_UNREACHABLE", C)))
    clock.t += 10
    assert w.observe(bad) == []
    clock.t += 10
    assert w.observe(bad) == []
    clock.t += 10
    (ev,) = w.observe(bad)
    assert ev.event == "change" and ev.status is Status.FAILING and ev.in_previous_state_s == 30.0


def test_single_blip_never_alerts(clock):
    w = make(clock, confirm=2)
    w.observe(sess(rep()))
    bad, good = sess(rep("a.test", finding("TCP_UNREACHABLE", C))), sess(rep())
    for _ in range(5):  # flapping bad/good/bad/good: the candidate never reaches 2 in a row
        clock.t += 5
        assert w.observe(bad) == []
        clock.t += 5
        assert w.observe(good) == []


def test_a_different_candidate_restarts_the_count(clock):
    w = make(clock, confirm=2)
    w.observe(sess(rep()))
    a, b = sess(rep("a.test", finding("HIGH_LATENCY"))), sess(rep("a.test", finding("TCP_UNREACHABLE", C)))
    assert w.observe(a) == []  # candidate A: 1/2
    assert w.observe(b) == []  # candidate B replaces it: 1/2
    assert w.observe(a) == []  # back to A: 1/2 again
    (ev,) = w.observe(a)  # A confirmed
    assert ev.status is Status.DEGRADED


def test_confirmed_recovery_is_also_damped(clock):
    w = make(clock, confirm=2)
    bad = sess(rep("a.test", finding("TCP_UNREACHABLE", C)))
    w.observe(bad)
    assert w.observe(sess(rep())) == []
    assert w.observe(sess(rep()))[0].event == "recovered"


def test_unconfirmed_changes_produce_no_misleading_heartbeat(clock):
    w = make(clock, confirm=3, heartbeat=5)
    w.observe(sess(rep()))
    clock.t += 6
    assert w.observe(sess(rep("a.test", finding("HIGH_LATENCY")))) == []  # pending, and no heartbeat claiming health


def test_confirm_is_validated(clock):
    for bad in (0, 21):
        with pytest.raises(ValueError, match="confirm"):
            make(clock, confirm=bad)


# ------------------------------------------------------------------ loop bookkeeping used by metrics
def test_loop_tracks_errors_last_session_and_calls_hook(clock):
    w = make(clock, interval=1)
    good = sess(rep())
    runner, _ = scripted(good, RuntimeError("x"), good)
    seen: list = []
    w.loop(lambda e: None, max_runs=3, runner=runner, sleep=lambda s, st: None, on_session=seen.append)
    assert w.errors == 1 and w.runs == 3 and w.last_session is good and seen == [good, good]


def test_rendering_an_event_without_status_or_target_does_not_crash():
    out = watch.render_event_text(watch.WatchEvent("change", "2026-01-01T00:00:00Z"), ascii_only=True)
    assert out.endswith("change") and "2026-01-01 00:00:00Z" in out
