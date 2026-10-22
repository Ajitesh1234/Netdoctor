"""Renderers: terminal text, Markdown and JSON. Pure functions; no I/O."""

from __future__ import annotations

import json

from .models import Finding, SessionReport, Severity, Status, TargetReport, to_plain

_ICONS = {Severity.OK: "✔", Severity.INFO: "ℹ", Severity.WARNING: "⚠", Severity.CRITICAL: "✖"}
_ASCII = {Severity.OK: "[ OK ]", Severity.INFO: "[INFO]", Severity.WARNING: "[WARN]", Severity.CRITICAL: "[FAIL]"}
_COLORS = {Severity.OK: "32", Severity.INFO: "36", Severity.WARNING: "33", Severity.CRITICAL: "31"}
_STATUS_SEV = {Status.HEALTHY: Severity.OK, Status.DEGRADED: Severity.WARNING, Status.FAILING: Severity.CRITICAL}


def render_json(session: SessionReport) -> str:
    return json.dumps(to_plain(session), indent=2, ensure_ascii=False)


# ------------------------------------------------------------------ check summaries
def _fmt(v: float | None, unit: str = "ms") -> str:
    return "n/a" if v is None else f"{v:g} {unit}"


def check_lines(rep: TargetReport) -> list[tuple[Severity, str, str]]:
    """One ``(severity, label, detail)`` row per check performed."""
    rows: list[tuple[Severity, str, str]] = []
    tcp_dead = bool(rep.tcp) and not any(t.ok for t in rep.tcp)
    d = rep.dns
    if d:
        if d.ok:
            extra = ""
            pub = [r for r in d.public if r.ok]
            if d.public:
                extra = f"; {len(pub)}/{len(d.public)} public resolvers answered"
            detail = (
                "literal IP address" if d.skipped else f"{', '.join(d.addresses[:4])} ({_fmt(d.latency_ms)}){extra}"
            )
            rows.append((Severity.OK, "DNS", detail))
        else:
            rows.append((Severity.CRITICAL, "DNS", f"{d.error_kind}: {d.error}"))
    for tc in rep.tcp:
        label = f"TCP {tc.port}/{tc.family[-2:]}"
        if tc.ok:
            sev = Severity.WARNING if tc.loss_pct > 0 else Severity.OK
            rows.append(
                (
                    sev,
                    label,
                    f"{tc.address} avg {_fmt(tc.avg_ms)}, jitter {_fmt(tc.jitter_ms)}, loss {tc.loss_pct:g}% ({tc.successes}/{tc.attempts})",
                )
            )
        else:
            rows.append((Severity.CRITICAL, label, f"{tc.address} {tc.error_kind}: {tc.error}"))
    if rep.tls:
        tl = rep.tls
        if tl.ok:
            rows.append(
                (
                    Severity.OK,
                    "TLS",
                    f"{tl.version}, {tl.issuer or 'unknown issuer'}, expires in {_fmt(tl.days_to_expiry, 'days')} (handshake {_fmt(tl.handshake_ms)})",
                )
            )
        else:
            sev = Severity.INFO if tcp_dead else Severity.CRITICAL
            rows.append((sev, "TLS", f"{'(follows from TCP failure) ' if tcp_dead else ''}{tl.error_kind}: {tl.error}"))
    if rep.http:
        h = rep.http
        if h.ok:
            sev = Severity.OK if (h.status or 0) < 400 else Severity.WARNING
            rows.append(
                (
                    sev,
                    "HTTP",
                    f"{h.status} {h.reason} via {h.scheme}, TTFB {_fmt(h.ttfb_ms)}, total {_fmt(h.total_ms)}, {len(h.hops)} request(s)",
                )
            )
        else:
            sev = Severity.INFO if tcp_dead else Severity.CRITICAL
            rows.append((sev, "HTTP", f"{'(follows from TCP failure) ' if tcp_dead else ''}{h.error_kind}: {h.error}"))
    if rep.icmp:
        ic = rep.icmp
        if not ic.available:
            rows.append((Severity.INFO, "ICMP", f"not run: {ic.error}"))
        elif ic.ok:
            sev = Severity.WARNING if (ic.loss_pct or 0) > 0 else Severity.OK
            rows.append((sev, "ICMP", f"avg {_fmt(ic.avg_ms)}, jitter {_fmt(ic.jitter_ms)}, loss {ic.loss_pct:g}%"))
        else:
            rows.append((Severity.INFO, "ICMP", ic.error or "no reply"))
    if rep.traceroute:
        tr = rep.traceroute
        if not tr.available:
            rows.append((Severity.INFO, "TRACE", f"not run: {tr.error}"))
        elif tr.ok:
            note = " (truncated)" if tr.truncated else ""
            rows.append((Severity.OK, "TRACE", f"{len(tr.hops)} hop(s){note}"))
        else:
            rows.append((Severity.INFO, "TRACE", tr.error or "failed"))
    return rows


# ------------------------------------------------------------------ text
def _paint(text: str, sev: Severity, color: bool) -> str:
    return f"\033[{_COLORS[sev]}m{text}\033[0m" if color else text


def render_text(session: SessionReport, *, ascii_only: bool = False, color: bool = False) -> str:
    icons = _ASCII if ascii_only else _ICONS
    out: list[str] = [f"NetDoctor {session.tool_version}  -  {session.generated_at}", ""]
    for rep in session.reports:
        sev = _STATUS_SEV[rep.status]
        badge = _paint(f"{icons[sev]} {rep.status.value.upper()}", sev, color)
        out.append(f"{rep.target}  {badge}  ({rep.duration_ms / 1000:.1f}s)")
        out.append(f"  {rep.summary}")
        out.append("")
        for csev, label, detail in check_lines(rep):
            out.append(f"  {_paint(icons[csev], csev, color)} {label:<11} {detail}")
        out.append("")
        out.append("  Findings:")
        for f in rep.findings:
            out.append(f"    {_paint(icons[f.severity], f.severity, color)} {f.message}")
            if f.hint:
                out.append(f"        -> {f.hint}")
        if rep.traceroute and rep.traceroute.ok:
            out += ["", "  Traceroute:"] + [f"    {h}" for h in rep.traceroute.hops]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# ------------------------------------------------------------------ markdown
def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(session: SessionReport) -> str:
    out = ["# NetDoctor Report", "", f"_Generated {session.generated_at} by NetDoctor {session.tool_version}_", ""]
    for rep in session.reports:
        out += [f"## {rep.target} — {rep.status.value.upper()}", "", f"**Summary:** {rep.summary}", ""]
        out += ["| Check | Result |", "| --- | --- |"]
        for sev, label, detail in check_lines(rep):
            out.append(f"| {label} | {_ICONS[sev]} {_md_escape(detail)} |")
        out += ["", "### Findings", ""]
        for f in rep.findings:
            out.append(_md_finding(f))
        if rep.traceroute and rep.traceroute.ok:
            out += ["", "### Traceroute", "", "```text", *rep.traceroute.hops, "```"]
        out.append("")
    return "\n".join(out)


def _md_finding(f: Finding) -> str:
    line = f"- {_ICONS[f.severity]} **{f.severity.name}** `{f.code}` — {f.message}"
    return line + (f"  \n  _Hint:_ {f.hint}" if f.hint else "")
