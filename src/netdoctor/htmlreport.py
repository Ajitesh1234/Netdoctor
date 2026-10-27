"""Self-contained HTML report.

Design constraints (this file is meant to be attached to tickets, mailed and archived):

* **One file, no external resources, no JavaScript.** A ``Content-Security-Policy`` meta tag
  (``default-src 'none'``) makes browsers enforce that.
* **Everything dynamic is HTML-escaped** (targets, hostnames, error text and certificate fields
  come from the network and must be treated as hostile).
* **Accessible:** semantic headings and tables with captions and ``scope``, status conveyed by
  text *and* symbol (never colour alone), a skip link, AA-contrast palettes for light and dark
  mode, and a print stylesheet.
"""

from __future__ import annotations

from html import escape

from .models import Finding, SessionReport, Severity, Status, TargetReport
from .report import check_lines

_SYMBOL = {Severity.OK: "✔", Severity.INFO: "ℹ", Severity.WARNING: "⚠", Severity.CRITICAL: "✖"}
_LABEL = {Severity.OK: "OK", Severity.INFO: "Info", Severity.WARNING: "Warning", Severity.CRITICAL: "Critical"}
_STATUS_SEV = {Status.HEALTHY: Severity.OK, Status.DEGRADED: Severity.WARNING, Status.FAILING: Severity.CRITICAL}

_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f23;--muted:#4a5568;--line:#d0d7de;--card:#f6f8fa;
--ok:#116329;--info:#0550ae;--warn:#7d4e00;--crit:#a40e26}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#a8b3c0;--line:#30363d;--card:#161b22;
--ok:#56d364;--info:#79c0ff;--warn:#e3b341;--crit:#ff7b72}}
*{box-sizing:border-box}body{margin:0;padding:1.5rem;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:64rem;margin:0 auto}h1{margin-top:0}h2{margin-top:2.5rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;background:var(--card);padding:.5rem}
.meta{color:var(--muted);font-size:.9rem}table{border-collapse:collapse;width:100%;margin:1rem 0}
caption{text-align:left;font-weight:600;padding:.4rem 0}th,td{border:1px solid var(--line);padding:.45rem .6rem;text-align:left;vertical-align:top}
th{background:var(--card)}td.detail{overflow-wrap:anywhere}
.sev{font-weight:700;white-space:nowrap}.sev-ok{color:var(--ok)}.sev-info{color:var(--info)}.sev-warning{color:var(--warn)}.sev-critical{color:var(--crit)}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.8rem 1rem;margin:1rem 0}
ul.findings{list-style:none;padding:0}ul.findings li{margin:.7rem 0;padding-left:.2rem}
.hint{display:block;color:var(--muted);margin-left:1.6rem}code,pre{font:.9rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--card);border:1px solid var(--line);padding:.8rem;overflow-x:auto}
footer{margin-top:3rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--line);padding-top:1rem}
@media print{body{padding:0}.skip{display:none}h2{break-after:avoid}table,.card{break-inside:avoid}}
"""


def _sev(sev: Severity) -> str:
    return (
        f'<span class="sev sev-{sev.name.lower()}"><span aria-hidden="true">{_SYMBOL[sev]}</span> {_LABEL[sev]}</span>'
    )


def _anchor(i: int) -> str:
    return f"target-{i}"


def _finding(f: Finding) -> str:
    hint = f'<span class="hint">{escape(f.hint)}</span>' if f.hint else ""
    return f"<li>{_sev(f.severity)} <code>{escape(f.code)}</code> &mdash; {escape(f.message)}{hint}</li>"


def _target_section(i: int, rep: TargetReport) -> str:
    sev = _STATUS_SEV[rep.status]
    rows = "".join(
        f'<tr><th scope="row">{escape(label)}</th><td>{_sev(s)}</td><td class="detail">{escape(detail)}</td></tr>'
        for s, label, detail in check_lines(rep)
    )
    trace = ""
    if rep.traceroute and rep.traceroute.ok:
        trace = "<h3>Traceroute</h3><pre>" + escape("\n".join(rep.traceroute.hops)) + "</pre>"
    return f"""<section aria-labelledby="{_anchor(i)}">
<h2 id="{_anchor(i)}">{escape(rep.target)}</h2>
<div class="card"><p><strong>Status:</strong> {_sev(sev)} {escape(rep.status.value.upper())}</p>
<p><strong>Summary:</strong> {escape(rep.summary)}</p>
<p class="meta">Diagnosis took {rep.duration_ms / 1000:.1f}&nbsp;s</p></div>
<table><caption>Checks performed</caption>
<thead><tr><th scope="col">Check</th><th scope="col">Result</th><th scope="col">Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
<h3>Findings</h3><ul class="findings">{"".join(_finding(f) for f in rep.findings)}</ul>{trace}
</section>"""


def render_html(session: SessionReport) -> str:
    overview = "".join(
        f'<tr><th scope="row"><a href="#{_anchor(i)}">{escape(r.target)}</a></th>'
        f"<td>{_sev(_STATUS_SEV[r.status])} {escape(r.status.value.upper())}</td><td>{escape(r.summary)}</td></tr>"
        for i, r in enumerate(session.reports)
    )
    sections = "\n".join(_target_section(i, r) for i, r in enumerate(session.reports))
    run = f" &middot; run <code>{escape(session.run_id)}</code>" if session.run_id else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<meta name="generator" content="NetDoctor {escape(session.tool_version)}">
<title>NetDoctor report &ndash; {escape(session.generated_at)}</title><style>{_CSS}</style></head>
<body><a class="skip" href="#main">Skip to report</a>
<main id="main"><h1>NetDoctor report</h1>
<p class="meta">Generated {escape(session.generated_at)} by NetDoctor {escape(session.tool_version)}{run}</p>
<table><caption>Overview of {len(session.reports)} target(s)</caption>
<thead><tr><th scope="col">Target</th><th scope="col">Status</th><th scope="col">Summary</th></tr></thead>
<tbody>{overview}</tbody></table>
{sections}
<footer>Findings are evidence-based hints, not proof. Some conditions (CDN DNS variation, bot protection,
filtered ICMP) have innocent explanations; see the project documentation for limitations.</footer>
</main></body></html>
"""
