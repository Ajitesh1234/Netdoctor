"""HTML report: structure, accessibility hooks, and hostile-input safety."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from netdoctor.htmlreport import render_html
from netdoctor.models import (
    DnsResult,
    Finding,
    HttpResult,
    SessionReport,
    Severity,
    Status,
    TargetReport,
    TcpResult,
    TracerouteResult,
)

VOID = {"meta", "br", "hr", "img", "input", "link"}
EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


class Checker(HTMLParser):
    """Verifies tags are balanced and collects structural facts."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.tags: list[str] = []
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for k, v in attrs:
            self.attrs.append((k, v))
            if k == "id" and v:
                self.ids.add(v)
            if k == "href" and v:
                self.hrefs.append(v)
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        assert self.stack and self.stack[-1] == tag, f"unbalanced </{tag}>, open: {self.stack[-3:]}"
        self.stack.pop()


def parse(html: str) -> Checker:
    c = Checker()
    c.feed(html)
    c.close()
    assert c.stack == [], f"unclosed tags: {c.stack}"
    return c


def make(target="shop.example", **kw) -> TargetReport:
    base = {
        "dns": DnsResult(True, ["1.2.3.4"], 12.0),
        "tcp": [TcpResult(443, "1.2.3.4", "ipv4", 5, 5, 0.0, 10, 12, 15, 1)],
        "http": HttpResult(True, "https", "https://x/", 200, "OK", 10, 80.0, 100),
        "findings": [Finding(Severity.WARNING, "HIGH_LATENCY", "slow link", "try later")],
        "status": Status.DEGRADED,
        "summary": "slow link",
        "duration_ms": 2500.0,
    }
    base.update(kw)
    return TargetReport(target, target, **base)


def session(*reports, **kw) -> SessionReport:
    return SessionReport("1.2.0", "2026-10-23T10:00:00Z", list(reports), **kw)


def test_document_is_well_formed_and_self_contained():
    html = render_html(session(make("a.test"), make("b.test")))
    c = parse(html)
    assert html.startswith("<!doctype html>") and '<html lang="en">' in html
    assert "default-src 'none'" in html and "<script" not in html.lower()
    assert not [1 for k, v in c.attrs if k in ("src", "srcset", "action", "formaction")]  # nothing loads externally
    assert all(h.startswith("#") for h in c.hrefs)  # only in-page links


def test_overview_links_resolve_to_sections():
    c = parse(render_html(session(make("a.test"), make("b.test"), make("c.test"))))
    assert len(c.hrefs) == 4 and all(h[1:] in c.ids for h in c.hrefs if h != "#main")


def test_accessibility_structure():
    html = render_html(session(make()))
    c = parse(html)
    assert '<a class="skip" href="#main">' in html and 'id="main"' in html
    assert c.tags.count("caption") == c.tags.count("table") == 2
    assert ("scope", "col") in c.attrs and ("scope", "row") in c.attrs
    assert "color-scheme" in html and "@media print" in html
    # status is conveyed with text, not colour alone
    assert "Warning" in html and "DEGRADED" in html


def test_every_severity_has_a_text_label():
    findings = [Finding(s, f"C_{s.name}", f"m {s.name}") for s in Severity]
    html = render_html(session(make(findings=findings)))
    for label in ("OK", "Info", "Warning", "Critical"):
        assert f"</span> {label}</span>" in html


def test_hostile_input_is_escaped_everywhere():
    rep = make(
        EVIL,
        findings=[Finding(Severity.CRITICAL, 'X"><b>', EVIL, EVIL)],
        summary=EVIL,
        http=HttpResult(False, error=EVIL, error_kind=EVIL),
        traceroute=TracerouteResult(True, hops=[EVIL]),
        status=Status.FAILING,
    )
    html = render_html(SessionReport("<b>1</b>", EVIL, [rep], run_id=EVIL))
    parse(html)
    assert "<script>alert" not in html and "<img src=x" not in html and "<b>1</b>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "onerror=alert(2)" in html and "&quot;&gt;&lt;img" in html  # present only as inert text


def test_traceroute_and_run_id_are_shown():
    rep = make(traceroute=TracerouteResult(True, hops=[" 1  10.0.0.1  1.2 ms"]))
    html = render_html(session(rep, run_id="abc123"))
    assert "<pre> 1  10.0.0.1  1.2 ms</pre>" in html and "run <code>abc123</code>" in html


def test_empty_session_is_still_valid():
    html = render_html(session())
    parse(html)
    assert "Overview of 0 target(s)" in html


def test_no_hint_means_no_hint_markup():
    html = render_html(session(make(findings=[Finding(Severity.WARNING, "X", "m")])))
    assert 'class="hint"' not in re.sub(r"<style>.*?</style>", "", html, flags=re.S)
