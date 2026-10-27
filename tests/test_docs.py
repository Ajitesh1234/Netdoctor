"""Documentation must not drift from the code. These tests fail when it does."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import re
import time
from pathlib import Path

import pytest

from netdoctor import __version__, cli, notify

ROOT = Path(__file__).resolve().parent.parent
MD_FILES = [
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "CHANGELOG.md",
    *sorted((ROOT / "docs").glob("*.md")),
]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_docs", ROOT / "scripts" / "gen_docs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ generated references
def test_generated_references_are_up_to_date():
    gen = load_generator()
    for rel, fn in gen.FILES.items():
        assert read(rel) == fn(), f"{rel} is stale: run `python scripts/gen_docs.py`"


def test_every_setting_and_flag_is_documented():
    gen = load_generator()
    from netdoctor.settings import SCHEMA

    for section, body in SCHEMA.items():
        for key in body:
            assert f"{section}.{key}" in gen.DOCS and f"{section}.{key}" in gen.FLAGS, (
                f"undocumented setting {section}.{key}"
            )


# ------------------------------------------------------------------ threat model traceability
def test_every_test_referenced_by_the_threat_model_exists():
    refs = re.findall(r"tests/(test_\w+\.py)::(test_\w+)", read("docs/THREAT_MODEL.md"))
    assert len(refs) >= 25
    for filename, name in refs:
        source = (ROOT / "tests" / filename).read_text(encoding="utf-8")
        assert re.search(rf"^def {name}\(", source, re.M), f"THREAT_MODEL.md references missing test {filename}::{name}"


# ------------------------------------------------------------------ the documented webhook verifier
def _verifier(tmp_path):
    block = re.search(
        r"<!-- verifier:start -->\s*```python\n(.*?)```\s*<!-- verifier:end -->", read("docs/DEPLOYMENT.md"), re.S
    )
    assert block, "verifier snippet missing from DEPLOYMENT.md"
    module_file = tmp_path / "documented_verifier.py"
    module_file.write_text(block.group(1), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("documented_verifier", module_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


def test_the_documented_webhook_verifier_accepts_real_signatures_and_rejects_forgeries(tmp_path):
    verify = _verifier(tmp_path)
    body, ts = b'{"event":"change"}', str(int(time.time()))
    good = {"X-NetDoctor-Timestamp": ts, "X-NetDoctor-Signature": notify.sign("s3cret", ts, body)}
    assert verify("s3cret", good, body) is True
    assert verify("wrong", good, body) is False  # wrong key
    assert verify("s3cret", good, body + b" ") is False  # tampered body
    old = str(int(time.time()) - 3600)
    stale = {"X-NetDoctor-Timestamp": old, "X-NetDoctor-Signature": notify.sign("s3cret", old, body)}
    assert verify("s3cret", stale, body) is False  # replay of an old message
    assert (
        verify("s3cret", {}, body) is False
        and verify("s3cret", {"X-NetDoctor-Timestamp": "x", "X-NetDoctor-Signature": "y"}, body) is False
    )
    # and it matches an independent implementation of the documented algorithm
    expect = "sha256=" + hmac.new(b"s3cret", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert good["X-NetDoctor-Signature"] == expect


# ------------------------------------------------------------------ README <-> engine
def test_readme_finding_codes_match_the_analysis_engine():
    source = (ROOT / "src" / "netdoctor" / "analysis.py").read_text(encoding="utf-8")
    in_code = set(re.findall(r'"([A-Z]+(?:_[A-Z0-9]+)+)"', source))
    section = read("README.md").split("### Finding codes", 1)[1].split("Default thresholds", 1)[0]
    in_readme = set(re.findall(r"`([A-Z]+(?:_[A-Z0-9]+)+)`", section))
    assert in_code == in_readme, (
        f"only in code: {sorted(in_code - in_readme)}; only in README: {sorted(in_readme - in_code)}"
    )


# ------------------------------------------------------------------ links and examples
@pytest.mark.parametrize("path", MD_FILES, ids=lambda p: p.name)
def test_relative_links_resolve(path):
    for target in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
        if re.match(r"(https?:|mailto:|#)", target):
            continue
        file_part = target.split("#", 1)[0]
        assert (path.parent / file_part).exists(), f"{path.name}: broken link {target}"


def test_documented_command_examples_use_real_flags():
    known = {opt for a in cli.build_parser()._actions for opt in a.option_strings}
    bad = []
    for path in MD_FILES:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip().lstrip("$ ").lstrip("`")
            if "docker " in stripped or not re.match(r"(netdoctor|python -m netdoctor)\s", stripped):
                continue
            for flag in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", stripped):
                if flag not in known:
                    bad.append((path.name, flag, stripped[:70]))
    assert not bad, f"docs mention unknown flags: {bad}"


def test_every_documented_flag_in_the_readme_exists():
    known = {opt for a in cli.build_parser()._actions for opt in a.option_strings}
    mentioned = set(re.findall(r"`(--[a-z][a-z0-9-]+)", read("README.md")))
    assert mentioned - known == set(), f"README mentions flags that do not exist: {sorted(mentioned - known)}"


# ------------------------------------------------------------------ release plumbing
def test_changelog_has_an_entry_for_the_current_version():
    assert re.search(rf"^## \[{re.escape(__version__)}\]", read("CHANGELOG.md"), re.M), (
        "the release workflow publishes these notes"
    )


def test_distribution_name_is_not_the_taken_pypi_name():
    text = read("pyproject.toml")
    assert 'name = "netdoctor-cli"' in text and 'name = "netdoctor"' not in text


def test_example_files_are_present_and_valid():
    for name in ("netdoctor.toml", "netdoctor.service", "prometheus-alerts.yml", "kubernetes.yaml"):
        assert (ROOT / "examples" / name).stat().st_size > 200
    yaml = pytest.importorskip("yaml")
    for name in ("prometheus-alerts.yml", "kubernetes.yaml"):
        yaml.safe_load(read(f"examples/{name}"))
