"""The demo page keeps its four runs, its picker and counters, and loads nothing it should not."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

SITE = Path(__file__).resolve().parents[1] / "site"
# Fonts come from Google Fonts. Everything else the page loads must ship in site/.
ALLOWED_HOSTS = ("https://fonts.googleapis.com", "https://fonts.gstatic.com", "https://github.com/samad-zeeshan/")


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.runs: list[str] = []
        self.ids: set[str] = set()
        self.refs: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "data-run" in a:
            self.runs.append(a["data-run"])
        if "id" in a:
            self.ids.add(a["id"])
        for key in ("src", "href"):
            if key in a and tag in ("script", "link", "a"):
                self.refs.append(a[key])


def _page() -> _Page:
    p = _Page()
    p.feed((SITE / "index.html").read_text(encoding="utf-8"))
    return p


def test_four_runs_with_the_tamper_last():
    assert _page().runs == ["safe", "dangerous", "attack", "tamper"]


def test_the_elements_the_script_needs_exist():
    ids = _page().ids
    app = (SITE / "app.js").read_text(encoding="utf-8")
    for needed in re.findall(r'getElementById\("([^"]+)"\)', app):
        assert needed in ids, needed


def test_every_reference_resolves_or_is_allowed():
    for ref in _page().refs:
        if ref.startswith(("data:", "#")):
            continue
        if ref.startswith("http"):
            assert ref.startswith(ALLOWED_HOSTS), ref
            continue
        assert (SITE / ref).is_file(), ref


def test_the_page_hashes_the_chain_like_the_server():
    app = (SITE / "app.js").read_text(encoding="utf-8")
    assert 'sha256(prev + "\\n" + entry.blob)' in app


def test_assets_stay_small():
    total = sum(f.stat().st_size for f in SITE.rglob("*") if f.is_file())
    assert total < 2 * 1024 * 1024
