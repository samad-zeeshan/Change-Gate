"""README drift check: every table and numeric sentence must match what the results files render."""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.readme_numbers import BLOCKS

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", sorted(BLOCKS))
def test_block_matches_the_results_file(name):
    rendered = BLOCKS[name]()
    assert rendered in README, f"README block {name!r} is stale; rerun python -m eval.readme_numbers"


def test_results_section_has_no_hand_typed_table_rows():
    # Any table row in the results section must come from a rendered block, so a
    # number typed by hand cannot sit next to the generated ones.
    start, end = README.index("## Results"), README.index("## Run it")
    rendered = "\n".join(fn() for fn in BLOCKS.values())
    for line in README[start:end].splitlines():
        if line.startswith("|"):
            assert line in rendered, line


def test_readme_is_the_only_markdown_file():
    import os

    found = []
    for here, dirs, files in os.walk(ROOT):
        # Hidden folders hold the venv, caches and git itself. None of it ships.
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        found += [os.path.relpath(os.path.join(here, f), ROOT) for f in files
                  if f.endswith(".md")]
    assert found == ["README.md"]
