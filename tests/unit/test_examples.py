"""Every example directory must pass `ordivus config validate` (no connection needed)."""

from pathlib import Path

import pytest

from ordivus import cli

EXAMPLES = sorted(p for p in (Path(__file__).parents[2] / "examples").glob("*") if p.is_dir())


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.name)
def test_example_validates(example):
    assert cli.main(["config", "validate", "-f", str(example)]) == 0
