from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_security_rules_enabled_for_src():
    lint = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["ruff"]["lint"]
    assert "S" in lint["extend-select"]
    assert lint["per-file-ignores"]["tests/**"] == ["S101", "S104", "S105", "S106", "S108", "S311", "S603", "S607"]


def test_every_noqa_S_has_a_reason():
    for path in (ROOT / "src").rglob("*.py"):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "noqa: S" in line:
                assert re.search(r"noqa: S\d+(,\s*S\d+)*\s+--\s+\S", line), f"{path}:{n}"
