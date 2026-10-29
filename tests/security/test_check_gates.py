"""scripts/check status mapping: exit 3 is a skip only when a gate gave a reason."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _tree_with_fake_pytest(tmp_path: Path, exit_code: int) -> Path:
    """A copy of scripts/check whose venv pytest just exits with `exit_code`."""
    (tmp_path / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts" / "check", tmp_path / "scripts" / "check")
    bindir = tmp_path / ".venv" / "bin"
    bindir.mkdir(parents=True)
    fake = bindir / "pytest"
    fake.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    fake.chmod(0o755)
    return tmp_path


def _run(tree: Path, *gates: str, strict: bool = False) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("CUI_GUARD_ROOT", "CUI_GUARD_STRICT")}
    if strict:
        env["CUI_GUARD_STRICT"] = "1"
    return subprocess.run(
        [str(tree / "scripts" / "check"), *gates],
        capture_output=True, text=True, env=env, timeout=60, check=False,
    )  # fmt: skip


def test_pytest_internal_error_is_a_failure_not_a_skip(tmp_path):
    # pytest exits 3 on an internal error; that must never read as SKIPPED.
    tree = _tree_with_fake_pytest(tmp_path, 3)
    proc = _run(tree, "test")
    assert proc.returncode != 0
    assert "== test: FAIL (exit 3 without a skip reason)" in proc.stdout
    assert "SKIPPED" not in proc.stdout


def test_skip_reason_does_not_leak_into_the_next_gate(tmp_path):
    # `secrets` skips with a reason when gitleaks is absent; the next gate's
    # exit 3 must not inherit that reason.
    tree = _tree_with_fake_pytest(tmp_path, 3)
    env_path = "/usr/bin:/bin"  # no gitleaks on PATH
    env = {k: v for k, v in os.environ.items() if k not in ("CUI_GUARD_ROOT", "CUI_GUARD_STRICT")}
    env["PATH"] = env_path
    env.pop("GITLEAKS_BIN", None)
    proc = subprocess.run(
        [str(tree / "scripts" / "check"), "secrets", "test"],
        capture_output=True, text=True, env=env, timeout=60, check=False,
    )  # fmt: skip
    assert "== secrets: SKIPPED (gitleaks not installed; runs in CI)" in proc.stdout
    assert "== test: FAIL (exit 3 without a skip reason)" in proc.stdout


def test_real_skip_still_skips_locally_and_fails_in_strict_mode(tmp_path):
    tree = _tree_with_fake_pytest(tmp_path, 0)
    env = {k: v for k, v in os.environ.items() if k not in ("CUI_GUARD_ROOT", "CUI_GUARD_STRICT")}
    env["PATH"] = "/usr/bin:/bin"
    env.pop("GITLEAKS_BIN", None)
    local = subprocess.run(
        [str(tree / "scripts" / "check"), "secrets"], capture_output=True, text=True, env=env, timeout=60, check=False
    )
    assert local.returncode == 0 and "== secrets: SKIPPED" in local.stdout
    env["CUI_GUARD_STRICT"] = "1"
    strict = subprocess.run(
        [str(tree / "scripts" / "check"), "secrets"], capture_output=True, text=True, env=env, timeout=60, check=False
    )
    assert strict.returncode != 0
    assert "== secrets: FAIL (skipped in strict mode: gitleaks not installed; runs in CI)" in strict.stdout


def test_passing_gate_passes(tmp_path):
    tree = _tree_with_fake_pytest(tmp_path, 0)
    proc = _run(tree, "test", strict=True)
    assert proc.returncode == 0 and "== test: PASS" in proc.stdout
