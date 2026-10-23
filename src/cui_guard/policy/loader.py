"""Locate and load policy files, and build the effective policy."""

from __future__ import annotations

import os
import sys
import tomllib
from importlib import resources
from pathlib import Path

from cui_guard.policy.merge import merge_layers
from cui_guard.policy.schema import (
    EffectivePolicy,
    PolicyError,
    PolicyLayer,
    parse_layer,
)


def user_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "cui-guard" / "config.toml"


def org_policy_path() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/cui-guard/policy.toml")
    return Path("/etc/cui-guard/policy.toml")


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "cui-guard"


def _read_layer(path: Path, source: str) -> PolicyLayer:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise PolicyError(f"cannot read {source} policy {path}: {e}") from e
    return parse_layer(data, source)


def load_builtin_layer() -> PolicyLayer:
    text = resources.files("cui_guard.policy").joinpath("builtin.toml").read_text(encoding="utf-8")
    try:
        return parse_layer(tomllib.loads(text), "builtin")
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"cannot parse builtin policy: {e}") from e


def load_effective_policy(
    user_path: Path | None = None, org_path: Path | None = None
) -> tuple[EffectivePolicy, PolicyLayer | None]:
    """Load and merge all layers. Any unreadable or invalid file that exists raises."""
    user_path = user_path if user_path is not None else user_config_path()
    org_path = org_path if org_path is not None else org_policy_path()
    user = _read_layer(user_path, "user") if user_path.exists() else None
    org = _read_layer(org_path, "org") if org_path.exists() else None
    return merge_layers(load_builtin_layer(), user, org), user
