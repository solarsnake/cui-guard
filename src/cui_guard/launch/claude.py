"""Launch Claude Code through the gateway with bypass traffic turned off."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from cui_guard.launch.session import (
    GatewaySession,
    LaunchError,
    add_no_proxy,
    banner,
    exit_on_signals,
    lane_credential_var,
    session_policy,
    start_gateway,
    version_lt,
    version_tuple,
)
from cui_guard.policy.loader import state_dir, user_config_path

MIN_CLAUDE_VERSION = "2.1.285"

_LOCKDOWN_ENV = {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_FEEDBACK_COMMAND": "1",
    "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
    "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    "DISABLE_AUTOUPDATER": "1",
    "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
}


_STRIP_EXACT = (
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "ANTHROPIC_AWS_BASE_URL",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "CLOUD_ML_REGION",
)


def _is_alt_route(name: str, gateway_mode: bool) -> bool:
    return (
        name.startswith(("CLAUDE_CODE_USE_", "AWS_"))
        or name in _STRIP_EXACT
        or (gateway_mode and name == "CLAUDE_CODE_OAUTH_TOKEN")
    )


def _settings_files() -> list[Path]:
    """User settings, then project settings in the working directory and every parent."""
    files = [Path.home() / ".claude" / "settings.json"]
    cwd = Path.cwd()
    for d in (cwd, *cwd.parents):
        files += [d / ".claude" / "settings.json", d / ".claude" / "settings.local.json"]
    seen: set[Path] = set()
    out = []
    for f in files:
        key = f.absolute()
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def check_user_claude_settings(gateway_mode: bool) -> None:
    """Refuse if any Claude settings file in effect sets variables that bypass the gateway."""
    for path in _settings_files():
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise LaunchError(f"cannot read {path}: {e}") from e
        env = data.get("env") if isinstance(data, dict) else None
        if not isinstance(env, dict):
            continue
        bad = sorted(k for k in env if _is_alt_route(k, gateway_mode))
        if bad:
            raise LaunchError(
                f"{path} sets {', '.join(bad)}, which can send traffic around the gateway; "
                "remove them before using cui-guard"
            )


def check_claude_version(output: str) -> None:
    m = re.search(r"\d+(?:\.\d+)+", output)
    if not m:
        raise LaunchError(f"cannot read the Claude Code version from {output.strip()!r}")
    if version_lt(version_tuple(m.group(0)), version_tuple(MIN_CLAUDE_VERSION)):
        raise LaunchError(
            f"Claude Code {m.group(0)} is older than {MIN_CLAUDE_VERSION}, "
            "the minimum that supports the lockdown settings"
        )


def _base_url_env(s: GatewaySession) -> dict[str, str]:
    return {"ANTHROPIC_BASE_URL": f"http://127.0.0.1:{s.port}", **_LOCKDOWN_ENV}


def build_claude_env(base: Mapping[str, str], s: GatewaySession) -> dict[str, str]:
    env = {
        k: v for k, v in base.items() if not _is_alt_route(k, s.credential_mode != "passthrough")
    }
    env.pop("ANTHROPIC_API_KEY", None)
    var = lane_credential_var(s.lane)
    if var:
        env.pop(var, None)
    env.pop("ANTHROPIC_AUTH_TOKEN", None)
    env.update(_base_url_env(s))
    env["ANTHROPIC_CUSTOM_HEADERS"] = f"X-CUI-Guard-Token: {s.token}"
    if s.credential_mode != "passthrough":
        env["ANTHROPIC_AUTH_TOKEN"] = s.token
    add_no_proxy(env)
    return env


def build_claude_settings(s: GatewaySession) -> dict:
    """Settings file content. The token is never written here; it travels in the env only."""
    cfg_dir = user_config_path().parent
    st_dir = state_dir()
    return {
        "env": _base_url_env(s),
        "skipWebFetchPreflight": True,
        "permissions": {
            "deny": [
                "WebSearch",
                "mcp__claude-in-chrome",
                f"Edit({cfg_dir}/**)",
                f"Write({cfg_dir}/**)",
                f"Edit({st_dir}/**)",
                f"Write({st_dir}/**)",
            ]
        },
    }


def run_claude(args: list[str], lane: str | None, headless: bool) -> int:
    try:
        ver = subprocess.run(
            ["claude", "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LaunchError(f"cannot run claude --version: {e}") from e
    check_claude_version(ver.stdout)
    with exit_on_signals(), start_gateway("claude", lane, headless, os.environ) as s:
        check_user_claude_settings(s.credential_mode != "passthrough")
        print(banner(s, session_policy(s)), file=sys.stderr)
        fd, name = tempfile.mkstemp(prefix="cui-guard-claude-", suffix=".json")
        path = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(build_claude_settings(s), f)
            try:
                return subprocess.run(
                    ["claude", "--settings", name, *args],
                    env=build_claude_env(os.environ, s),
                    check=False,
                ).returncode
            except KeyboardInterrupt:
                return 130
        finally:
            path.unlink(missing_ok=True)
