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
    banner,
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
    env = dict(base)
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("ANTHROPIC_AUTH_TOKEN", None)
    env.update(_base_url_env(s))
    env["ANTHROPIC_CUSTOM_HEADERS"] = f"X-CUI-Guard-Token: {s.token}"
    if s.credential_mode != "passthrough":
        env["ANTHROPIC_AUTH_TOKEN"] = s.token
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
    with start_gateway("claude", lane, headless, os.environ) as s:
        assert s.policy is not None
        print(banner(s, s.policy), file=sys.stderr)
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
