"""Launch Codex CLI through the gateway as a custom model provider."""

from __future__ import annotations

import json
import os
import subprocess
import sys
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
)


def build_codex_args(s: GatewaySession) -> list[str]:
    pairs = [
        'model_provider="cuiguard"',
        'model_providers.cuiguard.name="cui-guard"',
        f'model_providers.cuiguard.base_url="http://127.0.0.1:{s.port}/v1"',
        'model_providers.cuiguard.env_key="CUI_GUARD_TOKEN"',
        'model_providers.cuiguard.wire_api="responses"',
        "analytics.enabled=false",
        "feedback.enabled=false",
        "check_for_update_on_startup=false",
        'otel.exporter="none"',
        'otel.trace_exporter="none"',
        'otel.metrics_exporter="none"',
    ]
    out: list[str] = []
    for p in pairs:
        out += ["-c", p]
    return out


def detect_chatgpt_session(codex_home: Path) -> bool:
    """True if a stored ChatGPT login exists. An unreadable auth file counts as one."""
    auth = Path(codex_home) / "auth.json"
    if not auth.exists():
        return False
    try:
        data = json.loads(auth.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(data, dict):
        return True
    return data.get("tokens") is not None or data.get("auth_mode") == "chatgpt"


def run_codex(args: list[str], lane: str | None, headless: bool) -> int:
    home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    if detect_chatgpt_session(home):
        raise LaunchError(
            f"a stored ChatGPT login was found in {home / 'auth.json'}. Codex may send "
            "traffic with that login directly to OpenAI, outside the gateway "
            "(spec 13 trade-off). Sign out (codex logout) and use an API key instead. "
            "ChatGPT logins stored in the OS keyring cannot be detected; do not use "
            "one with cui-guard."
        )
    with exit_on_signals(), start_gateway("codex", lane, headless, os.environ) as s:
        print(banner(s, session_policy(s)), file=sys.stderr)
        env = dict(os.environ)
        for k in ("OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", lane_credential_var(s.lane)):
            if k:
                env.pop(k, None)
        env["CUI_GUARD_TOKEN"] = s.token
        add_no_proxy(env)
        try:
            return subprocess.run(
                ["codex", *build_codex_args(s), *args], env=env, check=False
            ).returncode
        except KeyboardInterrupt:
            return 130
