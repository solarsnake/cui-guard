"""Run any command with its base URLs pointed at the gateway."""

from __future__ import annotations

import os
import subprocess
import sys

from cui_guard.launch.session import (
    add_no_proxy,
    banner,
    exit_on_signals,
    lane_credential_var,
    session_policy,
    start_gateway,
)


def run_generic(cmd: list[str], lane: str | None, headless: bool) -> int:
    with exit_on_signals(), start_gateway("generic", lane, headless, os.environ) as s:
        print(banner(s, session_policy(s)), file=sys.stderr)
        print(
            "cui-guard: bypass traffic for this agent is not managed. Only requests sent "
            "to the gateway are checked. Other vendor keys in the environment may remain.",
            file=sys.stderr,
        )
        env = dict(os.environ)
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY", lane_credential_var(s.lane)):
            if k:
                env.pop(k, None)
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{s.port}"
        env["ANTHROPIC_CUSTOM_HEADERS"] = f"X-CUI-Guard-Token: {s.token}"
        env["OPENAI_BASE_URL"] = f"http://127.0.0.1:{s.port}/v1"
        env["OPENAI_API_KEY"] = s.token
        add_no_proxy(env)
        try:
            return subprocess.run(cmd, env=env, check=False).returncode  # noqa: S603 -- argv list, no shell; command is the user's own
        except KeyboardInterrupt:
            return 130
