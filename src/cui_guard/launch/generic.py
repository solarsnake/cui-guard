"""Run any command with its base URLs pointed at the gateway."""

from __future__ import annotations

import os
import subprocess
import sys

from cui_guard.launch.session import banner, start_gateway


def run_generic(cmd: list[str], lane: str | None, headless: bool) -> int:
    with start_gateway("generic", lane, headless, os.environ) as s:
        assert s.policy is not None
        print(banner(s, s.policy), file=sys.stderr)
        print(
            "cui-guard: bypass traffic for this agent is not managed. Only requests sent "
            "to the gateway are checked.",
            file=sys.stderr,
        )
        env = dict(os.environ)
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{s.port}"
        env["ANTHROPIC_CUSTOM_HEADERS"] = f"X-CUI-Guard-Token: {s.token}"
        env["OPENAI_BASE_URL"] = f"http://127.0.0.1:{s.port}/v1"
        env["OPENAI_API_KEY"] = s.token
        try:
            return subprocess.run(cmd, env=env, check=False).returncode
        except KeyboardInterrupt:
            return 130
