import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cui_guard.launch import claude as cl
from cui_guard.launch.claude import (
    build_claude_env,
    build_claude_settings,
    check_claude_version,
)
from cui_guard.launch.session import GatewaySession, LaunchError
from cui_guard.model import Trust
from cui_guard.override.human import FakeChannel
from cui_guard.policy.loader import state_dir, user_config_path
from cui_guard.policy.schema import Endpoint

TOKEN = "tok-abc"


def fake_session(mode):
    lane = Endpoint("anthropic", "https://x.example.invalid", ("anthropic",), Trust.PUBLIC, "none")
    return GatewaySession(4321, TOKEN, "sid", lane, mode, proc=None)  # type: ignore[arg-type]


def test_claude_env_passthrough():
    env = build_claude_env(
        {"ANTHROPIC_API_KEY": "k", "ANTHROPIC_AUTH_TOKEN": "t", "KEEP": "1"},
        fake_session("passthrough"),
    )
    assert "ANTHROPIC_AUTH_TOKEN" not in env and "ANTHROPIC_API_KEY" not in env
    assert env["ANTHROPIC_CUSTOM_HEADERS"] == f"X-CUI-Guard-Token: {TOKEN}"
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4321"
    assert env["KEEP"] == "1"


def test_claude_env_gateway_mode():
    env = build_claude_env({"ANTHROPIC_API_KEY": "k"}, fake_session("gateway"))
    assert env["ANTHROPIC_AUTH_TOKEN"] == TOKEN
    assert "ANTHROPIC_API_KEY" not in env
    for k in (
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "DISABLE_TELEMETRY",
        "DISABLE_ERROR_REPORTING",
        "DISABLE_FEEDBACK_COMMAND",
        "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY",
        "DISABLE_AUTOUPDATER",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL",
    ):
        assert env[k] == "1"
    assert env["ENABLE_CLAUDEAI_MCP_SERVERS"] == "false"


def test_claude_settings_denies():
    st = build_claude_settings(fake_session("gateway"))
    deny = st["permissions"]["deny"]
    cfg, state = user_config_path().parent, state_dir()
    for item in (
        "WebSearch",
        "mcp__claude-in-chrome",
        f"Edit({cfg}/**)",
        f"Write({cfg}/**)",
        f"Edit({state}/**)",
        f"Write({state}/**)",
    ):
        assert item in deny
    assert st["skipWebFetchPreflight"] is True
    assert st["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4321"
    assert TOKEN not in json.dumps(st)


def test_claude_version_too_old():
    with pytest.raises(LaunchError):
        check_claude_version("2.1.200 (Claude Code)")
    with pytest.raises(LaunchError):
        check_claude_version("garbage")
    check_claude_version("2.1.309 (Claude Code)")
    check_claude_version("2.1.285 (Claude Code)")
    check_claude_version("2.2.0 (Claude Code)")


def test_run_claude_uses_settings_file_and_cleans_up(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if cmd[1] == "--version":
            return SimpleNamespace(stdout="2.1.309 (Claude Code)\n", returncode=0)
        import os
        import stat

        path = cmd[2]
        calls.append(("mode", stat.S_IMODE(os.stat(path).st_mode)))
        calls.append(("content", Path(path).read_text()))
        return SimpleNamespace(returncode=7)

    real_start = cl.start_gateway
    monkeypatch.setattr(
        cl,
        "start_gateway",
        lambda agent, lane, headless, env: real_start(
            agent, lane, headless, {"PATH": ""}, channel=FakeChannel("j", True)
        ),
    )
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert cl.run_claude(["-p", "hi"], None, True) == 7
    cmd, kw = calls[1]
    assert cmd[0] == "claude" and cmd[1] == "--settings" and cmd[3:] == ["-p", "hi"]
    token = kw["env"]["ANTHROPIC_CUSTOM_HEADERS"].split(": ", 1)[1]
    assert ("mode", 0o600) in calls
    content = next(c[1] for c in calls if c[0] == "content")
    assert token not in content
    import os

    assert not os.path.exists(cmd[2])


def _patch_start(monkeypatch, mod, mode="passthrough"):
    real_start = mod.start_gateway
    monkeypatch.setattr(
        mod,
        "start_gateway",
        lambda agent, lane, headless, env: real_start(
            agent, lane, headless, {"PATH": ""}, channel=FakeChannel("j", True)
        ),
    )


def test_claude_env_strips_alternate_routes_and_sets_no_proxy():
    base = {
        "CLAUDE_CODE_USE_BEDROCK": "1",
        "CLAUDE_CODE_USE_VERTEX": "1",
        "ANTHROPIC_BEDROCK_BASE_URL": "x",
        "ANTHROPIC_VERTEX_BASE_URL": "x",
        "ANTHROPIC_FOUNDRY_BASE_URL": "x",
        "ANTHROPIC_AWS_BASE_URL": "x",
        "ANTHROPIC_FOUNDRY_API_KEY": "x",
        "ANTHROPIC_FOUNDRY_AUTH_TOKEN": "x",
        "AWS_PROFILE": "x",
        "GOOGLE_APPLICATION_CREDENTIALS": "x",
        "ANTHROPIC_VERTEX_PROJECT_ID": "x",
        "CLOUD_ML_REGION": "x",
        "CLAUDE_CODE_OAUTH_TOKEN": "x",
        "NO_PROXY": "corp.example.invalid",
        "KEEP": "1",
    }
    gw = build_claude_env(base, fake_session("gateway"))
    assert gw == {
        k: gw[k] for k in gw if k in ("KEEP", "NO_PROXY", "no_proxy") or k.startswith(("ANTHROPIC_", "CLAUDE_CODE_DISABLE", "DISABLE_", "ENABLE_"))
    } and "CLAUDE_CODE_OAUTH_TOKEN" not in gw
    for k in base:
        if k not in ("KEEP", "NO_PROXY"):
            assert k not in gw or k.startswith("ANTHROPIC_CUSTOM")
    assert gw["NO_PROXY"] == "corp.example.invalid,127.0.0.1,localhost,::1"
    assert gw["no_proxy"] == "127.0.0.1,localhost,::1"
    pt = build_claude_env(base, fake_session("passthrough"))
    assert pt["CLAUDE_CODE_OAUTH_TOKEN"] == "x" and "CLAUDE_CODE_USE_BEDROCK" not in pt


def test_user_settings_env_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cl.check_user_claude_settings(True)  # no file
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "x", "OK": "1"}})
    )
    with pytest.raises(LaunchError, match="AWS_REGION.*CLAUDE_CODE_USE_BEDROCK|CLAUDE_CODE_USE_BEDROCK"):
        cl.check_user_claude_settings(False)
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"env": {"OK": "1"}}))
    cl.check_user_claude_settings(False)


def test_run_claude_refuses_bad_user_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"CLAUDE_CODE_USE_VERTEX": "1"}})
    )
    _patch_start(monkeypatch, cl)
    ran = []

    def fake_run(cmd, **kw):
        ran.append(cmd)
        return SimpleNamespace(stdout="2.1.309 (Claude Code)\n", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(LaunchError, match="CLAUDE_CODE_USE_VERTEX"):
        cl.run_claude([], None, True)
    assert ran == [["claude", "--version"]]
