import json
import os
import stat

import httpx
import pytest

from cui_guard.launch import session as sess
from cui_guard.launch.session import (
    LaunchError,
    banner,
    prepare_policy,
    resolve_credential,
    start_gateway,
)
from cui_guard.model import Trust
from cui_guard.override.human import FakeChannel
from cui_guard.policy.loader import state_dir, user_config_path
from cui_guard.policy.schema import Endpoint, parse_layer
from cui_guard.policy.snapshot import save_snapshot, snapshot_path


def ep(cred):
    return Endpoint("x", "https://x.example.invalid", ("anthropic",), Trust.PUBLIC, cred)


def test_resolve_passthrough_when_no_key():
    assert resolve_credential(ep("env-or-passthrough:K"), {}) == ("passthrough", None)


def test_resolve_gateway_when_key():
    assert resolve_credential(ep("env-or-passthrough:K"), {"K": "v"}) == ("gateway", "v")
    assert resolve_credential(ep("env:K"), {"K": "v"}) == ("gateway", "v")
    assert resolve_credential(ep("none"), {}) == ("none", None)


def test_env_missing_raises():
    with pytest.raises(LaunchError):
        resolve_credential(ep("env:K"), {})


def _loosened_setup():
    save_snapshot(snapshot_path(), parse_layer({"profile": "cui"}, "user"))
    cfg = user_config_path()
    cfg.parent.mkdir(parents=True)
    cfg.write_text('profile = "general"\n')


def test_headless_refuses_loosening():
    _loosened_setup()
    with pytest.raises(LaunchError, match="profile"):
        prepare_policy(True, FakeChannel("j", True))


def test_loosening_requires_auth():
    _loosened_setup()
    ch = FakeChannel("j", False)
    with pytest.raises(LaunchError):
        prepare_policy(False, ch)
    assert ch.auth_requests and "approve loosened settings" in ch.auth_requests[0]


def test_loosening_needs_auth_every_launch():
    """The snapshot never authorizes: an approved loosening is asked for again next launch (I3)."""
    _loosened_setup()
    ch = FakeChannel("j", True)
    assert prepare_policy(False, ch).profile == "general"
    assert "changed since your last approval: profile changed from cui to general" in ch.auth_requests[0]
    again = FakeChannel("j", True)
    assert prepare_policy(False, again).profile == "general"
    assert len(again.auth_requests) == 1
    assert "changed since your last approval" not in again.auth_requests[0]  # nothing new
    with pytest.raises(LaunchError, match="interactive approval"):
        prepare_policy(True, FakeChannel("j", True))
    with pytest.raises(LaunchError, match="not approved"):
        prepare_policy(False, FakeChannel("j", False))


def _write_user(text):
    cfg = user_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(text)


def test_forged_snapshot_does_not_authorize():
    """A well-formed snapshot written by the agent to match the loosened config changes nothing (I4)."""
    text = (
        'default_lane = "corp"\n[endpoints.corp]\nurl = "https://llm.corp.example.invalid"\n'
        'formats = ["anthropic"]\ntrust = "approved"\n'
    )
    _write_user(text)
    import tomllib

    save_snapshot(snapshot_path(), parse_layer(tomllib.loads(text), "user"))  # forged
    ch = FakeChannel("j", False)
    with pytest.raises(LaunchError, match="not approved"):
        prepare_policy(False, ch)
    assert len(ch.auth_requests) == 1 and "corp" in ch.auth_requests[0]
    with pytest.raises(LaunchError, match="interactive approval"):
        prepare_policy(True, FakeChannel("j", True))


def test_new_endpoint_reusing_lane_key_is_loosening():
    _write_user(
        '[endpoints.mirror]\nurl = "https://mirror.example.invalid"\nformats = ["anthropic"]\n'
        'credential = "env:ANTHROPIC_API_KEY"\n'
    )
    with pytest.raises(LaunchError, match="mirror.*env:ANTHROPIC_API_KEY"):
        prepare_policy(True, FakeChannel("j", True))
    ch = FakeChannel("j", True)
    prepare_policy(False, ch)
    assert ch.auth_requests and "env:ANTHROPIC_API_KEY" in ch.auth_requests[0]


def test_default_lane_to_user_endpoint_is_loosening():
    _write_user(
        'default_lane = "mine"\n[endpoints.mine]\nurl = "https://mine.example.invalid"\n'
        'formats = ["anthropic"]\n'
    )
    with pytest.raises(LaunchError, match="user-defined endpoint mine"):
        prepare_policy(True, FakeChannel("j", True))


def test_tightening_only_config_needs_no_auth():
    _write_user('[identifiers]\ndomains = ["a.example.invalid"]\n')
    ch = FakeChannel("j", False)
    assert prepare_policy(True, ch).profile == "cui"
    assert prepare_policy(False, ch).profile == "cui"
    assert ch.auth_requests == []


def test_min_version_too_new(isolated_dirs, monkeypatch):
    org = isolated_dirs / "org.toml"
    org.write_text('min_version = "99.0.0"\n')
    monkeypatch.setattr("cui_guard.policy.loader.org_policy_path", lambda: org)
    with pytest.raises(LaunchError, match="older"):
        prepare_policy(True, FakeChannel("j", True))


def test_lane_choice_rules():
    policy, _ = sess.load_effective_policy()
    assert sess.choose_lane(policy, "claude", None).name == "anthropic"
    assert sess.choose_lane(policy, "codex", None).name == "openai"
    assert sess.choose_lane(policy, "claude", "ollama").name == "ollama"
    with pytest.raises(LaunchError):
        sess.choose_lane(policy, "codex", "anthropic")
    with pytest.raises(LaunchError):
        sess.choose_lane(policy, "claude", "nope")


def test_start_gateway_ready_and_two_sessions_isolated():
    env = {"PATH": os.environ.get("PATH", "")}
    ch = FakeChannel("j", True)
    with (
        start_gateway("claude", None, True, env, channel=ch) as a,
        start_gateway("claude", None, True, env, channel=ch) as b,
    ):
        assert a.port != b.port and a.token != b.token
        assert a.credential_mode == "passthrough"
        for s, other in ((a, b), (b, a)):
            r = httpx.post(
                f"http://127.0.0.1:{s.port}/v1/messages",
                json={"model": "m", "max_tokens": 1, "messages": []},
                headers={"x-cui-guard-token": other.token},
            )
            assert r.status_code == 401
        files = sorted((state_dir() / "sessions").glob("*.json"))
        assert len(files) == 2
        data = json.loads((state_dir() / "sessions" / f"{a.session_id}.json").read_text())
        assert data["pid"] == a.proc.pid and data["port"] == a.port
        assert data["agent"] == "claude" and data["lane"] == "anthropic"
        assert data["trust"] == "public" and "started" in data
        assert a.token not in json.dumps(data)
        mode = stat.S_IMODE((state_dir() / "sessions" / f"{a.session_id}.json").stat().st_mode)
        assert mode == 0o600
        procs = (a.proc, b.proc)
    assert all(p.poll() is not None for p in procs)
    assert list((state_dir() / "sessions").glob("*.json")) == []


def test_session_file_removed_on_exception():
    env = {"PATH": os.environ.get("PATH", "")}
    with (
        pytest.raises(RuntimeError),
        start_gateway("claude", None, True, env, channel=FakeChannel("j", True)) as s,
    ):
        proc = s.proc
        raise RuntimeError("boom")
    assert proc.poll() is not None
    assert list((state_dir() / "sessions").glob("*.json")) == []


def test_banner_mentions_passthrough_tradeoff():
    env = {"PATH": os.environ.get("PATH", "")}
    with start_gateway("claude", None, True, env, channel=FakeChannel("j", True)) as s:
        text = banner(s, s.policy)
    assert "anthropic" in text and "public" in text and "passthrough" in text
    assert "Trade-off" in text and "Consumer-plan" in text
    assert "compliant" not in text.lower()


def test_gateway_exits_when_launcher_stdin_closes():
    env = {"PATH": os.environ.get("PATH", "")}
    s = start_gateway("claude", None, True, env, channel=FakeChannel("j", True))
    try:
        assert s.proc.poll() is None
        s.proc.stdin.close()  # simulates the launcher dying
        assert s.proc.wait(timeout=5) == 0
    finally:
        s.close()


def test_signal_handlers_raise_systemexit_and_restore():
    import signal

    before = signal.getsignal(signal.SIGTERM)
    with sess.exit_on_signals():
        handler = signal.getsignal(signal.SIGTERM)
        assert handler is not before
        assert signal.getsignal(signal.SIGHUP) is handler
        with pytest.raises(SystemExit) as e:
            handler(signal.SIGTERM, None)
        assert e.value.code == 128 + signal.SIGTERM
        cleaned = []
        with pytest.raises(SystemExit):
            try:
                os.kill(os.getpid(), signal.SIGHUP)
                signal.pthread_kill(__import__("threading").get_ident(), 0)
                import time

                time.sleep(0.5)
            finally:
                cleaned.append(1)
        assert cleaned
    assert signal.getsignal(signal.SIGTERM) is before


def test_add_no_proxy_appends():
    env = {"no_proxy": "a.example.invalid,localhost"}
    sess.add_no_proxy(env)
    assert env["no_proxy"] == "a.example.invalid,localhost,127.0.0.1,::1"
    assert env["NO_PROXY"] == "127.0.0.1,localhost,::1"
