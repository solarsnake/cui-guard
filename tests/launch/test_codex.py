import json

import pytest

from cui_guard.launch import codex as cx
from cui_guard.launch.codex import build_codex_args, detect_chatgpt_session
from cui_guard.launch.session import GatewaySession, LaunchError
from cui_guard.model import Trust
from cui_guard.policy.schema import Endpoint


def fake_session():
    lane = Endpoint("openai", "https://x.example.invalid", ("openai-responses",), Trust.PUBLIC, "none")
    return GatewaySession(4321, "tok", "sid", lane, "gateway", proc=None)  # type: ignore[arg-type]


def test_codex_args_exact():
    assert build_codex_args(fake_session()) == [
        "-c", 'model_provider="cuiguard"',
        "-c", 'model_providers.cuiguard.name="cui-guard"',
        "-c", 'model_providers.cuiguard.base_url="http://127.0.0.1:4321/v1"',
        "-c", 'model_providers.cuiguard.env_key="CUI_GUARD_TOKEN"',
        "-c", 'model_providers.cuiguard.wire_api="responses"',
        "-c", "analytics.enabled=false",
        "-c", "feedback.enabled=false",
        "-c", "check_for_update_on_startup=false",
        "-c", 'otel.exporter="none"',
        "-c", 'otel.trace_exporter="none"',
        "-c", 'otel.metrics_exporter="none"',
    ]  # fmt: skip


def test_detect_chatgpt_session(tmp_path):
    assert not detect_chatgpt_session(tmp_path)
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"OPENAI_API_KEY": "x", "tokens": None}))
    assert not detect_chatgpt_session(tmp_path)
    auth.write_text(json.dumps({"tokens": {"id_token": "a"}}))
    assert detect_chatgpt_session(tmp_path)
    auth.write_text(json.dumps({"auth_mode": "chatgpt"}))
    assert detect_chatgpt_session(tmp_path)


def test_codex_chatgpt_session_refused(tmp_path, monkeypatch):
    (tmp_path / "auth.json").write_text(json.dumps({"tokens": {"id_token": "a"}}))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    started = []
    monkeypatch.setattr(cx, "start_gateway", lambda *a, **k: started.append(1))
    with pytest.raises(LaunchError, match="spec 13"):
        cx.run_codex([], None, True)
    assert not started
