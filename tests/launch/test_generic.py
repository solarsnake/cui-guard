import subprocess
from types import SimpleNamespace

from cui_guard.launch import generic as gn
from cui_guard.override.human import FakeChannel


def test_run_generic_env(monkeypatch, capsys):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY"):
        monkeypatch.setenv(k, "x")
    real = gn.start_gateway
    monkeypatch.setattr(
        gn,
        "start_gateway",
        lambda agent, lane, headless, env: real(
            agent, lane, headless, {}, channel=FakeChannel("j", True)
        ),
    )
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw["env"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert gn.run_generic(["tool"], None, True) == 0
    env = seen["env"]
    assert "ANTHROPIC_API_KEY" not in env and "CODEX_API_KEY" not in env
    token = env["ANTHROPIC_CUSTOM_HEADERS"].split(": ", 1)[1]
    assert env["OPENAI_API_KEY"] == token
    assert "::1" in env["no_proxy"]
    assert "may remain" in capsys.readouterr().err
