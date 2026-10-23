import tomllib

from cui_guard.cli import main
from cui_guard.orgemit import emit_claude_managed_settings, emit_codex_requirements


def test_emit_claude_managed_keys():
    d = emit_claude_managed_settings("http://127.0.0.1:9999")
    assert d["allowedProviders"] == ["customEndpoint"]
    assert d["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9999"
    assert d["env"]["DISABLE_TELEMETRY"] == "1"
    assert d["skipWebFetchPreflight"] is True
    for k in ("allowManagedHooksOnly", "allowManagedMcpServersOnly", "allowManagedPermissionRulesOnly"):
        assert d[k] is True
    assert d["permissions"]["disableBypassPermissionsMode"] == "disable"
    assert "WebSearch" in d["permissions"]["deny"]
    assert "mcp__claude-in-chrome" in d["permissions"]["deny"]


def test_emit_codex_requirements_parses_as_toml():
    text = emit_codex_requirements()
    data = tomllib.loads(text)
    assert data == {"allow_managed_hooks_only": True, "allowed_login_methods": ["api"]}
    assert "https://learn.chatgpt.com/docs/enterprise/managed-configuration" in text
    assert "no model-provider allowlist" in text


def test_org_emit_cli(capsys):
    assert main(["org", "emit", "codex-requirements"]) == 0
    assert "allow_managed_hooks_only" in capsys.readouterr().out
    assert main(["org", "emit", "claude-managed-settings", "--gateway-url", "http://h:1"]) == 0
    assert "customEndpoint" in capsys.readouterr().out
    assert main(["org", "emit", "claude-managed-settings"]) == 2
