from pathlib import Path

import pytest

from cui_guard.model import Action, Trust
from cui_guard.policy import loader
from cui_guard.policy.loader import load_builtin_layer
from cui_guard.policy.schema import PolicyError, parse_layer


def test_unknown_key_rejected():
    with pytest.raises(PolicyError):
        parse_layer({"bogus": 1}, "user")


def test_org_only_key_in_user_rejected():
    with pytest.raises(PolicyError):
        parse_layer({"lock_endpoints": True}, "user")
    with pytest.raises(PolicyError):
        parse_layer({"poc": "sec@example.invalid"}, "user")


def test_bad_enums_rejected():
    with pytest.raises(PolicyError):
        parse_layer({"actions": {"secret": {"public": "nope"}}}, "user")
    with pytest.raises(PolicyError):
        parse_layer({"actions": {"secret": {"elsewhere": "block"}}}, "user")
    bad = {"url": "http://x.invalid", "formats": ["grpc"], "trust": "public"}
    with pytest.raises(PolicyError):
        parse_layer({"endpoints": {"x": bad}}, "user")


def test_bad_pattern_wrapped():
    with pytest.raises(PolicyError, match=r"patterns\[0\]"):
        parse_layer(
            {"patterns": [{"id": "p", "class": "secret", "regex": "("}]}, "user"
        )


def test_builtin_parses():
    layer = load_builtin_layer()
    assert layer.profile == "cui"
    assert set(layer.endpoints) == {"anthropic", "openai", "ollama"}
    assert layer.endpoints["ollama"].trust is Trust.LOCAL
    assert layer.endpoints["ollama"].formats == (
        "anthropic",
        "openai-responses",
        "openai-chat",
    )
    assert set(layer.profiles) == {"cui", "general"}
    assert layer.profiles["cui"][("cui-marking", Trust.PUBLIC)] is Action.BLOCK


def test_paths(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    assert loader.user_config_path() == tmp_path / "c" / "cui-guard" / "config.toml"
    assert loader.state_dir() == tmp_path / "s" / "cui-guard"
    monkeypatch.setattr("sys.platform", "darwin")
    assert str(loader.org_policy_path()).startswith("/Library/Application Support/")
    monkeypatch.setattr("sys.platform", "linux")
    assert loader.org_policy_path() == Path("/etc/cui-guard/policy.toml")


def _ep_layer(cred):
    ep = {"url": "https://x.example.invalid", "formats": ["anthropic"], "credential": cred}
    return {"endpoints": {"x": ep}}


def test_bare_passthrough_credential_rejected():
    """Only env-or-passthrough:VAR is valid; bare "passthrough" is refused at parse time (M8)."""
    with pytest.raises(PolicyError, match="passthrough"):
        parse_layer(_ep_layer("passthrough"), "user")
    for ok in ("none", "env:K", "env-or-passthrough:K", "keychain:svc/acct"):
        parse_layer(_ep_layer(ok), "user")


def _pat(**over):
    return {"patterns": [{"id": "u.p", "class": "identifier", "regex": "ZZ-[0-9]+", **over}]}


def test_pattern_kind_validated():
    """Pattern kind must be a placeholder kind, and only identifier/secret may set one (M9)."""
    for kind in ("host", "ip", "email", "jira", "person", "secret", "term"):
        assert parse_layer(_pat(kind=kind), "org").patterns[0].kind == kind
    assert parse_layer(_pat(**{"class": "secret", "kind": "secret"}), "user").patterns[0].kind == "secret"
    assert parse_layer(_pat(**{"class": "cui-marking"}), "user").patterns[0].kind is None
    for bad in ("tok", "HOST", "", 5, ["host"]):
        with pytest.raises(PolicyError, match="kind"):
            parse_layer(_pat(kind=bad), "user")
    for cls in ("cui-marking", "controlled-content", "classified-marking"):
        with pytest.raises(PolicyError, match="kind"):
            parse_layer(_pat(**{"class": cls, "kind": "term"}), "org")
