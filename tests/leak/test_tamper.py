"""The agent cannot weaken the guard: config tampering, tokens, binding, override surface."""

import socket

import pytest
from canaries import CANARIES, PATHS, build, carrier
from harness import Dirs, launch_gateway, write_user_config

from cui_guard.launch.session import LaunchError, prepare_policy
from cui_guard.override.human import FakeChannel
from cui_guard.policy import loader
from cui_guard.policy.snapshot import load_snapshot, snapshot_path


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    dirs = Dirs(tmp_path)
    monkeypatch.setenv("HOME", str(dirs.home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(dirs.config))
    monkeypatch.setenv("XDG_STATE_HOME", str(dirs.state))
    monkeypatch.setattr(loader, "org_policy_path", lambda: tmp_path / "no-org-policy.toml")
    return dirs


def test_user_config_loosened_by_agent_requires_auth(isolated):
    write_user_config(isolated.config, "https://llm.example.invalid", "public")
    prepare_policy(False, FakeChannel(None, auth_ok=True))  # human approves the first launch
    approved = load_snapshot(snapshot_path())
    assert approved is not None

    # the agent edits the user config between launches: lane moves to approved trust
    write_user_config(isolated.config, "https://llm.example.invalid", "approved")
    channel = FakeChannel(None, auth_ok=False)
    with pytest.raises(LaunchError, match="not approved"):
        prepare_policy(False, channel)
    assert len(channel.auth_requests) == 1
    assert load_snapshot(snapshot_path()) == approved  # a refusal leaves the snapshot alone

    with pytest.raises(LaunchError, match="interactive approval"):
        prepare_policy(True, FakeChannel(None, auth_ok=True))  # headless never self-approves

    # every later launch asks again; the prompt names what changed since the last approval
    write_user_config(isolated.config, "https://llm.example.invalid", "public")
    prepare_policy(False, FakeChannel(None, auth_ok=True))
    cfg = isolated.config / "cui-guard" / "config.toml"
    cfg.write_text(cfg.read_text().replace(CANARIES["codename"], "OTHERNAME"))
    channel = FakeChannel(None, auth_ok=False)
    with pytest.raises(LaunchError, match="not approved"):
        prepare_policy(False, channel)
    assert f"codename removed: {CANARIES['codename']}" in channel.auth_requests[0]


def test_snapshot_never_authorizes(isolated):
    """Approved, deleted, corrupted or forged: the snapshot never stands in for OS auth (I3/I4)."""
    write_user_config(isolated.config, "http://127.0.0.1:9", "local")
    prepare_policy(False, FakeChannel(None, auth_ok=True))
    with pytest.raises(LaunchError, match="not approved"):
        prepare_policy(False, FakeChannel(None, auth_ok=False))  # unchanged still asks
    for tamper in (lambda: snapshot_path().unlink(), lambda: snapshot_path().write_text("{ not json")):
        prepare_policy(False, FakeChannel(None, auth_ok=True))
        tamper()
        channel = FakeChannel(None, auth_ok=False)
        with pytest.raises(LaunchError, match="not approved"):
            prepare_policy(False, channel)
        assert channel.auth_requests
    with pytest.raises(LaunchError, match="interactive approval"):
        prepare_policy(True, FakeChannel(None, auth_ok=True))


@pytest.mark.parametrize("fmt", list(PATHS))
def test_wrong_token_rejected(gateways, upstream, fmt):
    gw = gateways("public")
    body = build(fmt, "user", "hello there", False)
    cases = [
        gw.post(PATHS[fmt], body, token=None),
        gw.post(PATHS[fmt], body, token="not-the-token"),
        gw.post(PATHS[fmt], body, token=gw.token[:-1]),
        gw.post(PATHS[fmt], body, token=None, headers={"authorization": "Bearer wrong"}),
        gw.client.post(f"{gw.base}{PATHS[fmt]}?x-cui-guard-token={gw.token}", json=body),
    ]
    assert [r.status_code for r in cases] == [401] * len(cases)
    assert upstream.records == []
    # the right token works
    assert gw.post(PATHS[fmt], body).status_code == 200
    assert len(upstream.records) == 1


def test_passthrough_gateway_ignores_bearer_as_session_token(upstream, tmp_path):
    """In passthrough mode Authorization carries the agent's own login, never the guard token."""
    dirs = Dirs(tmp_path)
    gw = launch_gateway(
        dirs, upstream.url, "public", credential="env-or-passthrough:CUI_GUARD_TEST_UNSET_KEY",
        extra_env={"CUI_GUARD_TEST_UNSET_KEY": ""},
    )
    try:
        assert gw.session.credential_mode == "passthrough"
        body = build("anthropic", "user", "hello there", False)
        resp = gw.post(PATHS["anthropic"], body, token=None,
                       headers={"authorization": f"Bearer {gw.token}"})  # fmt: skip
        assert resp.status_code == 401
        assert upstream.records == []
        assert gw.post(PATHS["anthropic"], body).status_code == 200
    finally:
        gw.close()


def _external_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") or ip == "0.0.0.0" else ip


def test_gateway_binds_loopback_only(gateways):
    gw = gateways("public")
    ip = _external_ip()
    if ip is None:
        pytest.skip("no non-loopback IPv4 address on this machine")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        with pytest.raises(OSError):
            s.connect((ip, gw.session.port))
    with socket.create_connection(("127.0.0.1", gw.session.port), timeout=3):
        pass  # loopback works


OVERRIDE_PATHS = (
    "/override", "/overrides", "/v1/override", "/grant", "/approve", "/admin", "/api/override",
    "/override/CGOV-1", "/v1/messages/override",
)


def test_no_http_override_surface(gateways, upstream):
    gw = gateways("public")
    for path in OVERRIDE_PATHS:
        for method in ("GET", "POST", "PUT", "DELETE"):
            resp = gw.client.request(
                method, gw.base + path, json={"override": True},
                headers={"x-cui-guard-token": gw.token},
            )
            assert resp.status_code in (404, 405), (method, path, resp.status_code)
    assert upstream.records == []

    # override-shaped headers and fields on a blocked request change nothing
    body = build("anthropic", "user", carrier("cui"), False)
    body["cui_guard_override"] = True
    resp = gw.post(
        PATHS["anthropic"], body,
        headers={"x-cui-guard-override": "1", "x-cui-guard-justification": "because I said so"},
    )  # fmt: skip
    assert resp.status_code >= 400
    assert upstream.records == []
