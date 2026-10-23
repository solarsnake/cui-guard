from cui_guard.model import Action, Trust
from cui_guard.policy.schema import parse_layer
from cui_guard.policy.snapshot import (
    load_snapshot,
    loosenings,
    save_snapshot,
    snapshot_path,
)

APPROVED_EP = {
    "corp": {
        "url": "https://llm.corp.example.invalid",
        "formats": ["anthropic"],
        "trust": "approved",
    }
}


def _layer(**data):
    return parse_layer(data, "user")


def test_no_change_no_loosening():
    a = _layer(identifiers={"domains": ["a.example.invalid"]}, profile="cui")
    b = _layer(identifiers={"domains": ["a.example.invalid"]}, profile="cui")
    assert loosenings(a, b) == []
    assert loosenings(None, None) == []


def test_removed_domain():
    a = _layer(identifiers={"domains": ["a.example.invalid", "b.example.invalid"]})
    b = _layer(identifiers={"domains": ["a.example.invalid"]})
    reasons = loosenings(a, b)
    assert reasons and any("b.example.invalid" in r for r in reasons)
    assert loosenings(a, None)


def test_profile_to_general():
    assert loosenings(_layer(profile="cui"), _layer(profile="general"))


def test_new_approved_endpoint():
    reasons = loosenings(None, _layer(endpoints=APPROVED_EP))
    assert reasons and any("corp" in r for r in reasons)


def test_tightening_not_loosening():
    a = _layer(identifiers={"domains": ["a.example.invalid"]})
    b = _layer(identifiers={"domains": ["a.example.invalid", "c.example.invalid"]})
    assert loosenings(a, b) == []


def test_lower_rule_action_and_overrides_and_audit():
    a = _layer(
        actions={"secret": {"public": "block"}},
        overrides_enabled=False,
        override_disabled_rules=["r1"],
        audit={"path": "/x/audit.jsonl"},
    )
    b = _layer(
        actions={"secret": {"public": "allow"}},
        overrides_enabled=True,
        override_disabled_rules=[],
        audit={"path": "/y/audit.jsonl"},
    )
    assert len(loosenings(a, b)) == 4


def test_default_lane_to_higher_trust():
    a = _layer(default_lane="anthropic")
    b = _layer(default_lane="corp", endpoints=APPROVED_EP)
    reasons = loosenings(a, b)
    assert any("corp" in r for r in reasons)
    assert loosenings(b, a) == []


def test_tampered_snapshot_is_none(tmp_path):
    p = tmp_path / "snap.json"
    p.write_text("{not json")
    assert load_snapshot(p) is None
    assert load_snapshot(tmp_path / "missing.json") is None
    p.write_text('{"source": "org"}')
    assert load_snapshot(p) is None
    assert loosenings(load_snapshot(p), _layer(endpoints=APPROVED_EP))


def test_snapshot_path_in_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert snapshot_path() == tmp_path / "cui-guard" / "approved-user-policy.json"


def test_round_trip(tmp_path):
    layer = _layer(
        profile="cui",
        default_lane="corp",
        endpoints=APPROVED_EP,
        identifiers={"domains": ["a.example.invalid"], "people": ["Jane Doe"]},
        patterns=[{"id": "p1", "class": "identifier", "regex": "ZZ-[0-9]+"}],
        actions={"secret": {"public": "block"}},
        overrides_enabled=True,
        override_disabled_rules=["r1"],
        audit={"path": "/x/audit.jsonl"},
    )
    p = tmp_path / "sub" / "snap.json"
    save_snapshot(p, layer)
    assert p.stat().st_mode & 0o777 == 0o600
    back = load_snapshot(p)
    assert back is not None
    assert back.profile == "cui" and back.default_lane == "corp"
    assert back.endpoints == layer.endpoints
    assert back.identifiers == layer.identifiers
    assert [r.id for r in back.patterns] == ["p1"]
    assert back.rule_actions == {("secret", Trust.PUBLIC): Action.BLOCK}
    assert back.overrides_enabled is True
    assert back.override_disabled_rules == frozenset({"r1"})
    assert back.audit == layer.audit
    assert loosenings(layer, back) == []
    save_snapshot(p, None)
    empty = load_snapshot(p)
    assert empty is not None and empty.profile is None


def test_edited_pattern_is_loosening():
    pat = {"id": "p1", "class": "identifier", "regex": "ZZ-[0-9]+"}
    a = _layer(patterns=[pat])
    b = _layer(patterns=[{**pat, "regex": "(?!)"}])
    assert any("p1" in r for r in loosenings(a, b))
    assert loosenings(a, _layer(patterns=[pat])) == []


def test_malformed_snapshots_are_none(tmp_path):
    p = tmp_path / "s.json"
    bad = [
        '{"source": "user", "override_disabled_rules": "abc"}',
        '{"source": "user", "profile": 5}',
        '{"source": "user", "overrides_enabled": "yes"}',
        '{"source": "user", "identifiers": {"domains": "a.b"}}',
        '{"source": "user", "identifiers": []}',
        '{"source": "user", "endpoints": {"x": {"url": 1}}}',
        '{"source": "user", "actions": [["secret", "public"]]}',
        (
            '{"source": "user", "audit": {"path": 3, "sink": null,'
            ' "on_sink_failure": "buffer"}}'
        ),
    ]
    for text in bad:
        p.write_text(text)
        assert load_snapshot(p) is None, text


def test_public_endpoint_not_loosening():
    pub = {"x": {"url": "https://x.example.invalid", "formats": ["anthropic"]}}
    other = {"x": {"url": "https://y.example.invalid", "formats": ["anthropic"]}}
    assert loosenings(None, _layer(endpoints=pub)) == []
    assert loosenings(_layer(endpoints=pub), _layer(endpoints=other)) == []


def test_approved_to_public_not_loosening():
    down = {"corp": {**APPROVED_EP["corp"], "trust": "public"}}
    assert loosenings(_layer(endpoints=APPROVED_EP), _layer(endpoints=down)) == []


def test_atomic_save_leaves_no_temp(tmp_path):
    p = tmp_path / "snap.json"
    save_snapshot(p, _layer(profile="cui"))
    save_snapshot(p, _layer(profile="general"))
    assert p.stat().st_mode & 0o777 == 0o600
    assert load_snapshot(p).profile == "general"
    assert [x.name for x in tmp_path.iterdir()] == ["snap.json"]


def _pat(**over):
    base = {
        "id": "p1",
        "class": "identifier",
        "regex": "ZZ",
        "flags": [],
        "kind": None,
        "verified": True,
        "source": "user",
    }
    base.update(over)
    return base


def test_malformed_pattern_entries_are_none(tmp_path):
    import json

    p = tmp_path / "s.json"
    p.write_text(json.dumps({"source": "user", "patterns": [_pat()]}))
    assert load_snapshot(p) is not None
    bad = [
        _pat(id=1),
        _pat(**{"class": 3}),
        _pat(regex=None),
        _pat(source=None),
        _pat(kind=5),
        _pat(verified="false"),
        _pat(verified=1),
        _pat(flags="IGNORECASE"),
        _pat(flags=[1]),
    ]
    for entry in bad:
        p.write_text(json.dumps({"source": "user", "patterns": [entry]}))
        assert load_snapshot(p) is None, entry


def test_save_closes_fd_when_fdopen_fails(tmp_path, monkeypatch):
    import os

    closed = []
    real_close = os.close
    monkeypatch.setattr(os, "close", lambda fd: (closed.append(fd), real_close(fd)))

    def boom(*a, **k):
        raise OSError("boom")

    monkeypatch.setattr(os, "fdopen", boom)
    try:
        save_snapshot(tmp_path / "s.json", _layer(profile="cui"))
    except OSError:
        pass
    else:
        raise AssertionError("expected OSError")
    assert len(closed) == 1
    assert list(tmp_path.iterdir()) == []
