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
