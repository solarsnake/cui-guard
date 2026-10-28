import json

import pytest

from cui_guard.model import Action, DetClass, Hit, Trust
from cui_guard.policy.loader import load_builtin_layer, load_effective_policy
from cui_guard.policy.merge import merge_layers
from cui_guard.policy.schema import EffectivePolicy, PolicyError, parse_layer

A, P, B, H = Action.ALLOW, Action.PSEUDONYMIZE, Action.BLOCK, Action.BLOCK_HARD

# Spec 3.4: class -> (public, approved, local)
TABLE = {
    DetClass.CLASSIFIED_MARKING: (H, H, H),
    DetClass.CUI_MARKING: (B, A, A),
    DetClass.CONTROLLED_CONTENT: (B, A, A),
    DetClass.SECRET: (P, P, P),
    DetClass.IDENTIFIER: (P, A, A),
    DetClass.OPAQUE_CONTENT: (B, A, A),
    DetClass.UNPARSEABLE: (H, H, H),
}


@pytest.fixture(autouse=True)
def _xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def merged(user=None, org=None):
    u = parse_layer(user, "user") if user is not None else None
    o = parse_layer(org, "org") if org is not None else None
    return merge_layers(load_builtin_layer(), u, o)


def test_baseline_matches_spec_table():
    pol = merged()
    for cls, row in TABLE.items():
        for trust, expected in zip(
            (Trust.PUBLIC, Trust.APPROVED, Trust.LOCAL), row, strict=True
        ):
            assert pol.action_for_class(cls, trust) is expected, (cls, trust)
    assert pol.audit.path.endswith("cui-guard/audit.jsonl")
    assert "{state_dir}" not in pol.audit.path


def test_user_cannot_loosen():
    pol = merged(user={"actions": {"cui-marking": {"public": "allow"}}})
    assert pol.action_for_class(DetClass.CUI_MARKING, Trust.PUBLIC) is B


def test_user_can_tighten():
    pol = merged(user={"actions": {"identifier": {"approved": "pseudonymize"}}})
    assert pol.action_for_class(DetClass.IDENTIFIER, Trust.APPROVED) is P
    assert pol.provenance["actions.identifier.approved"] == "user"


def test_classified_invariant():
    pol = merged(org={"actions": {"classified-marking": {"local": "allow"}}})
    assert pol.action_for_class(DetClass.CLASSIFIED_MARKING, Trust.LOCAL) is H
    assert pol.action_for_class(DetClass.UNPARSEABLE, Trust.LOCAL) is H


def test_rule_id_cannot_weaken_classified():
    pol = merged(user={"actions": {"classified-banner": {"public": "allow"}}})
    hit = Hit("classified-banner", DetClass.CLASSIFIED_MARKING, 0, 1, "v")
    assert pol.action_for(hit, Trust.PUBLIC) is H
    # A rule-ID entry may tighten but never loosen a normal class.
    pol = merged(
        user={
            "actions": {
                "secret.assignment": {"public": "allow"},
                "secret.openai-key": {"public": "block"},
            }
        }
    )
    assert (
        pol.action_for(
            Hit("secret.assignment", DetClass.SECRET, 0, 1, "v"), Trust.PUBLIC
        )
        is P
    )
    assert (
        pol.action_for(
            Hit("secret.openai-key", DetClass.SECRET, 0, 1, "v"), Trust.PUBLIC
        )
        is B
    )


def test_general_profile():
    pol = merged(user={"profile": "general"})
    assert pol.action_for_class(DetClass.CONTROLLED_CONTENT, Trust.PUBLIC) is A
    assert pol.action_for_class(DetClass.CUI_MARKING, Trust.PUBLIC) is B
    assert pol.action_for_class(DetClass.SECRET, Trust.PUBLIC) is P


def test_lock_profile():
    pol = merged(user={"profile": "general"}, org={"lock_profile": "cui"})
    assert pol.profile == "cui"
    assert pol.action_for_class(DetClass.CONTROLLED_CONTENT, Trust.PUBLIC) is B


def test_lock_endpoints():
    corp = {
        "url": "https://llm.corp.invalid",
        "formats": ["openai-chat"],
        "trust": "approved",
    }
    mine = {
        "url": "https://mine.invalid",
        "formats": ["openai-chat"],
        "trust": "approved",
    }
    pol = merged(
        user={"endpoints": {"mine": mine}},
        org={"lock_endpoints": True, "endpoints": {"corp": corp}},
    )
    assert set(pol.endpoints) == {"corp"}


def test_fake_local_downgraded():
    ep = {"url": "https://ollama.lan:11434", "formats": ["openai-chat"], "trust": "local"}
    pol = merged(user={"endpoints": {"fake": ep}})
    assert pol.endpoints["fake"].trust is Trust.PUBLIC
    assert pol.endpoints["ollama"].trust is Trust.LOCAL
    ok = {
        "url": "https://ollama.lan:11434",
        "formats": ["openai-chat"],
        "trust": "approved",
    }
    assert (
        merged(user={"endpoints": {"fake": ok}}).endpoints["fake"].trust
        is Trust.APPROVED
    )


def test_user_ignored():
    pat = {"id": "u.pat", "class": "secret", "regex": "zzz+"}
    user = {"patterns": [pat], "identifiers": {"codenames": ["BLUEJAY"]}}
    assert [r.id for r in merged(user=user).extra_rules] == ["u.pat"]
    pol = merged(user=user, org={"user_config": "ignore"})
    assert pol.extra_rules == []
    assert pol.identifiers.codenames == ()


def test_overrides_and():
    pol = merged(
        user={"overrides_enabled": True, "override_disabled_rules": ["a"]},
        org={"overrides_enabled": False, "override_disabled_rules": ["b"]},
    )
    assert pol.overrides_enabled is False
    assert pol.override_disabled_rules == {"a", "b"}


def test_unions():
    pol = merged(
        user={"identifiers": {"domains": ["a.invalid"], "people": ["Pat"]}},
        org={"identifiers": {"domains": ["b.invalid", "a.invalid"]}},
    )
    assert pol.identifiers.domains == ("a.invalid", "b.invalid")
    assert pol.identifiers.people == ("Pat",)


def test_unparseable_org_refuses(tmp_path):
    bad = tmp_path / "policy.toml"
    bad.write_text("this is = = not toml", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_effective_policy(user_path=tmp_path / "none.toml", org_path=bad)


def test_missing_files_use_builtin(tmp_path):
    pol, user = load_effective_policy(tmp_path / "u.toml", tmp_path / "o.toml")
    assert user is None
    assert pol.profile == "cui"


def test_effective_policy_round_trip():
    pat = {"id": "u.pat", "class": "secret", "regex": "zzz+", "kind": "secret"}
    pol = merged(
        user={
            "patterns": [pat],
            "identifiers": {"codenames": ["BLUEJAY"], "jira_projects": ["ABC"]},
            "actions": {"secret.assignment": {"public": "block"}},
        },
        org={
            "poc": "sec@example.invalid",
            "messages_file": "/etc/x.txt",
            "override_disabled_rules": ["secret.assignment"],
            "audit": {
                "path": "/var/a.jsonl",
                "sink": "https://sink.invalid",
                "on_sink_failure": "block",
            },
        },
    )
    again = EffectivePolicy.from_dict(json.loads(json.dumps(pol.to_dict())))
    assert again.to_dict() == pol.to_dict()
    assert again.actions == pol.actions
    assert again.endpoints == pol.endpoints
    assert again.identifiers == pol.identifiers
    assert again.audit == pol.audit
    assert again.override_disabled_rules == pol.override_disabled_rules
    assert again.poc == "sec@example.invalid"
    (rule,) = again.extra_rules
    assert (rule.id, rule.cls, rule.kind, rule.verified, rule.source) == (
        "u.pat", DetClass.SECRET, "secret", True, "user",
    )  # fmt: skip
    assert rule.pattern.search("zzzz")


def _ep(url, trust="public", **kw):
    return {"url": url, "formats": ["anthropic"], "trust": trust, **kw}


def test_min_version_exposed_and_round_trips():
    pol = merged(org={"min_version": "1.2.3"})
    assert pol.min_version == "1.2.3"
    again = EffectivePolicy.from_dict(json.loads(json.dumps(pol.to_dict())))
    assert again.min_version == "1.2.3"
    assert merged().min_version is None


def test_audit_sink_org_only():
    for key, val in (("sink", "https://s.invalid"), ("on_sink_failure", "block")):
        with pytest.raises(PolicyError):
            parse_layer({"audit": {key: val}}, "user")
    assert (
        parse_layer({"audit": {"path": "/x/a.jsonl"}}, "user").audit.path
        == "/x/a.jsonl"
    )


def test_dangling_builtin_default_lane_is_none():
    corp = _ep("https://llm.corp.invalid", "approved")
    pol = merged(org={"lock_endpoints": True, "endpoints": {"corp": corp}})
    assert pol.default_lane is None
    again = EffectivePolicy.from_dict(json.loads(json.dumps(pol.to_dict())))
    assert again.default_lane is None


def test_explicit_dangling_default_lane_rejected():
    with pytest.raises(PolicyError):
        merged(user={"default_lane": "nope"})
    corp = _ep("https://llm.corp.invalid", "approved")
    with pytest.raises(PolicyError):
        merged(
            org={
                "lock_endpoints": True,
                "endpoints": {"corp": corp},
                "default_lane": "x",
            }
        )
    ok = merged(
        org={
            "lock_endpoints": True,
            "endpoints": {"corp": corp},
            "default_lane": "corp",
        }
    )
    assert ok.default_lane == "corp"


def test_dangling_org_symlink_refuses(tmp_path):
    link = tmp_path / "policy.toml"
    link.symlink_to(tmp_path / "missing.toml")
    with pytest.raises(PolicyError):
        load_effective_policy(user_path=tmp_path / "none.toml", org_path=link)


def test_org_ignore_skips_user_file(tmp_path):
    user = tmp_path / "config.toml"
    user.write_text("garbage = = =", encoding="utf-8")
    org = tmp_path / "policy.toml"
    org.write_text('user_config = "ignore"\n', encoding="utf-8")
    pol, user_layer = load_effective_policy(user_path=user, org_path=org)
    assert user_layer is None
    assert pol.profile == "cui"


def test_user_cannot_redirect_endpoint():
    with pytest.raises(PolicyError):
        merged(user={"endpoints": {"anthropic": _ep("https://evil.invalid")}})
    with pytest.raises(PolicyError):
        merged(
            user={
                "endpoints": {
                    "anthropic": _ep(
                        "https://api.anthropic.com", credential="env:OTHER"
                    )
                }
            }
        )
    same = _ep(
        "https://api.anthropic.com", credential="env-or-passthrough:ANTHROPIC_API_KEY"
    )
    assert "anthropic" in merged(user={"endpoints": {"anthropic": same}}).endpoints


def test_unknown_action_key_rejected():
    with pytest.raises(PolicyError, match="cui-markng"):
        merged(user={"actions": {"cui-markng": {"public": "block"}}})
    pat = {"id": "u.pat", "class": "secret", "regex": "zzz+"}
    pol = merged(user={"patterns": [pat], "actions": {"u.pat": {"public": "block"}}})
    assert pol.actions[("u.pat", Trust.PUBLIC)] is B


def test_egress_rehydration_builtin_is_default_and_round_trips():
    assert (merged().egress_rehydration, merged().provenance["egress_rehydration"]) == (
        "withhold", "builtin",
    )  # fmt: skip
    user_allow = merged(user={"egress_rehydration": "allow"})
    assert (user_allow.egress_rehydration, user_allow.provenance["egress_rehydration"]) == (
        "allow", "user",
    )  # fmt: skip
    assert merged(org={"egress_rehydration": "allow"}).egress_rehydration == "allow"
    pol = merged(user={"egress_rehydration": "allow"}, org={"egress_rehydration": "withhold"})
    assert (pol.egress_rehydration, pol.provenance["egress_rehydration"]) == ("withhold", "org")
    again = EffectivePolicy.from_dict(json.loads(json.dumps(pol.to_dict())))
    assert again.egress_rehydration == "withhold"
    with pytest.raises(PolicyError):
        parse_layer({"egress_rehydration": "maybe"}, "user")
    with pytest.raises(PolicyError):
        EffectivePolicy.from_dict({**pol.to_dict(), "egress_rehydration": "off"})


def test_fips_and_ca_file_merge_and_round_trip():
    assert (merged().fips, merged().provenance["fips"]) == ("off", "builtin")
    pol = merged(user={"fips": "off"}, org={"fips": "require"})
    assert (pol.fips, pol.provenance["fips"]) == ("require", "org")
    assert merged(user={"fips": "require"}).provenance["fips"] == "user"
    ca = "/etc/pki/corp-roots.crt"
    pol = merged(
        user={"endpoints": {"anthropic": {
            "url": "https://api.anthropic.com", "formats": ["anthropic"],
            "credential": "env-or-passthrough:ANTHROPIC_API_KEY", "ca_file": ca,
        }}},
        org={"fips": "require"},
    )  # fmt: skip
    assert pol.endpoints["anthropic"].ca_file == ca
    again = EffectivePolicy.from_dict(json.loads(json.dumps(pol.to_dict())))
    assert again.fips == "require" and again.endpoints == pol.endpoints
    with pytest.raises(PolicyError):
        EffectivePolicy.from_dict({**pol.to_dict(), "fips": "maybe"})


def test_downgraded_endpoint_keeps_ca_file():
    pol = merged(user={"endpoints": {"fake": {
        "url": "https://not-local.example.invalid", "formats": ["anthropic"],
        "trust": "local", "ca_file": "/etc/pki/corp-roots.crt",
    }}})  # fmt: skip
    assert pol.endpoints["fake"].trust is Trust.PUBLIC
    assert pol.endpoints["fake"].ca_file == "/etc/pki/corp-roots.crt"
