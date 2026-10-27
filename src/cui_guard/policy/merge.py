"""Strictest-wins merge of builtin, user and organization layers (spec 4)."""

from __future__ import annotations

from urllib.parse import urlparse

from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.detect.rules import Rule, load_builtin_rules
from cui_guard.model import Action, DetClass, Trust
from cui_guard.policy.schema import (
    ALWAYS_HARD,
    DEFAULT_AUDIT_PATH,
    AuditConfig,
    EffectivePolicy,
    Endpoint,
    PolicyError,
    PolicyLayer,
)

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
_STRICTNESS = {Trust.LOCAL: 0, Trust.APPROVED: 1, Trust.PUBLIC: 2}


def _union(*groups: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(v for g in groups for v in g))


def _downgrade(ep: Endpoint) -> Endpoint:
    """A `local` endpoint must really be loopback, otherwise it is `public`."""
    host = urlparse(ep.url).hostname
    if ep.trust is Trust.LOCAL and host not in _LOOPBACK:
        return Endpoint(ep.name, ep.url, ep.formats, Trust.PUBLIC, ep.credential)
    return ep


def _merge_endpoints(
    layers: list[PolicyLayer], org: PolicyLayer | None
) -> tuple[dict, dict]:
    if org is not None and org.lock_endpoints:
        layers = [org]
    out: dict[str, Endpoint] = {}
    prov: dict[str, str] = {}
    fixed = {
        n: e
        for src in (layers[0], org)
        if src is not None
        for n, e in (src.endpoints or {}).items()
    }
    for layer in layers:
        for name, raw in (layer.endpoints or {}).items():
            old_fixed = fixed.get(name)
            if (
                layer.source == "user"
                and old_fixed is not None
                and (raw.url, raw.credential) != (old_fixed.url, old_fixed.credential)
            ):
                raise PolicyError(
                    f"endpoints.{name}: user layer may not change url or credential"
                )
            ep = _downgrade(raw)
            old = out.get(name)
            if old is not None and _STRICTNESS[ep.trust] < _STRICTNESS[old.trust]:
                raise PolicyError(
                    f"endpoints.{name}: {layer.source} layer would loosen trust of an existing endpoint"
                )
            out[name] = ep
            prov[f"endpoints.{name}"] = layer.source
    return out, prov


def _check_action_keys(layers: list[PolicyLayer]) -> None:
    known = {c.value for c in DetClass} | {r.id for r in load_builtin_rules()}
    for layer in layers:
        known |= {r.id for r in layer.patterns or []}
    for layer in layers:
        for key, _ in layer.rule_actions or {}:
            if key not in known:
                raise PolicyError(f"actions: unknown class or rule id {key!r}")


def merge_layers(
    builtin: PolicyLayer, user: PolicyLayer | None, org: PolicyLayer | None
) -> EffectivePolicy:
    from cui_guard.policy.loader import state_dir

    if org is not None and org.user_config == "ignore":
        user = None
    layers = [x for x in (builtin, user, org) if x is not None]
    prov: dict[str, str] = {}

    # Profile.
    profile = None
    for layer in layers:
        if layer.profile is not None:
            profile, prov["profile"] = layer.profile, layer.source
    if org is not None and org.lock_profile is not None:
        profile, prov["profile"] = org.lock_profile, "org"
    if profile is None or builtin.profiles is None or profile not in builtin.profiles:
        raise PolicyError(f"unknown or unset profile {profile!r}")

    # Actions: strictest across layers.
    actions: dict[tuple[str, Trust], Action] = dict(builtin.profiles[profile])
    for key in actions:
        prov[f"actions.{key[0]}.{key[1].value}"] = "builtin"
    for layer in layers:
        for key, act in (layer.rule_actions or {}).items():
            if key not in actions or act > actions[key]:
                actions[key] = act
                prov[f"actions.{key[0]}.{key[1].value}"] = layer.source
    for cls in ALWAYS_HARD:
        for trust in Trust:
            actions[(cls.value, trust)] = Action.BLOCK_HARD
            prov[f"actions.{cls.value}.{trust.value}"] = "invariant"

    _check_action_keys(layers)
    endpoints, ep_prov = _merge_endpoints(layers, org)
    prov.update(ep_prov)

    # Unions.
    fields = ("domains", "ip_ranges", "codenames", "jira_projects", "people")
    ids = [layer.identifiers for layer in layers if layer.identifiers is not None]
    identifiers = IdentifierConfig(
        **{f: _union(*(getattr(i, f) for i in ids)) for f in fields}
    )
    for layer in layers:
        if layer.identifiers is not None:
            for f in fields:
                for v in getattr(layer.identifiers, f):
                    prov.setdefault(f"identifiers.{f}.{v}", layer.source)
    extra_rules: list[Rule] = []
    for layer in layers:
        for rule in layer.patterns or []:
            extra_rules.append(rule)
            prov[f"patterns.{rule.id}"] = layer.source

    # Overrides: AND, with disabled rules unioned.
    overrides_enabled, prov["overrides_enabled"] = True, "builtin"
    for layer in layers:
        if layer.overrides_enabled is False:
            overrides_enabled, prov["overrides_enabled"] = False, layer.source
    disabled = frozenset().union(
        *(x.override_disabled_rules or frozenset() for x in layers)
    )

    # Egress rehydration: strictest wins, so any layer's "withhold" beats "allow".
    egress, prov["egress_rehydration"] = "withhold", "builtin"
    modes = [(x.egress_rehydration, x.source) for x in layers if x.egress_rehydration is not None]
    if modes and all(m == "allow" for m, _ in modes):
        egress, prov["egress_rehydration"] = "allow", modes[-1][1]
    for m, src in modes:
        if m == "withhold":
            prov["egress_rehydration"] = src

    # Highest layer that sets a scalar wins.
    default_lane = messages_file = poc = None
    audit = AuditConfig(path=DEFAULT_AUDIT_PATH)
    for layer in layers:
        if layer.default_lane is not None:
            default_lane, prov["default_lane"] = layer.default_lane, layer.source
        if layer.audit is not None:
            audit, prov["audit"] = layer.audit, layer.source
        if layer.messages_file is not None:
            messages_file, prov["messages_file"] = layer.messages_file, layer.source
        if layer.poc is not None:
            poc, prov["poc"] = layer.poc, layer.source
    if default_lane is not None and default_lane not in endpoints:
        if prov["default_lane"] == "builtin":
            default_lane = None
            del prov["default_lane"]
        else:
            raise PolicyError(
                f"default_lane {default_lane!r} (set by {prov['default_lane']}) "
                "is not among the merged endpoints"
            )
    audit = AuditConfig(
        path=audit.path.replace("{state_dir}", str(state_dir())),
        sink=audit.sink,
        on_sink_failure=audit.on_sink_failure,
    )

    return EffectivePolicy(
        profile=profile,
        endpoints=endpoints,
        default_lane=default_lane,
        identifiers=identifiers,
        extra_rules=extra_rules,
        overrides_enabled=overrides_enabled,
        override_disabled_rules=disabled,
        audit=audit,
        messages_file=messages_file,
        poc=poc,
        min_version=org.min_version if org is not None else None,
        provenance=prov,
        actions=actions,
        egress_rehydration=egress,
    )
