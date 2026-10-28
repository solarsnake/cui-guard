"""Snapshot of the last human-approved user policy, and loosening detection."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.model import Action, Trust
from cui_guard.policy.loader import load_builtin_layer, state_dir
from cui_guard.policy.schema import (
    DEFAULT_AUDIT_PATH,
    EGRESS_MODES,
    FIPS_MODES,
    AuditConfig,
    Endpoint,
    PolicyError,
    PolicyLayer,
    _action_name,
    _rule_from_dict,
    _rule_to_dict,
)

_TRUST_RANK = {Trust.PUBLIC: 0, Trust.APPROVED: 1, Trust.LOCAL: 2}
_CREDENTIAL_PREFIXES = ("env:", "keychain:", "env-or-passthrough:")
_ID_FIELDS = (
    ("domains", "domain"),
    ("ip_ranges", "IP range"),
    ("codenames", "codename"),
    ("jira_projects", "Jira project"),
    ("people", "person"),
)


def _rule_sig(r) -> tuple:
    return (r.pattern.pattern, r.pattern.flags, r.cls, r.kind)


def _sends_credential(credential: str) -> bool:
    """True when the gateway or agent would hand a real credential to this endpoint."""
    return credential == "passthrough" or credential.startswith(_CREDENTIAL_PREFIXES)


def snapshot_path() -> Path:
    return state_dir() / "approved-user-policy.json"


def _lane_rank(layer: PolicyLayer, builtin: dict[str, Endpoint]) -> int:
    """Trust rank of the layer's default lane. Unset or unresolvable is public."""
    lane = layer.default_lane
    if lane is None:
        return 0
    ep = (layer.endpoints or {}).get(lane) or builtin.get(lane)
    return _TRUST_RANK[ep.trust] if ep else 0


def loosenings(previous: PolicyLayer | None, current: PolicyLayer | None) -> list[str]:
    """Human-readable reasons `current` is looser than `previous`.

    With `previous=None` the baseline is "no user config": this is what decides
    whether a launch needs OS authentication. Against the snapshot it only
    describes what changed since the last approval.
    """
    prev = previous or PolicyLayer(source="user")
    cur = current or PolicyLayer(source="user")
    reasons: list[str] = []

    pi = prev.identifiers or IdentifierConfig()
    ci = cur.identifiers or IdentifierConfig()
    for attr, label in _ID_FIELDS:
        for value in sorted(set(getattr(pi, attr)) - set(getattr(ci, attr))):
            reasons.append(f"{label} removed: {value}")

    cur_rules = {r.id: r for r in cur.patterns or []}
    for rule in prev.patterns or []:
        new_rule = cur_rules.get(rule.id)
        if new_rule is None:
            reasons.append(f"pattern removed: {rule.id}")
        elif _rule_sig(new_rule) != _rule_sig(rule):
            reasons.append(f"pattern changed: {rule.id}")

    cur_actions = cur.rule_actions or {}
    for (key, trust), old in sorted((prev.rule_actions or {}).items()):
        new = cur_actions.get((key, trust))
        if new is None:
            reasons.append(f"action for {key}/{trust.value} removed (was {old.name})")
        elif new < old:
            reasons.append(
                f"action for {key}/{trust.value} lowered: {old.name} -> {new.name}"
            )

    if (prev.profile or "cui") == "cui" and cur.profile == "general":
        reasons.append("profile changed from cui to general")

    prev_eps = prev.endpoints or {}
    for name, ep in sorted((cur.endpoints or {}).items()):
        old_ep = prev_eps.get(name)
        if ep.trust not in (Trust.APPROVED, Trust.LOCAL):
            continue
        if old_ep is None:
            reasons.append(f"endpoint {name} added with trust {ep.trust.value}")
        elif old_ep.trust != ep.trust:
            reasons.append(
                f"endpoint {name} trust raised: "
                f"{old_ep.trust.value} -> {ep.trust.value}"
            )
        elif old_ep != ep:
            reasons.append(f"endpoint {name} changed (trust {ep.trust.value})")

    # A different trust store decides which servers the endpoint will accept (design 8.2).
    for name, ep in sorted((cur.endpoints or {}).items()):
        old_ep = prev_eps.get(name)
        if ep.ca_file != (old_ep.ca_file if old_ep is not None else None):
            reasons.append(f"endpoint {name} trust store changed (ca_file)")

    for name, ep in sorted((cur.endpoints or {}).items()):
        if _sends_credential(ep.credential) and prev_eps.get(name) != ep:
            reasons.append(
                f"endpoint {name} ({ep.url}) is given credential {ep.credential}"
            )

    cur_eps = cur.endpoints or {}
    lane = cur.default_lane
    if lane is not None and lane in cur_eps and (
        prev.default_lane != lane or prev_eps.get(lane) != cur_eps[lane]
    ):
        reasons.append(f"default lane set to user-defined endpoint {lane}")

    builtin = load_builtin_layer().endpoints or {}
    if cur.default_lane is not None and _lane_rank(cur, builtin) > _lane_rank(
        prev, builtin
    ):
        reasons.append(
            f"default lane moved to higher-trust endpoint {cur.default_lane}"
        )

    # Unset means the built-in default (enabled), so only an explicit "false" can be loosened.
    if prev.overrides_enabled is False and cur.overrides_enabled is not False:
        reasons.append("overrides enabled")

    for rule_id in sorted(
        (prev.override_disabled_rules or frozenset())
        - (cur.override_disabled_rules or frozenset())
    ):
        reasons.append(f"override-disabled rule removed: {rule_id}")

    # Unset means the built-in default (withhold), so only an explicit "allow" loosens.
    if prev.egress_rehydration != "allow" and cur.egress_rehydration == "allow":
        reasons.append("egress_rehydration set to allow")

    # A user "require" is a tightening; dropping an approved one is not.
    if prev.fips == "require" and cur.fips != "require":
        reasons.append("fips requirement removed")

    prev_path = prev.audit.path if prev.audit else DEFAULT_AUDIT_PATH
    if cur.audit is not None and cur.audit.path != prev_path:
        reasons.append(f"audit log path changed: {prev_path} -> {cur.audit.path}")

    return reasons


def _to_dict(layer: PolicyLayer) -> dict:
    d: dict = {"source": layer.source}
    if layer.profile is not None:
        d["profile"] = layer.profile
    if layer.default_lane is not None:
        d["default_lane"] = layer.default_lane
    if layer.endpoints is not None:
        d["endpoints"] = {
            n: {
                "url": e.url,
                "formats": list(e.formats),
                "trust": e.trust.value,
                "credential": e.credential,
                "ca_file": e.ca_file,
            }
            for n, e in layer.endpoints.items()
        }
    if layer.identifiers is not None:
        d["identifiers"] = {
            a: list(getattr(layer.identifiers, a)) for a, _ in _ID_FIELDS
        }
    if layer.patterns is not None:
        d["patterns"] = [_rule_to_dict(r) for r in layer.patterns]
    if layer.rule_actions is not None:
        d["actions"] = [
            [k, t.value, _action_name(a)] for (k, t), a in layer.rule_actions.items()
        ]
    if layer.overrides_enabled is not None:
        d["overrides_enabled"] = layer.overrides_enabled
    if layer.override_disabled_rules is not None:
        d["override_disabled_rules"] = sorted(layer.override_disabled_rules)
    if layer.audit is not None:
        d["audit"] = {
            "path": layer.audit.path,
            "sink": layer.audit.sink,
            "on_sink_failure": layer.audit.on_sink_failure,
        }
    if layer.egress_rehydration is not None:
        d["egress_rehydration"] = layer.egress_rehydration
    if layer.fips is not None:
        d["fips"] = layer.fips
    return d


def _opt(d: dict, key: str, typ: type):
    v = d.get(key)
    if v is not None and not isinstance(v, typ):
        raise PolicyError(f"snapshot: bad {key}")
    return v


def _strs(v) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise PolicyError("snapshot: expected list of strings")
    return v


def _check_rule(r: dict) -> dict:
    ok = (
        all(isinstance(r.get(k), str) for k in ("id", "class", "regex", "source"))
        and (r.get("kind") is None or isinstance(r["kind"], str))
        and isinstance(r.get("verified"), bool)
        and ("flags" not in r or isinstance(r["flags"], list))
    )
    if not ok:
        raise PolicyError("snapshot: bad pattern entry")
    _strs(r.get("flags", []))
    return r


def _from_dict(d: dict) -> PolicyLayer:
    if not isinstance(d, dict) or d.get("source") != "user":
        raise PolicyError("snapshot is not a user layer")
    layer = PolicyLayer(source="user")
    layer.profile = _opt(d, "profile", str)
    layer.default_lane = _opt(d, "default_lane", str)
    if "endpoints" in d:
        if not isinstance(d["endpoints"], dict):
            raise PolicyError("snapshot: bad endpoints")
        eps = {}
        for n, e in d["endpoints"].items():
            if not (
                isinstance(e, dict)
                and isinstance(e["url"], str)
                and isinstance(e["credential"], str)
                and isinstance(e["trust"], str)
                and isinstance(e.get("ca_file"), str | None)
            ):
                raise PolicyError("snapshot: bad endpoint")
            eps[n] = Endpoint(
                n,
                e["url"],
                tuple(_strs(e["formats"])),
                Trust(e["trust"]),
                e["credential"],
                e.get("ca_file"),
            )
        layer.endpoints = eps
    if "identifiers" in d:
        ids = d["identifiers"]
        if not isinstance(ids, dict) or set(ids) - {a for a, _ in _ID_FIELDS}:
            raise PolicyError("snapshot: bad identifiers")
        layer.identifiers = IdentifierConfig(
            **{k: tuple(_strs(v)) for k, v in ids.items()}
        )
    if "patterns" in d:
        pats = d["patterns"]
        if not isinstance(pats, list) or not all(isinstance(r, dict) for r in pats):
            raise PolicyError("snapshot: bad patterns")
        layer.patterns = [_rule_from_dict(_check_rule(r)) for r in pats]
    if "actions" in d:
        acts = d["actions"]
        if not isinstance(acts, list) or not all(
            isinstance(r, list) and len(r) == 3 and all(isinstance(x, str) for x in r)
            for r in acts
        ):
            raise PolicyError("snapshot: bad actions")
        layer.rule_actions = {(k, Trust(t)): Action.parse(a) for k, t, a in acts}
    layer.overrides_enabled = _opt(d, "overrides_enabled", bool)
    if "override_disabled_rules" in d:
        layer.override_disabled_rules = frozenset(_strs(d["override_disabled_rules"]))
    if "audit" in d:
        a = d["audit"]
        if not (
            isinstance(a, dict)
            and isinstance(a["path"], str)
            and isinstance(a["sink"], str | None)
            and a["on_sink_failure"] in ("buffer", "block")
        ):
            raise PolicyError("snapshot: bad audit")
        layer.audit = AuditConfig(a["path"], a["sink"], a["on_sink_failure"])
    if d.get("egress_rehydration") not in (None, *EGRESS_MODES):
        raise PolicyError("snapshot: bad egress_rehydration")
    layer.egress_rehydration = d.get("egress_rehydration")
    if d.get("fips") not in (None, *FIPS_MODES):
        raise PolicyError("snapshot: bad fips")
    layer.fips = d.get("fips")
    return layer


def load_snapshot(path: Path) -> PolicyLayer | None:
    """The approved layer, or None if missing, unparseable or tampered."""
    try:
        return _from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, PolicyError):
        return None


def ensure_private_dir(path: Path) -> None:
    """Create `path` (and missing parents) as 0700. Directories that already existed are
    tightened only if they are cui-guard's own (named `cui-guard`, or directly inside one)."""
    path = Path(path)
    missing = []
    d = path
    while not d.exists() and d != d.parent:
        missing.append(d)
        d = d.parent
    ours = list(missing)
    for cand in (path, path.parent):
        if cand.exists() and cand not in ours and (
            cand.name == "cui-guard" or cand.parent.name == "cui-guard"
        ):
            ours.append(cand)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for d in ours:
        if d.is_dir() and not d.is_symlink():
            d.chmod(0o700)  # mkdir's mode is masked by the umask, and ignored for parents


def save_snapshot(path: Path, layer: PolicyLayer | None) -> None:
    path = Path(path)
    ensure_private_dir(path.parent)
    data = _to_dict(layer or PolicyLayer(source="user"))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".snapshot-", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, 0o600)
            f = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        with f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
