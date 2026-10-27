"""Policy data model: layers, effective policy, parsing and validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.detect.rules import Rule, _compile, rules_from_patterns
from cui_guard.model import Action, DetClass, Hit, Trust

FORMATS = frozenset({"anthropic", "openai-responses", "openai-chat"})
SOURCES = ("builtin", "user", "org")
ALWAYS_HARD = (DetClass.CLASSIFIED_MARKING, DetClass.UNPARSEABLE)
_CRED_PREFIXES = ("env:", "env-or-passthrough:")
_FLAG_NAMES = {"IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE}


class PolicyError(Exception):
    """Invalid policy. Callers must fail closed."""


@dataclass(frozen=True)
class Endpoint:
    name: str
    url: str
    formats: tuple[str, ...]
    trust: Trust
    credential: str


@dataclass(frozen=True)
class AuditConfig:
    path: str
    sink: str | None = None
    on_sink_failure: Literal["buffer", "block"] = "buffer"


@dataclass
class PolicyLayer:
    source: Literal["builtin", "user", "org"]
    profile: str | None = None
    default_lane: str | None = None
    endpoints: dict[str, Endpoint] | None = None
    identifiers: IdentifierConfig | None = None
    patterns: list[Rule] | None = None
    rule_actions: dict[tuple[str, Trust], Action] | None = None
    overrides_enabled: bool | None = None
    override_disabled_rules: frozenset[str] | None = None
    audit: AuditConfig | None = None
    egress_rehydration: Literal["withhold", "allow"] | None = None
    # Org-only keys.
    lock_endpoints: bool | None = None
    lock_profile: str | None = None
    user_config: Literal["use", "ignore"] | None = None
    min_version: str | None = None
    messages_file: str | None = None
    poc: str | None = None
    # Built-in only: named baseline tables.
    profiles: dict[str, dict[tuple[str, Trust], Action]] | None = None


_COMMON_KEYS = {
    "profile", "default_lane", "endpoints", "identifiers", "patterns", "actions",
    "overrides_enabled", "override_disabled_rules", "audit", "egress_rehydration",
}  # fmt: skip
_ORG_KEYS = {
    "lock_endpoints", "lock_profile", "user_config", "min_version", "messages_file", "poc",
}  # fmt: skip
_ENDPOINT_KEYS = {"url", "formats", "trust", "credential"}
_AUDIT_KEYS = {"path", "sink", "on_sink_failure"}
_ID_KEYS = {"domains", "ip_ranges", "codenames", "jira_projects", "people"}
EGRESS_MODES = ("withhold", "allow")
DEFAULT_AUDIT_PATH = "{state_dir}/audit.jsonl"


def _check_keys(where: str, data: dict, allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {unknown}")


def _table(where: str, value: Any) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{where}: expected a table")
    return value


def _str(where: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{where}: expected a non-empty string")
    return value


def _bool(where: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where}: expected true or false")
    return value


def _str_list(where: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError(f"{where}: expected a list of non-empty strings")
    return tuple(value)


def _trust(where: str, value: Any) -> Trust:
    try:
        return Trust(value)
    except ValueError:
        raise PolicyError(f"{where}: unknown trust {value!r}") from None


def _action(where: str, value: Any) -> Action:
    try:
        return Action.parse(value)
    except (ValueError, TypeError):
        raise PolicyError(f"{where}: unknown action {value!r}") from None


def _credential_ok(cred: str) -> bool:
    if cred == "none":
        return True
    for prefix in _CRED_PREFIXES:
        if cred.startswith(prefix):
            return len(cred) > len(prefix)
    if cred.startswith("keychain:"):
        service, sep, account = cred[len("keychain:") :].partition("/")
        return bool(service and sep and account)
    return False


def is_loopback_host(host: str) -> bool:
    if host.lower() in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback and host.count(":") == 0
    except ValueError:
        return False


def _parse_endpoint(name: str, raw: Any) -> Endpoint:
    where = f"endpoints.{name}"
    t = _table(where, raw)
    _check_keys(where, t, _ENDPOINT_KEYS)
    url = _str(f"{where}.url", t.get("url"))
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise PolicyError(f"{where}.url: expected an http(s) URL")
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname):
        raise PolicyError(
            f"{where}.url: http:// is only allowed for loopback hosts; "
            "put TLS in front of remote model servers"
        )
    formats = _str_list(f"{where}.formats", t.get("formats"))
    if not formats or not set(formats) <= FORMATS:
        raise PolicyError(
            f"{where}.formats: must be a non-empty subset of {sorted(FORMATS)}"
        )
    cred = _str(f"{where}.credential", t.get("credential", "none"))
    if cred == "passthrough":
        raise PolicyError(
            f"{where}.credential: bare 'passthrough' is not supported; "
            "use 'env-or-passthrough:VAR'"
        )
    if not _credential_ok(cred):
        raise PolicyError(f"{where}.credential: invalid credential {cred!r}")
    return Endpoint(
        name, url, formats, _trust(f"{where}.trust", t.get("trust", "public")), cred
    )


def _parse_action_table(where: str, raw: Any) -> dict[tuple[str, Trust], Action]:
    out: dict[tuple[str, Trust], Action] = {}
    for key, row in _table(where, raw).items():
        row = _table(f"{where}.{key}", row)
        for trust_name, action_name in row.items():
            trust = _trust(f"{where}.{key}", trust_name)
            out[(key, trust)] = _action(f"{where}.{key}.{trust_name}", action_name)
    return out


def _parse_profiles(raw: Any) -> dict[str, dict[tuple[str, Trust], Action]]:
    profiles: dict[str, dict[tuple[str, Trust], Action]] = {}
    for name, table in _table("profiles", raw).items():
        actions = _parse_action_table(f"profiles.{name}", table)
        for cls in DetClass:
            for trust in Trust:
                if (cls.value, trust) not in actions:
                    raise PolicyError(
                        f"profiles.{name}: missing {cls.value}.{trust.value}"
                    )
        unknown = {k for k, _ in actions} - {c.value for c in DetClass}
        if unknown:
            raise PolicyError(f"profiles.{name}: unknown class(es) {sorted(unknown)}")
        profiles[name] = actions
    return profiles


def parse_layer(data: dict, source: str) -> PolicyLayer:
    """Validate raw TOML data and build a layer. Raises PolicyError."""
    if source not in SOURCES:
        raise PolicyError(f"unknown layer source {source!r}")
    if not isinstance(data, dict):
        raise PolicyError("policy root must be a table")
    allowed = set(_COMMON_KEYS)
    if source == "org":
        allowed |= _ORG_KEYS
    elif source == "builtin":
        allowed |= _ORG_KEYS | {"profiles"}
    else:
        org_only = sorted(set(data) & _ORG_KEYS)
        if org_only:
            raise PolicyError(f"{source}: organization-only key(s) {org_only}")
    _check_keys(source, data, allowed)

    layer = PolicyLayer(source=source)  # type: ignore[arg-type]
    if "profile" in data:
        layer.profile = _str("profile", data["profile"])
    if "default_lane" in data:
        layer.default_lane = _str("default_lane", data["default_lane"])
    if "endpoints" in data:
        layer.endpoints = {
            name: _parse_endpoint(name, raw)
            for name, raw in _table("endpoints", data["endpoints"]).items()
        }
    if "identifiers" in data:
        t = _table("identifiers", data["identifiers"])
        _check_keys("identifiers", t, _ID_KEYS)
        layer.identifiers = IdentifierConfig(
            **{k: _str_list(f"identifiers.{k}", v) for k, v in t.items()}
        )
    if "patterns" in data:
        entries = data["patterns"]
        if not isinstance(entries, list) or not all(
            isinstance(e, dict) for e in entries
        ):
            raise PolicyError("patterns: expected an array of tables")
        try:
            layer.patterns = rules_from_patterns(entries, source)
        except ValueError as e:
            raise PolicyError(str(e)) from e
    if "actions" in data:
        layer.rule_actions = _parse_action_table("actions", data["actions"])
    if "overrides_enabled" in data:
        layer.overrides_enabled = _bool("overrides_enabled", data["overrides_enabled"])
    if "override_disabled_rules" in data:
        layer.override_disabled_rules = frozenset(
            _str_list("override_disabled_rules", data["override_disabled_rules"])
        )
    if "audit" in data:
        t = _table("audit", data["audit"])
        _check_keys("audit", t, _AUDIT_KEYS)
        on_fail = t.get("on_sink_failure", "buffer")
        if on_fail not in ("buffer", "block"):
            raise PolicyError(f"audit.on_sink_failure: unknown value {on_fail!r}")
        org_only = sorted(set(t) & {"sink", "on_sink_failure"})
        if source == "user" and org_only:
            raise PolicyError(f"audit: organization-only key(s) {org_only}")
        sink = _str("audit.sink", t["sink"]) if "sink" in t else None
        path = _str("audit.path", t.get("path", DEFAULT_AUDIT_PATH))
        layer.audit = AuditConfig(path=path, sink=sink, on_sink_failure=on_fail)
    if "egress_rehydration" in data:
        mode = data["egress_rehydration"]
        if mode not in EGRESS_MODES:
            raise PolicyError(f"egress_rehydration: unknown value {mode!r}")
        layer.egress_rehydration = mode
    if "lock_endpoints" in data:
        layer.lock_endpoints = _bool("lock_endpoints", data["lock_endpoints"])
    if "lock_profile" in data:
        layer.lock_profile = _str("lock_profile", data["lock_profile"])
    if "user_config" in data:
        if data["user_config"] not in ("use", "ignore"):
            raise PolicyError(f"user_config: unknown value {data['user_config']!r}")
        layer.user_config = data["user_config"]
    for key in ("min_version", "messages_file", "poc"):
        if key in data:
            setattr(layer, key, _str(key, data[key]))
    if "profiles" in data:
        layer.profiles = _parse_profiles(data["profiles"])
    return layer


def _action_name(a: Action) -> str:
    return a.name.lower().replace("_", "-")


def _rule_to_dict(r: Rule) -> dict:
    flags = [n for n, bit in _FLAG_NAMES.items() if r.pattern.flags & bit]
    return {
        "id": r.id,
        "class": r.cls.value,
        "regex": r.pattern.pattern,
        "flags": flags,
        "kind": r.kind,
        "verified": r.verified,
        "source": r.source,
    }


def _rule_from_dict(d: dict) -> Rule:
    try:
        return Rule(
            id=d["id"],
            cls=DetClass(d["class"]),
            pattern=_compile(d["id"], d["regex"], list(d.get("flags", []))),
            kind=d.get("kind"),
            verified=bool(d["verified"]),
            source=d["source"],
        )
    except (KeyError, ValueError, TypeError) as e:
        raise PolicyError(f"invalid serialized rule: {e}") from e


@dataclass
class EffectivePolicy:
    profile: str
    endpoints: dict[str, Endpoint]
    default_lane: str | None
    identifiers: IdentifierConfig
    extra_rules: list[Rule]
    overrides_enabled: bool
    override_disabled_rules: frozenset[str]
    audit: AuditConfig
    messages_file: str | None
    poc: str | None
    min_version: str | None
    provenance: dict[str, str]
    actions: dict[tuple[str, Trust], Action] = field(default_factory=dict)
    egress_rehydration: str = "withhold"

    def action_for_class(self, cls: DetClass, trust: Trust) -> Action:
        """Class action; a missing cell fails closed to block-hard."""
        if cls in ALWAYS_HARD:
            return Action.BLOCK_HARD
        return self.actions.get((cls.value, trust), Action.BLOCK_HARD)

    def action_for(self, hit: Hit, trust: Trust) -> Action:
        """A rule-ID entry applies only when it is at least as strict as the class entry."""
        base = self.action_for_class(hit.cls, trust)
        if hit.cls in ALWAYS_HARD:
            return base
        rule_level = self.actions.get((hit.rule_id, trust))
        return base if rule_level is None else max(base, rule_level)

    def to_dict(self) -> dict:
        ids = self.identifiers
        return {
            "profile": self.profile,
            "endpoints": {
                n: {
                    "url": e.url,
                    "formats": list(e.formats),
                    "trust": e.trust.value,
                    "credential": e.credential,
                }
                for n, e in self.endpoints.items()
            },
            "default_lane": self.default_lane,
            "identifiers": {
                "domains": list(ids.domains),
                "ip_ranges": list(ids.ip_ranges),
                "codenames": list(ids.codenames),
                "jira_projects": list(ids.jira_projects),
                "people": list(ids.people),
            },
            "extra_rules": [_rule_to_dict(r) for r in self.extra_rules],
            "overrides_enabled": self.overrides_enabled,
            "override_disabled_rules": sorted(self.override_disabled_rules),
            "audit": {
                "path": self.audit.path,
                "sink": self.audit.sink,
                "on_sink_failure": self.audit.on_sink_failure,
            },
            "messages_file": self.messages_file,
            "poc": self.poc,
            "min_version": self.min_version,
            "provenance": dict(self.provenance),
            "actions": [
                [k, t.value, _action_name(a)] for (k, t), a in self.actions.items()
            ],
            "egress_rehydration": self.egress_rehydration,
        }

    @classmethod
    def from_dict(cls, d: dict) -> EffectivePolicy:
        try:
            a = d["audit"]
            if d["egress_rehydration"] not in EGRESS_MODES:
                raise PolicyError("invalid serialized policy: egress_rehydration")
            return cls(
                profile=d["profile"],
                endpoints={
                    n: Endpoint(
                        n,
                        e["url"],
                        tuple(e["formats"]),
                        Trust(e["trust"]),
                        e["credential"],
                    )
                    for n, e in d["endpoints"].items()
                },
                default_lane=d["default_lane"],
                identifiers=IdentifierConfig(
                    **{k: tuple(v) for k, v in d["identifiers"].items()}
                ),
                extra_rules=[_rule_from_dict(r) for r in d["extra_rules"]],
                overrides_enabled=d["overrides_enabled"],
                override_disabled_rules=frozenset(d["override_disabled_rules"]),
                audit=AuditConfig(a["path"], a["sink"], a["on_sink_failure"]),
                messages_file=d["messages_file"],
                poc=d["poc"],
                min_version=d["min_version"],
                provenance=dict(d["provenance"]),
                actions={(k, Trust(t)): Action.parse(a_) for k, t, a_ in d["actions"]},
                egress_rehydration=d["egress_rehydration"],
            )
        except PolicyError:
            raise
        except (KeyError, ValueError, TypeError) as e:
            raise PolicyError(f"invalid serialized policy: {e}") from e
