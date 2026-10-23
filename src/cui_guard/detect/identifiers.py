"""Identifier detection: hosts, IPs, emails, Jira keys, codenames, people."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from cui_guard.detect.normalize import normalize
from cui_guard.model import DetClass, Hit

BUILTIN_DOMAINS = ("mil", "gov")
BUILTIN_IP_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_EMAIL = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_JIRA = re.compile(r"(?<![A-Za-z0-9])([A-Z][A-Z0-9]{1,9})-\d+(?![A-Za-z0-9])")


@dataclass(frozen=True)
class IdentifierConfig:
    domains: tuple[str, ...] = ()
    ip_ranges: tuple[str, ...] = ()
    codenames: tuple[str, ...] = ()
    jira_projects: tuple[str, ...] = ()
    people: tuple[str, ...] = ()


def _host_pattern(domains: tuple[str, ...]) -> re.Pattern[str] | None:
    names = [d.strip(".") for d in domains if d.strip(".")]
    if not names:
        return None
    alt = "|".join(re.escape(d) for d in sorted(set(names), key=len, reverse=True))
    return re.compile(
        rf"(?<![A-Za-z0-9.\-])(?:{_LABEL}\.)+(?:{alt})(?![A-Za-z0-9\-]|\.[A-Za-z0-9])",
        re.IGNORECASE,
    )


def _words(terms: tuple[str, ...], flags: int) -> re.Pattern[str] | None:
    parts = [re.escape(t) for t in terms if t]
    if not parts:
        return None
    return re.compile(rf"(?<!\w)(?:{'|'.join(parts)})(?!\w)", flags)


def identifier_hits(text: str, cfg: IdentifierConfig) -> list[Hit]:
    norm, index_map = normalize(text)
    hits: list[Hit] = []

    def add(kind: str, m: re.Match[str]) -> None:
        start = index_map[m.start()]
        end = index_map[m.end() - 1] + 1
        hits.append(
            Hit(
                rule_id=f"id.{kind}",
                cls=DetClass.IDENTIFIER,
                start=start,
                end=end,
                value=text[start:end],
                kind=kind,
            )
        )

    host_pat = _host_pattern(BUILTIN_DOMAINS + cfg.domains)
    if host_pat:
        for m in host_pat.finditer(norm):
            add("host", m)

    networks = [
        ipaddress.ip_network(r, strict=False) for r in BUILTIN_IP_RANGES + cfg.ip_ranges
    ]
    for m in _IPV4.finditer(norm):
        try:
            addr = ipaddress.IPv4Address(m.group())
        except ValueError:
            continue
        if any(addr in n for n in networks if n.version == 4):
            add("ip", m)

    for m in _EMAIL.finditer(norm):
        add("email", m)

    cfg_host_pat = _host_pattern(cfg.domains)
    any_key = bool(cfg_host_pat and cfg_host_pat.search(norm))
    projects = set(cfg.jira_projects)
    for m in _JIRA.finditer(norm):
        if m.group(1) in projects or any_key:
            add("jira", m)

    codename_pat = _words(cfg.codenames, re.IGNORECASE)
    if codename_pat:
        for m in codename_pat.finditer(norm):
            add("term", m)

    people_pat = _words(cfg.people, 0)
    if people_pat:
        for m in people_pat.finditer(norm):
            add("person", m)

    hits.sort(key=lambda h: (h.start, h.end))
    return hits
