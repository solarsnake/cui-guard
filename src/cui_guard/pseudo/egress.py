"""Egress-aware rehydration: a tool-call string that names an outside host keeps its placeholders."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Literal

from cui_guard.detect.identifiers import (
    BUILTIN_DOMAINS,
    BUILTIN_IP_RANGES,
    IdentifierConfig,
)
from cui_guard.detect.normalize import normalize

if TYPE_CHECKING:
    from cui_guard.pseudo.mapper import SessionMap

# Generic and country-code TLDs that a bare `name.tld` token is taken to end in. Codes that are
# also common file extensions or code idioms are left out (`main.py`, `user.id`, `x.to(dev)`,
# `Dockerfile.dev`, `id_rsa.pub`), as is `invalid`, the TLD of every guard placeholder. URLs,
# `user@host` forms and IP literals count whatever their TLD.
COMMON_TLDS = frozenset(
    {
        # generic
        "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "mobi", "aero",
        "asia", "coop", "jobs", "museum", "travel", "tel", "post", "cat", "xxx",
        "xyz", "top", "site", "online", "club", "shop", "store", "live", "link", "click", "win",
        "vip", "work", "icu", "buzz", "fun", "space", "website", "tech", "cloud", "life", "world",
        "today", "email", "host", "press", "rest", "bar", "loan", "men", "date", "review",
        "stream", "trade", "party", "racing", "science", "download", "accountant", "cricket",
        "faith", "bid", "cyou", "monster", "sbs", "cfd", "lol", "quest", "uno", "best", "mom",
        "guru", "page", "blog", "news", "network", "systems", "solutions", "services", "agency",
        "digital", "media", "studio", "design", "art", "one", "global", "group", "company",
        "center", "zone", "team", "new",
        # country codes
        "ad", "ae", "af", "ag", "al", "ao", "aq", "ar", "as", "au", "aw", "ax", "az", "ba", "bb", "bd",
        "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "bq", "br", "bs", "bt", "bw", "by", "bz", "ca",
        "cd", "cg", "ch", "ci", "ck", "cm", "cn", "co", "cr", "cv", "cw", "cx", "cy", "cz", "de", "dj",
        "dk", "dm", "dz", "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo",
        "fr", "ga", "gb", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gt",
        "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "ie", "il", "im", "io", "iq", "ir",
        "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw",
        "ky", "kz", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "me", "mf", "mg",
        "mh", "mn", "mp", "mq", "mr", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "ne", "nf",
        "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg", "ph", "pk", "pn",
        "pr", "pw", "qa", "ro", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn",
        "sr", "ss", "st", "su", "sx", "sy", "sz", "tc", "td", "tg", "th", "tj", "tk", "tl", "tm", "tn", "tr",
        "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn",
        "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw",
    }
)  # fmt: skip

_LOOPBACK_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
# scheme://authority — the authority ends at a path, query, fragment, quote or backslash.
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://([^\s/?#\\'\"`<>]*)")
# user@host, optionally followed by ':' (the scp / git form). Any non-space character before
# '@' counts, so a quote or backslash (`"http://x.mil"@evil.app`) cannot hide the host.
_AT = re.compile(r"(?<=\S)@(\[[0-9A-Fa-f:.%\w]+\]|[\w\-]+(?:\.[\w\-]+)*)(:?)")
# A maximal dotted token: `a.b`, `x.y.z` (labels are Unicode word characters or '-').
_DOTTED = re.compile(r"(?<![\w\-.])[\w\-]+(?:\.[\w\-]+)+(?![\w\-]|\.[\w\-])")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?(?![\w:])")
_CLEAN_HOST = re.compile(r"[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*")
_DIGEST = re.compile(r"sha\d+|md5|blake\w*")  # `image@sha256:...` is not an scp target
_HOST_OR_IP_PLACEHOLDER = re.compile(r"host-\d+\.cg\.invalid|198\.18\.\d{1,3}\.\d{1,3}")


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An IP literal, or None. Octets with a leading zero are refused (resolvers may read octal)."""
    h = host.split("%", 1)[0]
    if re.fullmatch(r"[\d.]+", h) and any(len(o) > 1 and o[0] == "0" for o in h.split(".")):
        return None
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _at_destination(host: str, colon: bool) -> bool:
    """Whether the host of a `user@host` (or `user@host:`) form is a destination."""
    labels = host.strip("[]").split(".")
    if labels[-1].lower() == "invalid":
        return False  # RFC 6761: never resolves; the guard's email placeholders end in it
    if host.startswith("[") or _ip(host) is not None:
        return True
    if len(labels) >= 2:
        return any(c.isalpha() for c in labels[-1])  # `pkg@1.2.3` is a version, not a host
    return colon and not _DIGEST.fullmatch(host.lower())  # scp `u@box:`, not `img@sha256:`


class EgressGuard:
    """Decides whether a tool-call string names a destination outside the user's own network."""

    def __init__(self, identifiers: IdentifierConfig, mode: Literal["withhold", "allow"]) -> None:
        if mode not in ("withhold", "allow"):
            raise ValueError(f"unknown egress_rehydration mode {mode!r}")
        self.mode = mode
        self._domains = tuple(
            d.strip(".").lower() for d in BUILTIN_DOMAINS + identifiers.domains if d.strip(".")
        )
        nets = []
        for r in BUILTIN_IP_RANGES + identifiers.ip_ranges:
            try:
                nets.append(ipaddress.ip_network(r, strict=False))
            except ValueError as e:
                raise ValueError(f"invalid ip_ranges entry {r!r}: {e}") from e
        self._nets = tuple(nets)

    def _internal_ip(self, raw: str, smap: SessionMap) -> bool:
        addr = _ip(raw)
        if addr is None:
            return False
        if any(addr in n for n in _LOOPBACK_NETS if n.version == addr.version):
            return True
        if _HOST_OR_IP_PLACEHOLDER.fullmatch(raw) and smap.knows(raw):
            return True
        return any(addr in n for n in self._nets if n.version == addr.version)

    def _internal(self, host: str, smap: SessionMap) -> bool:
        h = host.lower()
        if h.startswith("[") and h.endswith("]"):
            return self._internal_ip(h[1:-1], smap)
        h = h.rstrip(".")
        if _ip(h) is not None:
            return self._internal_ip(h, smap)
        if not _CLEAN_HOST.fullmatch(h):
            return False  # percent-encoded, odd or non-ASCII hosts are never taken as internal
        if h == "localhost":
            return True
        if _HOST_OR_IP_PLACEHOLDER.fullmatch(h) and smap.knows(h):
            return True
        return any(h == d or h.endswith("." + d) for d in self._domains)

    def _destinations(self, text: str):
        """Every host the text names, in any of the destination forms."""
        for m in _URL.finditer(text):
            authority = m.group(1).rpartition("@")[2]
            if authority.startswith("["):
                host = authority[: authority.find("]") + 1] if "]" in authority else authority
            else:
                host = authority.split(":", 1)[0]
            if host:
                yield host
        for m in _AT.finditer(text):
            if _at_destination(m.group(1), bool(m.group(2))):
                yield m.group(1)
        for m in _DOTTED.finditer(text):
            tld = m.group(0).rsplit(".", 1)[1].lower()
            if tld in COMMON_TLDS or tld.startswith("xn--") or (not tld.isascii() and tld.isalpha()):
                yield m.group(0)
        for m in _IPV4.finditer(text):
            yield m.group(0)
        for m in _IPV6.finditer(text):
            cand = m.group(0)
            if any(c.isdigit() for c in cand) and _ip(cand) is not None:
                yield cand

    def is_outbound(self, text: str, smap: SessionMap) -> bool:
        """True when `text` names a destination (URL, user@host, name.tld, IP) that is not internal."""
        norm, _ = normalize(text)
        return any(not self._internal(h, smap) for h in self._destinations(norm))
