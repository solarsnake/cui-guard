import pytest

from cui_guard.detect.identifiers import IdentifierConfig, identifier_hits
from cui_guard.model import DetClass


def vals(text, cfg=None, kind=None):
    hits = identifier_hits(text, cfg or IdentifierConfig())
    return [h.value for h in hits if kind is None or h.kind == kind]


def test_mil_host_in_url():
    hits = identifier_hits(
        "see https://jira.ops.example.mil/browse/OPS-12", IdentifierConfig()
    )
    host = [h for h in hits if h.kind == "host"]
    assert [h.value for h in host] == ["jira.ops.example.mil"]
    assert host[0].cls is DetClass.IDENTIFIER and host[0].rule_id == "id.host"


def test_private_ip_only():
    assert vals("10.1.2.3", kind="ip") == ["10.1.2.3"]
    assert vals("8.8.8.8", kind="ip") == []
    assert vals("10.1.2.300", kind="ip") == []


def test_configured_domain_and_range():
    cfg = IdentifierConfig(domains=("corp.example",), ip_ranges=("203.0.113.0/24",))
    assert vals("db1.corp.example", cfg, "host") == ["db1.corp.example"]
    assert vals("203.0.113.9", cfg, "ip") == ["203.0.113.9"]
    assert vals("db1.other.example", cfg, "host") == []


def test_email():
    assert vals("mail bob@example.com.", kind="email") == ["bob@example.com"]


def test_jira_key_configured():
    cfg = IdentifierConfig(jira_projects=("OPS",))
    hits = identifier_hits("OPS-4412 and ABC-1", cfg)
    assert [(h.value, h.kind) for h in hits] == [("OPS-4412", "jira")]


def test_jira_any_key_with_configured_domain():
    cfg = IdentifierConfig(domains=("corp.example",))
    text = "https://jira.corp.example/browse/ABC-17"
    assert vals(text, cfg, "jira") == ["ABC-17"]
    assert vals("ABC-17", cfg, "jira") == []


def test_codename_whole_word():
    cfg = IdentifierConfig(codenames=("BLUEFIN",))
    hits = identifier_hits("bluefin rollout", cfg)
    assert [(h.value, h.kind) for h in hits] == [("bluefin", "term")]
    assert identifier_hits("bluefinch", cfg) == []


def test_people_whole_word():
    cfg = IdentifierConfig(people=("Jane Roe",))
    assert vals("ask Jane Roe today", cfg, "person") == ["Jane Roe"]
    assert vals("Jane Roeder", cfg, "person") == []


def test_jira_any_key_with_builtin_host_zero_config():
    text = "https://jira.example.mil/browse/ABC-17"
    assert vals(text, kind="jira") == ["ABC-17"]


def test_builtin_gov_host():
    assert vals("see portal.agency.gov now", kind="host") == ["portal.agency.gov"]


def test_range_boundaries():
    assert vals("172.31.255.255", kind="ip") == ["172.31.255.255"]
    assert vals("172.16.0.0", kind="ip") == ["172.16.0.0"]
    assert vals("172.32.0.1", kind="ip") == []
    assert vals("172.15.255.255", kind="ip") == []
    assert vals("192.168.255.255", kind="ip") == ["192.168.255.255"]
    assert vals("192.169.0.1", kind="ip") == []


def test_leading_zero_octets_not_evasion():
    assert vals("010.001.002.003", kind="ip") == ["010.001.002.003"]


def test_invalid_ip_range_entry_raises():
    with pytest.raises(ValueError, match="not-a-range"):
        identifier_hits("x", IdentifierConfig(ip_ranges=("not-a-range",)))


def test_people_flexible_whitespace():
    cfg = IdentifierConfig(people=("Jane Roe",))
    assert vals("Jane  Roe", cfg, "person") == ["Jane  Roe"]
    assert vals("Jane\nRoe", cfg, "person") == ["Jane\nRoe"]


def test_uppercase_host():
    assert vals("HOST.EXAMPLE.MIL", kind="host") == ["HOST.EXAMPLE.MIL"]


def test_zero_width_char_inside_host_and_ip():
    host = "jira.exam\u200bple.mil"
    assert vals(host, kind="host") == [host]
    ip = "10.1.\u200b2.3"
    assert vals(ip, kind="ip") == [ip]
