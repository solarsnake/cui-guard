import pytest

from cui_guard.model import DetClass, Hit
from cui_guard.pseudo.mapper import SessionMap


def hit(text: str, value: str, kind: str) -> Hit:
    i = text.index(value)
    return Hit("t", DetClass.IDENTIFIER, i, i + len(value), value, kind)


def test_deterministic_same_value():
    m = SessionMap()
    a = "go db.example.mil"
    b = "again db.example.mil"
    pa = m.pseudonymize(a, [hit(a, "db.example.mil", "host")])
    pb = m.pseudonymize(b, [hit(b, "db.example.mil", "host")])
    assert pa.split()[1] == pb.split()[1]
    assert len(m) == 1


def test_formats():
    m = SessionMap()
    assert m.placeholder_for("a.example.mil", "host") == "host-01.cg.invalid"
    assert m.placeholder_for("10.1.2.3", "ip") == "198.18.0.1"
    assert m.placeholder_for("x" * 12, "secret") == "CG_SECRET_01"
    assert m.placeholder_for("a@b.mil", "email") == "person01@example.invalid"
    assert m.placeholder_for("PROJ-9", "jira") == "CGTKT-1"
    assert m.placeholder_for("Jane", "person") == "CG_PERSON_01"
    assert m.placeholder_for("Falcon", "term") == "CG_TERM_01"


def test_round_trip():
    m = SessionMap()
    t = "ssh a.example.mil from 10.1.2.3 as Jane"
    hits = [hit(t, "a.example.mil", "host"), hit(t, "10.1.2.3", "ip"), hit(t, "Jane", "person")]
    out = m.pseudonymize(t, hits)
    assert "a.example.mil" not in out and "10.1.2.3" not in out
    assert m.rehydrate(out) == t


def test_substring_rehydration():
    m = SessionMap()
    m.placeholder_for("a.example.mil", "host")
    assert "a.example.mil" in m.rehydrate("ssh admin@host-01.cg.invalid -p 22")


def test_echo_remasked_without_hits():
    m = SessionMap()
    t = "db.example.mil"
    m.pseudonymize(t, [hit(t, t, "host")])
    assert "db.example.mil" not in m.pseudonymize("connect db.example.mil", [])


def test_collision_skips():
    m = SessionMap()
    m.pseudonymize("saw host-01.cg.invalid here", [])
    assert m.placeholder_for("a.example.mil", "host") == "host-02.cg.invalid"


def test_collision_seen_in_rehydrate_text():
    m = SessionMap()
    m.rehydrate("CG_SECRET_01 appears")
    assert m.placeholder_for("s" * 12, "secret") == "CG_SECRET_02"


def test_leftover():
    m = SessionMap()
    assert m.leftover_placeholders("host-99.cg.invalid") == ["host-99.cg.invalid"]
    p = m.placeholder_for("a.example.mil", "host")
    assert m.leftover_placeholders(p) == []


def test_rehydrate_no_prefix_match():
    m = SessionMap()
    for i in range(10):
        m.placeholder_for(f"h{i}.example.mil", "host")
    out = m.rehydrate("host-10.cg.invalid and host-01.cg.invalid")
    assert out == "h9.example.mil and h0.example.mil"
    assert m.rehydrate("host-11.cg.invalid") == "host-11.cg.invalid"


def test_rehydrate_secret_prefix():
    m = SessionMap()
    m.placeholder_for("s" * 12, "secret")
    assert m.rehydrate("CG_SECRET_011") == "CG_SECRET_011"
    assert m.rehydrate("CG_SECRET_01") == "s" * 12
    assert m.rehydrate("198.18.0.10") == "198.18.0.10"


def test_ip_prefix_not_rehydrated():
    m = SessionMap()
    m.placeholder_for("10.0.0.1", "ip")
    assert m.rehydrate("198.18.0.10") == "198.18.0.10"
    assert m.rehydrate("198.18.0.1") == "10.0.0.1"


def test_echo_not_inside_placeholder():
    m = SessionMap()
    m.placeholder_for("host", "term")  # real value "host" is a substring of placeholders
    p = m.placeholder_for("a.example.mil", "host")
    out = m.pseudonymize(f"{p} and host", [])
    assert out.startswith(p + " and ")
    assert out.endswith("CG_TERM_01")


def test_echo_longest_first():
    m = SessionMap()
    m.placeholder_for("db", "term")
    m.placeholder_for("db.example.mil", "host")
    out = m.pseudonymize("db.example.mil and db", [])
    assert out == "host-01.cg.invalid and CG_TERM_01"
    assert m.rehydrate(out) == "db.example.mil and db"


def test_overlapping_hits_skipped_and_none_kind_ignored():
    m = SessionMap()
    t = "abcdef"
    hits = [
        Hit("t", DetClass.IDENTIFIER, 2, 5, "cde", "term"),
        Hit("t", DetClass.IDENTIFIER, 0, 3, "abc", "term"),
        Hit("t", DetClass.CUI_MARKING, 5, 6, "f", None),
    ]
    assert m.pseudonymize(t, hits) == "CG_TERM_01def"
    assert len(m) == 1


def test_ip_cap_raises():
    m = SessionMap()
    for i in range(65534):
        m.placeholder_for(f"v{i}", "ip")
    assert m.placeholder_for("v65533", "ip") == "198.18.255.254"
    with pytest.raises(RuntimeError):
        m.placeholder_for("overflow", "ip")
