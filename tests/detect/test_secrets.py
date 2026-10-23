import re

import pytest

from cui_guard.detect.rules import Rule, load_builtin_rules, scan_rules
from cui_guard.model import DetClass

SECRET_RULES = [r for r in load_builtin_rules() if r.cls is DetClass.SECRET]

# Synthetic values are assembled at runtime so no literal key shapes live in source.
AWS = "AKI" + "A" + "Q" * 16
GH = "gh" + "p_" + "B" * 36
ANT = "sk-" + "ant-" + "api03-" + "A" * 30
OAI = "sk-" + "Z" * 30
SLACK = "xo" + "xb-" + "1" * 10 + "-" + "a" * 8
DASH = "-" * 5
PEM = f"{DASH}BEGIN RSA PRIVATE KEY{DASH}\nMIIB\nzz\n{DASH}END RSA PRIVATE KEY{DASH}"
PUBPEM = f"{DASH}BEGIN PUBLIC KEY{DASH}\nMIIB\n{DASH}END PUBLIC KEY{DASH}"
HUNTER = "hunt" + "er2"


def hits_for(rule_id: str, text: str):
    rules = [r for r in SECRET_RULES if r.id == rule_id]
    assert rules, rule_id
    return scan_rules(text, rules)


CASES = [
    ("secret.aws-access-key", f"key {AWS} end", AWS, "AKI" + "A1234"),
    ("secret.github-token", f"t {GH} x", GH, "gh" + "p_short"),
    ("secret.anthropic-key", f"k {ANT}", ANT, "sk-" + "ant-x"),
    ("secret.openai-key", f"k {OAI} z", OAI, "sk-" + "short"),
    ("secret.slack-token", f"s {SLACK}", SLACK, "xo" + "xb-1"),
    ("secret.private-key-block", f"a\n{PEM}\nb", PEM, PUBPEM),
    ("secret.assignment", "password=" + HUNTER, HUNTER, "password"),
    (
        "secret.assignment",
        "cfg passwd: " + "s3" + "cret!",
        "s3" + "cret!",
        "the token was lost",
    ),
    ("secret.assignment", 'TOKEN: "' + "abc" + '123"', "abc123", "passwords are hard"),
    (
        "secret.url-credentials",
        "db postgres://admin:" + "pw0" + "rd@host/db",
        "pw0" + "rd",
        "https://example.com/a@b",
    ),
]


@pytest.mark.parametrize(("rule_id", "pos", "value", "neg"), CASES)
def test_secret_rules(rule_id, pos, value, neg):
    hits = hits_for(rule_id, pos)
    assert [h.value for h in hits] == [value]
    assert hits[0].kind == "secret" and hits[0].cls is DetClass.SECRET
    assert hits_for(rule_id, neg) == []


def test_openai_rule_ignores_anthropic_key():
    assert hits_for("secret.openai-key", ANT) == []


def test_value_group_span_maps_to_original_offsets():
    text = "pw: password=" + HUNTER + " end"
    (h,) = hits_for("secret.assignment", text)
    assert text[h.start : h.end] == HUNTER


def test_rule_without_value_group_keeps_whole_match():
    rule = Rule("r", DetClass.SECRET, re.compile(r"ab(c)"), "secret", True, "t")
    (h,) = scan_rules("xabc", [rule])
    assert h.value == "abc"


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ('{"password": "' + "abc" + '12345"}', "abc12345"),
        ("API_TOKEN=" + "xyz" + "789", "xyz789"),
        ("export GITHUB_TOKEN=" + "qq" + "rr99", "qq" + "rr99"),
        ("token: Bearer " + "abc" + "def", "abc" + "def"),
        ("token: Basic " + "dXNl" + "cjpw", "dXNl" + "cjpw"),
    ],
)
def test_assignment_shapes(text, value):
    assert [h.value for h in hits_for("secret.assignment", text)] == [value]


def test_assignment_ignores_lookalike_names():
    assert hits_for("secret.assignment", "mytokenizer=fast") == []
