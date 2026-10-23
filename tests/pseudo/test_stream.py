import json
import random

import pytest

from cui_guard.pseudo.mapper import SessionMap
from cui_guard.pseudo.stream import ArgsBuffer, TextHoldback, rehydrate_json_text


def make_map() -> SessionMap:
    m = SessionMap()
    m.placeholder_for("db.example.mil", "host")
    m.placeholder_for("10.1.2.3", "ip")
    m.placeholder_for("a@b.mil", "email")
    m.placeholder_for("PROJ-9", "jira")
    m.placeholder_for("Jane", "person")
    m.placeholder_for("s3cret-value", "secret")
    m.placeholder_for("Falcon", "term")
    return m


def test_holdback_split_placeholder():
    m = make_map()
    h = TextHoldback(m)
    out = h.feed("go to host-0") + h.feed("1.cg.invalid now") + h.flush()
    assert out == "go to db.example.mil now"


def test_holdback_no_false_hold():
    h = TextHoldback(make_map())
    assert h.feed("hello world") == "hello world"


def test_holdback_bounded():
    h = TextHoldback(make_map())
    out = h.feed("host-" + "1" * 200)
    assert len(out) >= 200 - 40


def test_rehydrate_json_escapes_real_value():
    m = SessionMap()
    real = 'a"b\\c\nd'
    ph = m.placeholder_for(real, "secret")
    assert ph == "CG_SECRET_01"
    text = rehydrate_json_text('{"cmd":"echo CG_SECRET_01"}', m)
    assert json.loads(text)["cmd"] == "echo " + real


def test_rehydrate_json_keys_and_invalid():
    m = make_map()
    text = rehydrate_json_text('{"host-01.cg.invalid":["CGTKT-1",3]}', m)
    assert json.loads(text) == {"db.example.mil": ["PROJ-9", 3]}
    with pytest.raises(ValueError):
        rehydrate_json_text("{bad", m)


def test_args_buffer_fragments():
    m = make_map()
    b = ArgsBuffer()
    for frag in ['{"cmd":"ssh host-', "01.cg.inv", 'alid"}']:
        b.feed(frag)
    assert "db.example.mil" in b.finish(m)


PIECES = [
    "host-01.cg.invalid", "198.18.0.1", "person01@example.invalid", "CGTKT-1",
    "CG_PERSON_01", "CG_SECRET_01", "CG_TERM_01", "host-1", "host-10.cg.invalid",
    "CG_SECRET_011", "xhost-01.cg.invalid", "198.18.0.1.5", "5.198.18.0.1",
    "198.18.0.1.", "198.18.0.12", "CG_SE", "host-", "198.1", "person", "CGTKT-12",
    "CG_", "_CG_TERM_01", "CGTKT-1x", " ", "\n", ", ", "word ", "é", "198.18.0.",
]


def test_property_random_chunkings_match_rehydrate():
    m = make_map()
    rng = random.Random(1234)
    for _ in range(500):
        text = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 14)))
        expected = m.rehydrate(text)
        h = TextHoldback(m)
        out: list[str] = []
        i = 0
        while i < len(text):
            n = rng.randint(1, 8)
            out.append(h.feed(text[i : i + n]))
            i += n
        out.append(h.flush())
        assert "".join(out) == expected, text
