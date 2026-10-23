import pytest

from cui_guard.model import Action, DetClass
from cui_guard.override.store import OverrideStore
from cui_guard.pipeline import BlockInfo


def block(h: str, r: str) -> BlockInfo:
    return BlockInfo(r, DetClass.CUI_MARKING, Action.BLOCK, "loc", "x", h, None)


def test_grant_scoped_to_hash_and_rule():
    s = OverrideStore()
    oid = s.register(block("h1", "r1"))
    assert s.pending(oid) is not None
    assert not s.is_granted("h1", "r1")
    s.grant(oid, "because")
    assert s.is_granted("h1", "r1")
    assert not s.is_granted("h2", "r1")
    assert not s.is_granted("h1", "r2")


def test_unknown_override_id():
    with pytest.raises(KeyError):
        OverrideStore().grant("nope", "why")
