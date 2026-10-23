from cui_guard.model import Action, DetClass


def test_action_ordering():
    assert Action.ALLOW < Action.PSEUDONYMIZE < Action.BLOCK < Action.BLOCK_HARD
    assert max(Action.BLOCK, Action.ALLOW) is Action.BLOCK


def test_action_parse():
    assert Action.parse("block-hard") is Action.BLOCK_HARD
    try:
        Action.parse("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("Action.parse('nope') should raise ValueError")


def test_detclass_values():
    assert DetClass("cui-marking") is DetClass.CUI_MARKING
