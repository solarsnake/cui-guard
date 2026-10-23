import dataclasses

import pytest
from test_app import make_cfg

from cui_guard.gateway import __main__ as gm
from cui_guard.override.human import FakeChannel, HeadlessChannel


class Stop(Exception):
    pass


@pytest.mark.parametrize("headless", [False, True])
async def test_main_wires_channel_into_create_app(tmp_path, monkeypatch, headless):
    cfg = dataclasses.replace(make_cfg(tmp_path), headless=headless)
    cfg.policy.poc = "ISSO x1234"
    sentinel = FakeChannel("j", True)
    seen = {}

    def fake_select(h, messages, poc):
        seen["select"] = (h, poc, "warn.cui_public" in messages)
        return sentinel

    def fake_create(c, **kw):
        seen["channel"] = kw.get("channel")
        raise Stop

    monkeypatch.setattr(gm, "select_channel", fake_select)
    monkeypatch.setattr(gm, "create_app", fake_create)
    with pytest.raises(Stop):
        await gm._serve(cfg)
    assert seen["select"] == (headless, "ISSO x1234", True)
    assert seen["channel"] is sentinel


async def test_headless_config_selects_headless_channel(tmp_path, monkeypatch):
    cfg = dataclasses.replace(make_cfg(tmp_path), headless=True)
    seen = {}

    def fake_create(c, **kw):
        seen["channel"] = kw.get("channel")
        raise Stop

    monkeypatch.setattr(gm, "create_app", fake_create)
    with pytest.raises(Stop):
        await gm._serve(cfg)
    assert isinstance(seen["channel"], HeadlessChannel)


def test_watch_stdin_exits_on_eof():
    import io

    codes = []
    gm._watch_stdin(io.StringIO(""), codes.append)
    assert codes == [0]
