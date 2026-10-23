import asyncio
import threading

from test_app import CUI, H, Upstream, audit_rows, client, make_cfg, msg

from cui_guard.override.human import FakeChannel

JUSTIFICATION = "reviewed by me: synthetic test string, not CUI"
CLASSIFIED = "TOP SECRET//SI//TK//NOFORN"


async def until(pred, timeout=3.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if pred():
            return True
        await asyncio.sleep(0.01)
    return pred()


def override_rows(tmp_path):
    return [r for r in audit_rows(tmp_path) if r["action"] == "override"]


async def test_override_granted_after_auth_then_retry_forwards(tmp_path):
    up = Upstream()
    ch = FakeChannel(JUSTIFICATION, True)
    async with client(make_cfg(tmp_path), up, channel=ch) as c:
        r = await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert r.status_code == 400 and "Override offered on your screen" in r.json()["error"]["message"]
        assert up.requests == []
        assert await until(lambda: override_rows(tmp_path))
        r = await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert r.status_code == 200 and len(up.requests) == 1
    assert ch.auth_requests and ch.auth_requests[0].startswith("cui-guard override ")
    assert ch.justification_requests[0][1]  # the warning was shown
    assert "ISOO Notice 2026-01" in ch.justification_requests[0][1]


async def test_override_denied_when_auth_fails(tmp_path):
    up = Upstream()
    ch = FakeChannel(JUSTIFICATION, False)
    async with client(make_cfg(tmp_path), up, channel=ch) as c:
        await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert await until(lambda: ch.auth_requests)
        await asyncio.sleep(0.1)
        r = await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert r.status_code == 400 and up.requests == []
    assert override_rows(tmp_path) == []


async def test_override_denied_without_justification(tmp_path):
    up = Upstream()
    ch = FakeChannel(None, True)
    async with client(make_cfg(tmp_path), up, channel=ch) as c:
        await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert await until(lambda: ch.justification_requests)
        await asyncio.sleep(0.1)
        r = await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert r.status_code == 400
    assert ch.auth_requests == []


async def test_no_override_route_exists(tmp_path):
    async with client(make_cfg(tmp_path), Upstream(), channel=FakeChannel(JUSTIFICATION, True)) as c:
        for path in ("/override", "/overrides", "/admin"):
            for method in ("GET", "POST"):
                r = await c.request(method, path, headers=H, json={"id": "x"})
                assert r.status_code in (404, 405)


async def test_block_hard_never_prompts_justification(tmp_path):
    up = Upstream()
    ch = FakeChannel(JUSTIFICATION, True)
    async with client(make_cfg(tmp_path), up, channel=ch) as c:
        r = await c.post("/v1/messages", json=msg(f"banner {CLASSIFIED} end"), headers=H)
        assert r.status_code == 400 and up.requests == []
        m = r.json()["error"]["message"]
        assert "security officer" in m and "Nothing was forwarded" in m
        assert await until(lambda: ch.notifications)
    assert ch.justification_requests == [] and ch.auth_requests == []
    assert all(offered is False for _, offered in ch.notifications)


async def test_override_audit_record(tmp_path):
    ch = FakeChannel(JUSTIFICATION, True)
    async with client(make_cfg(tmp_path), Upstream(), channel=ch) as c:
        await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert await until(lambda: override_rows(tmp_path))
    (row,) = override_rows(tmp_path)
    (o,) = row["override"]
    assert o["status"] == "granted" and o["justification"] == JUSTIFICATION
    assert o["id"] and o["rule_id"] and len(o["content_hash"]) == 64
    assert CUI not in str(row)


async def test_repeated_blocks_do_not_stack_dialogs(tmp_path):
    gate = threading.Event()

    class Slow(FakeChannel):
        def request_justification(self, block, warning):
            self.justification_requests.append((block, warning))
            gate.wait(3)
            return self.justification

    ch = Slow(JUSTIFICATION, True)
    async with client(make_cfg(tmp_path), Upstream(), channel=ch) as c:
        for _ in range(3):
            await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
        assert await until(lambda: ch.justification_requests)
        await asyncio.sleep(0.1)
        assert len(ch.justification_requests) == 1
        gate.set()
        assert await until(lambda: override_rows(tmp_path))


async def test_no_override_message_uses_poc(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.policy.overrides_enabled = False
    cfg.policy.poc = "ISSO x1234"
    async with client(cfg, Upstream()) as c:
        r = await c.post("/v1/messages", json=msg(f"here {CUI} data"), headers=H)
    m = r.json()["error"]["message"]
    assert "No override available." in m and "contact ISSO x1234" in m
