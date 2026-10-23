import json
import os
import stat

import pytest

from cui_guard.audit import AuditLog, AuditUnavailable
from cui_guard.model import Action, DetClass, Trust
from cui_guard.pipeline import BlockInfo, Decision, Segment
from cui_guard.policy.schema import AuditConfig

CANARY = "CANARY-host-db.example.mil"
CANARY2 = "sk-" + "ant-" + "Q" * 24


def decision():
    d = Decision(hit_counts={"cui.marking": 1})
    d.blocked.append(
        BlockInfo("cui.marking", DetClass.CUI_MARKING, Action.BLOCK, "messages[0]", "x", "h", "abc")
    )
    d.replacements[0] = "something"
    return d


def rec(log, d=None, **kw):
    log.record(
        agent="claude", lane="public", trust=Trust.PUBLIC, decision=d or decision(),
        request_hash="deadbeef", **kw,
    )  # fmt: skip


def test_record_has_no_values(tmp_path):
    path = tmp_path / "sub" / "audit.jsonl"
    log = AuditLog(AuditConfig(path=str(path)), "sess1", "ph")
    d = decision()
    d.segments = [Segment(0, "messages[0]", f"{CANARY} {CANARY2}")]  # stray attribute: must not leak
    rec(log, d, overrides=[{"id": "abc", "rule_id": "cui.marking"}], leftover_count=2)
    text = path.read_text()
    assert CANARY not in text and CANARY2 not in text
    row = json.loads(text)
    assert set(row) == {
        "ts", "session", "agent", "lane", "trust", "hits", "action", "blocked_rules",
        "override", "leftover_count", "request_hash", "guard_version", "policy_hash",
    }  # fmt: skip
    assert row["action"] == "blocked" and row["blocked_rules"] == ["cui.marking"]
    assert row["override"] == {"id": "abc", "rule_id": "cui.marking"}
    assert row["leftover_count"] == 2 and row["trust"] == "public"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    rec(log, Decision())
    assert json.loads(path.read_text().splitlines()[1])["action"] == "forwarded"
    assert json.loads(path.read_text().splitlines()[1])["override"] is None


def test_buffer_on_sink_failure(tmp_path):
    path = tmp_path / "audit.jsonl"
    cfg = AuditConfig(path=str(path), sink="syslog:/nonexistent/dir/sock")
    rec(AuditLog(cfg, "s"))
    pending = tmp_path / "audit.jsonl.pending"
    assert json.loads(pending.read_text())["session"] == "s"


def test_block_on_sink_failure_raises(tmp_path):
    cfg = AuditConfig(
        path=str(tmp_path / "audit.jsonl"),
        sink="syslog:/nonexistent/dir/sock",
        on_sink_failure="block",
    )
    with pytest.raises(AuditUnavailable):
        rec(AuditLog(cfg, "s"))
