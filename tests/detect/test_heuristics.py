import time
from pathlib import Path

import pytest

from cui_guard.detect.heuristics import _cve_internal_host, controlled_content_hits
from cui_guard.detect.identifiers import IdentifierConfig
from cui_guard.model import DetClass

CORPUS = Path(__file__).parent.parent / "corpus"
CFG = IdentifierConfig(ip_ranges=("10.0.0.0/8",))

POSITIVE = sorted((CORPUS / "positive" / "controlled").glob("*.txt"))
NEGATIVE = sorted((CORPUS / "negative").glob("*.txt"))


@pytest.mark.parametrize("path", POSITIVE, ids=lambda p: p.stem)
def test_each_must_catch_file_hits(path):
    text = path.read_text()
    hits = controlled_content_hits(text, CFG)
    assert path.stem in {h.rule_id for h in hits}
    for h in hits:
        assert h.cls is DetClass.CONTROLLED_CONTENT
        assert text[h.start : h.end] == h.value


def test_positive_corpus_covers_all_rules():
    assert {p.stem for p in POSITIVE} == {
        "cc.nessus",
        "cc.nmap",
        "cc.stig",
        "cc.poam",
        "cc.fw_dump",
        "cc.cve_internal_host",
    }


def test_negative_corpus_size():
    assert len(NEGATIVE) >= 15


@pytest.mark.parametrize("path", NEGATIVE, ids=lambda p: p.name)
def test_negative_corpus_zero_hits(path):
    assert controlled_content_hits(path.read_text(), CFG) == []


@pytest.mark.parametrize("text", ["Status: done", "see CVE-2024-3094 in xz"])
def test_single_keyword_not_enough(text):
    assert controlled_content_hits(text, CFG) == []


def test_fw_dump_needs_configured_ranges():
    line = "iptables -A INPUT -s 10.20.30.4 -j DROP"
    assert controlled_content_hits(line, IdentifierConfig()) == []
    assert [h.rule_id for h in controlled_content_hits(line, CFG)] == ["cc.fw_dump"]


def test_cve_far_from_host_not_flagged():
    text = "host a.example.mil\n" + "x\n" * 10 + "CVE-2099-12345"
    assert controlled_content_hits(text, IdentifierConfig()) == []


def test_single_stig_vuln_id_not_enough():
    assert controlled_content_hits("ticket V-12345 closed", CFG) == []


PROSE = "Weakness, POC and Status tracking in our weekly status meeting"


def test_poam_prose_not_flagged():
    assert controlled_content_hits(PROSE, CFG) == []


@pytest.mark.parametrize(
    "header",
    [
        "Weakness | POC | Status",
        "Weakness\tPOC\tStatus",
        "Weakness,POC,Milestone,Status",
    ],
)
def test_poam_table_headers_hit(header):
    assert [h.rule_id for h in controlled_content_hits(header, CFG)] == ["cc.poam"]


def test_poam_csv_with_long_cell_not_flagged():
    line = "Weakness," + "x" * 50 + ",POC,Status"
    assert controlled_content_hits(line, CFG) == []


def _timed(text, cfg):
    start = time.perf_counter()
    _cve_internal_host(text, cfg)
    return time.perf_counter() - start


@pytest.mark.perf
def test_cve_scan_perf_no_hosts():
    text = "\n".join(f"CVE-2099-{10000 + i} noted" for i in range(20000))
    assert _timed(text, IdentifierConfig()) < 0.05


@pytest.mark.perf
def test_cve_scan_perf_one_host():
    lines = [f"CVE-2099-{10000 + i} noted" for i in range(20000)]
    lines[10] = "host a.example.mil"
    assert _timed("\n".join(lines), IdentifierConfig()) < 0.1
