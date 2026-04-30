"""Hash-chained audit log tests.

Covers chain primitives, append-time linkage, recovery on init, and
verify_chain detection of tampering / sequence skips / hash mismatches.
"""

import json
from pathlib import Path

from netauto.audit.chain import (
    GENESIS_PREV_HASH,
    canonical_body,
    compute_self_hash,
    link,
)
from netauto.audit.log import AuditLog
from netauto.audit.verify import verify_chain


def test_canonical_body_excludes_self_hash() -> None:
    e = {"a": 1, "self_hash": "deadbeef"}
    body = canonical_body(e)
    assert b"self_hash" not in body
    assert b"deadbeef" not in body


def test_canonical_body_is_deterministic_under_key_reorder() -> None:
    a = {"b": 2, "a": 1, "c": 3}
    b = {"c": 3, "a": 1, "b": 2}
    assert canonical_body(a) == canonical_body(b)


def test_compute_self_hash_is_64_hex_chars() -> None:
    h = compute_self_hash(
        {"seq": 1, "event_type": "x", "payload": {}, "prev_hash": GENESIS_PREV_HASH}
    )
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_link_attaches_prev_hash_and_self_hash() -> None:
    linked = link(GENESIS_PREV_HASH, {"seq": 1, "event_type": "x", "payload": {}})
    assert linked["prev_hash"] == GENESIS_PREV_HASH
    assert "self_hash" in linked
    assert len(linked["self_hash"]) == 64


def test_audit_log_first_record_has_genesis_prev(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    rec = log.append("first", {"x": 1})
    assert rec["seq"] == 1
    assert rec["prev_hash"] == GENESIS_PREV_HASH
    assert rec["self_hash"] != GENESIS_PREV_HASH
    assert len(rec["self_hash"]) == 64


def test_audit_log_chain_links_records(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    r1 = log.append("a", {})
    r2 = log.append("b", {})
    r3 = log.append("c", {})

    assert r2["prev_hash"] == r1["self_hash"]
    assert r3["prev_hash"] == r2["self_hash"]
    assert r1["seq"] == 1 and r2["seq"] == 2 and r3["seq"] == 3


def test_audit_log_resumes_chain_across_instances(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    a = AuditLog(p)
    r1 = a.append("first", {})
    # Reopen — second instance must continue the chain, not reset to genesis.
    b = AuditLog(p)
    r2 = b.append("second", {})
    assert r2["seq"] == 2
    assert r2["prev_hash"] == r1["self_hash"]


def test_verify_clean_chain(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append(f"e{i}", {"i": i})
    result = verify_chain(tmp_path / "a.jsonl")
    assert result.ok is True
    assert result.total_events == 5
    assert result.issues == []


def test_verify_empty_file_is_ok(tmp_path: Path) -> None:
    result = verify_chain(tmp_path / "missing.jsonl")
    assert result.ok is True
    assert result.total_events == 0


def test_verify_detects_payload_tampering(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})

    # Tamper with the payload of record 1 (preserving line count + seq + hashes)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["payload"]["x"] = 999
    lines[0] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")

    result = verify_chain(p)
    assert result.ok is False
    assert any("self_hash mismatch" in i for i in result.issues)


def test_verify_detects_seq_skip(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append("a", {})
    log.append("b", {})
    log.append("c", {})

    # Drop the middle record entirely — seq jumps 1 -> 3.
    lines = p.read_text().splitlines()
    p.write_text(lines[0] + "\n" + lines[2] + "\n")

    result = verify_chain(p)
    assert result.ok is False
    assert any("seq" in i for i in result.issues)


def test_verify_detects_prev_hash_mismatch(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append("a", {})
    log.append("b", {})

    # Replace prev_hash on record 2 with a bogus value
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["prev_hash"] = "f" * 64
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")

    result = verify_chain(p)
    assert result.ok is False
    assert any("prev_hash mismatch" in i for i in result.issues)


def test_verify_detects_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append("a", {})
    p.write_text(p.read_text() + "{not valid json\n")

    result = verify_chain(p)
    assert result.ok is False
    assert any("malformed JSON" in i for i in result.issues)


def test_audit_log_existing_tests_still_pass(tmp_path: Path) -> None:
    """The legacy assertions on payload/event_type/timestamp still hold."""
    log = AuditLog(tmp_path / "a.jsonl")
    rec = log.append("test.event", {"foo": "bar"})
    assert rec["event_type"] == "test.event"
    assert rec["payload"] == {"foo": "bar"}
    assert "timestamp" in rec
