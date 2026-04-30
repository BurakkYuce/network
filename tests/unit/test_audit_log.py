import json
from pathlib import Path

from netauto.audit.log import AuditLog


def test_audit_log_append(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    record = log.append("test.event", {"foo": "bar"})
    assert record["event_type"] == "test.event"
    assert record["payload"] == {"foo": "bar"}
    assert "timestamp" in record


def test_audit_log_read_all(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("a", {"x": 1})
    log.append("b", {"y": 2})
    records = log.read_all()
    assert len(records) == 2
    assert records[0]["event_type"] == "a"
    assert records[1]["event_type"] == "b"
    assert records[0]["payload"] == {"x": 1}


def test_audit_log_read_empty(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.read_all() == []


def test_audit_log_creates_parent_dir(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "deep" / "nested" / "audit.jsonl")
    log.append("x", {})
    assert (tmp_path / "deep" / "nested" / "audit.jsonl").exists()


def test_audit_log_jsonl_format(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append("a", {"x": 1})
    log.append("b", {"y": 2})

    lines = p.read_text().splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)


def test_audit_log_persists_across_instances(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    AuditLog(p).append("first", {})
    AuditLog(p).append("second", {})

    records = AuditLog(p).read_all()
    assert [r["event_type"] for r in records] == ["first", "second"]
