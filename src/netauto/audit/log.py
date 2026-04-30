import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netauto.audit.chain import GENESIS_PREV_HASH, compute_self_hash


class AuditLog:
    """JSONL append-only audit log with a SHA-256 hash chain.

    Each record carries:
      - ``seq``: monotonic 1-based sequence number
      - ``timestamp``: ISO-8601 UTC
      - ``event_type``: short string identifier
      - ``payload``: caller-supplied dict
      - ``prev_hash``: previous record's ``self_hash`` (genesis = 64x"0")
      - ``self_hash``: sha256 of this record's canonical body
        (everything except ``self_hash`` itself, sorted keys)

    The instance caches the last (hash, seq) in memory so appends are O(1)
    after construction. The constructor scans the file once to recover
    state — this assumes a single writer per file (good enough for demo
    and lab; multi-writer needs an external lock or a DB-backed sequence).
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash, self._last_seq = self._load_tail()

    def _load_tail(self) -> tuple[str, int]:
        if not self.path.exists():
            return GENESIS_PREV_HASH, 0
        last: dict[str, Any] | None = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            last = json.loads(line)
        if last is None:
            return GENESIS_PREV_HASH, 0
        return last["self_hash"], int(last["seq"])

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        seq = self._last_seq + 1
        record: dict[str, Any] = {
            "seq": seq,
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "prev_hash": self._last_hash,
        }
        record["self_hash"] = compute_self_hash(record)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        self._last_hash = record["self_hash"]
        self._last_seq = seq
        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line
        ]
