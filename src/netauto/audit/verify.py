"""Audit-log hash chain verification.

Reads an audit JSONL file end-to-end and reports any tampering: malformed
JSON, missing/duplicate sequence numbers, broken ``prev_hash`` linkage, or
recomputed ``self_hash`` that no longer matches.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from netauto.audit.chain import GENESIS_PREV_HASH, compute_self_hash


@dataclass
class ChainVerifyResult:
    ok: bool
    total_events: int = 0
    issues: list[str] = field(default_factory=list)


def verify_chain(path: Path | str) -> ChainVerifyResult:
    p = Path(path)
    if not p.exists():
        return ChainVerifyResult(ok=True, total_events=0)

    issues: list[str] = []
    total = 0
    expected_prev = GENESIS_PREV_HASH
    expected_seq = 1

    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            issues.append(f"line {lineno}: malformed JSON ({exc})")
            return ChainVerifyResult(ok=False, total_events=total, issues=issues)
        total += 1

        if event.get("seq") != expected_seq:
            issues.append(f"line {lineno}: seq {event.get('seq')!r} != expected {expected_seq}")
        if event.get("prev_hash") != expected_prev:
            got = (event.get("prev_hash") or "")[:12]
            issues.append(
                f"line {lineno}: prev_hash mismatch — got {got!r}, expected {expected_prev[:12]!r}"
            )
        recorded = event.get("self_hash", "")
        recomputed = compute_self_hash(event)
        if recorded != recomputed:
            issues.append(
                f"line {lineno}: self_hash mismatch — recorded {recorded[:12]!r}, "
                f"recomputed {recomputed[:12]!r} (payload tampered)"
            )

        expected_prev = recorded if recorded else recomputed
        expected_seq += 1

    return ChainVerifyResult(ok=not issues, total_events=total, issues=issues)
