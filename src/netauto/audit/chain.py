"""SHA-256 hash chain primitives for the audit log.

Each appended record carries ``prev_hash`` (the previous record's
``self_hash``) and ``self_hash`` (sha256 of its own canonical body
excluding the ``self_hash`` field itself). The first record points at
``GENESIS_PREV_HASH`` (64 zero hex chars).

Tampering with any record's payload — or removing/inserting a record —
breaks the chain: ``audit/verify.py`` recomputes every ``self_hash`` and
checks that ``prev_hash`` matches the predecessor.
"""

import hashlib
import json
from typing import Any

GENESIS_PREV_HASH: str = "0" * 64


def canonical_body(event: dict[str, Any]) -> bytes:
    """Return canonical bytes used for hashing.

    ``self_hash`` is excluded so the hash can be computed before/after the
    field is set. Keys are sorted; numbers/strings are JSON-default.
    """
    body = {k: v for k, v in event.items() if k != "self_hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_self_hash(event: dict[str, Any]) -> str:
    """sha256 hex digest of ``canonical_body(event)``."""
    return hashlib.sha256(canonical_body(event)).hexdigest()


def link(prev_hash: str, event: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``event`` with ``prev_hash`` and ``self_hash`` set."""
    out = dict(event)
    out["prev_hash"] = prev_hash
    out["self_hash"] = compute_self_hash(out)
    return out
