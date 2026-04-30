from dataclasses import dataclass, field
from typing import Any

import jsonpatch

from netauto.state.ephemeral import strip_ephemeral
from netauto.state.models.v1 import DeviceStateV1

# Fields that are always stripped before structural diff because they are not
# config drift signal (they vary every collect by definition).
DIFF_IGNORED_TOP_LEVEL = {"captured_at"}


@dataclass
class DiffResult:
    ops: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return len(self.ops) == 0


def state_to_diffable(state: DeviceStateV1) -> dict[str, Any]:
    """Project state to a dict shape suited to JSON Patch comparison.

    ACL entries are reshaped from a list to a dict keyed by ``seq``, so the
    diff path for an entry is stable (``/acls/EDGE-IN/entries/10``) regardless
    of insertions or deletions elsewhere in the list.
    """
    d: dict[str, Any] = state.model_dump(mode="json")
    for ignored in DIFF_IGNORED_TOP_LEVEL:
        d.pop(ignored, None)

    acls = d.get("acls", {}) or {}
    for acl_data in acls.values():
        entries = acl_data.get("entries", []) or []
        acl_data["entries"] = {
            str(entry["seq"]): {k: v for k, v in entry.items() if k != "seq"} for entry in entries
        }
    return d


def diff_states(
    old: DeviceStateV1,
    new: DeviceStateV1,
    ephemeral_patterns: list[list[str]] | None = None,
) -> DiffResult:
    """Compute JSON Patch (RFC 6902) ops between two states.

    Ephemeral patterns are stripped from both sides before diffing.
    """
    old_d = state_to_diffable(old)
    new_d = state_to_diffable(new)
    if ephemeral_patterns:
        old_d = strip_ephemeral(old_d, ephemeral_patterns)
        new_d = strip_ephemeral(new_d, ephemeral_patterns)

    patch = jsonpatch.make_patch(old_d, new_d)
    ops: list[dict[str, Any]] = list(patch)

    summary: dict[str, int] = {}
    for op in ops:
        op_type = str(op.get("op", "unknown"))
        summary[op_type] = summary.get(op_type, 0) + 1
    return DiffResult(ops=ops, summary=summary)
