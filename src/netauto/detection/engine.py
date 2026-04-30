import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from netauto.detection.event import DetectionEvent
from netauto.detection.operators import is_subset, path_glob_match
from netauto.detection.rule import CustomResponse, Rule, SigmaSelection


@dataclass
class EvalContext:
    device_hostname: str
    timestamp: datetime
    rule_versions: dict[str, str] = field(default_factory=dict)


def matches_diff_op(op: dict[str, Any], sel: SigmaSelection) -> bool:
    """Return True if a single JSON Patch op matches the selection clause."""
    if sel.diff_op and op.get("op") not in sel.diff_op:
        return False
    if sel.diff_path:
        path = op.get("path", "")
        if not any(path_glob_match(path, p) for p in sel.diff_path):
            return False
    return not (sel.diff_value is not None and not is_subset(sel.diff_value, op.get("value")))


def actions_for_response(r: CustomResponse) -> list[str]:
    """Project the response config to a flat list of action names."""
    actions: list[str] = []
    if r.alert_siem:
        actions.append("alert_siem")
    if r.notify_slack:
        actions.append("notify_slack")
    if r.notify_teams:
        actions.append("notify_teams")
    if r.page_oncall:
        actions.append("page_oncall")
    if r.snapshot_full_config:
        actions.append("snapshot_full_config")
    if r.auto_rollback and r.auto_rollback.get("enabled"):
        actions.append("auto_rollback")
    if r.trigger_image_integrity_check:
        actions.append("trigger_image_integrity_check")
    return actions


def compute_fingerprint(rule_id: str, device_hostname: str, op: dict[str, Any]) -> str:
    """sha256(rule_id | device | canonical(op))."""
    canonical = json.dumps(op, sort_keys=True, default=str)
    h = hashlib.sha256()
    h.update(rule_id.encode("utf-8"))
    h.update(b"|")
    h.update(device_hostname.encode("utf-8"))
    h.update(b"|")
    h.update(canonical.encode("utf-8"))
    return h.hexdigest()


def eval_rule(diff_ops: list[dict[str, Any]], rule: Rule, ctx: EvalContext) -> list[DetectionEvent]:
    """Evaluate a rule against a diff. Pure function — no I/O, replay-safe."""
    events: list[DetectionEvent] = []
    for op in diff_ops:
        if not matches_diff_op(op, rule.detection.selection):
            continue
        events.append(
            DetectionEvent(
                rule_id=rule.id,
                rule_version=ctx.rule_versions.get(rule.id, ""),
                title=rule.title,
                severity=rule.level,
                attack=rule.custom.attack,
                device_hostname=ctx.device_hostname,
                timestamp=ctx.timestamp,
                diff_op=op,
                fingerprint=compute_fingerprint(rule.id, ctx.device_hostname, op),
                response_actions=actions_for_response(rule.custom.response),
                replay_safe=rule.custom.replay_safe,
            )
        )
    return events


def eval_rules(
    diff_ops: list[dict[str, Any]],
    rules: list[tuple[Rule, str]],
    ctx: EvalContext,
) -> list[DetectionEvent]:
    """Evaluate every rule against the diff and concatenate events."""
    versions = {rule.id: version for rule, version in rules}
    ctx_with_versions = EvalContext(
        device_hostname=ctx.device_hostname,
        timestamp=ctx.timestamp,
        rule_versions={**ctx.rule_versions, **versions},
    )
    out: list[DetectionEvent] = []
    for rule, _ in rules:
        out.extend(eval_rule(diff_ops, rule, ctx_with_versions))
    return out
