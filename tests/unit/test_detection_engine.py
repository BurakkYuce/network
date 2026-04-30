from datetime import UTC, datetime
from pathlib import Path

import pytest

from netauto.detection.attack import AttackMetadata
from netauto.detection.engine import (
    EvalContext,
    actions_for_response,
    compute_fingerprint,
    eval_rule,
    eval_rules,
    matches_diff_op,
)
from netauto.detection.rule import (
    CustomBlock,
    CustomResponse,
    Rule,
    SigmaDetection,
    SigmaLogsource,
    SigmaSelection,
    load_rule_with_version,
)

REPO = Path(__file__).resolve().parents[2]


def _build_rule(
    *,
    diff_path: list[str] | None = None,
    diff_op: list[str] | None = None,
    diff_value: dict | None = None,
    response: CustomResponse | None = None,
) -> Rule:
    return Rule(
        id="NET-T1562.004-001",
        title="t",
        description="d",
        logsource=SigmaLogsource(product="cisco", service="config-drift"),
        detection=SigmaDetection(
            selection=SigmaSelection(
                diff_path=diff_path or [],
                diff_op=diff_op or [],
                diff_value=diff_value,
            )
        ),
        level="critical",
        custom=CustomBlock(
            attack=AttackMetadata(
                tactic="defense-evasion", technique="T1562", subtechnique="T1562.004"
            ),
            response=response or CustomResponse(),
        ),
    )


def _ctx() -> EvalContext:
    return EvalContext(device_hostname="r1", timestamp=datetime.now(UTC))


def test_matches_diff_op_path_only() -> None:
    rule = _build_rule(diff_path=["/users/*"])
    assert matches_diff_op({"op": "add", "path": "/users/admin"}, rule.detection.selection)
    assert not matches_diff_op({"op": "add", "path": "/acls/X"}, rule.detection.selection)


def test_matches_diff_op_op_only() -> None:
    rule = _build_rule(diff_op=["remove"])
    assert matches_diff_op({"op": "remove", "path": "/x"}, rule.detection.selection)
    assert not matches_diff_op({"op": "add", "path": "/x"}, rule.detection.selection)


def test_matches_diff_op_value_subset() -> None:
    rule = _build_rule(diff_value={"action": "permit", "src": "any"})
    op_match = {
        "op": "add",
        "path": "/a",
        "value": {"action": "permit", "src": "any", "dst": "any"},
    }
    op_miss = {"op": "add", "path": "/a", "value": {"action": "deny", "src": "any"}}
    assert matches_diff_op(op_match, rule.detection.selection)
    assert not matches_diff_op(op_miss, rule.detection.selection)


def test_matches_diff_op_no_value_when_value_required() -> None:
    rule = _build_rule(diff_value={"action": "permit"})
    op_no_value = {"op": "remove", "path": "/x"}
    assert not matches_diff_op(op_no_value, rule.detection.selection)


def test_matches_diff_op_combined_predicates_all_must_pass() -> None:
    rule = _build_rule(
        diff_path=["/acls/*/entries/*"],
        diff_op=["add"],
        diff_value={"action": "permit", "src": "any"},
    )
    op = {
        "op": "add",
        "path": "/acls/EDGE-IN/entries/5",
        "value": {"action": "permit", "proto": "ip", "src": "any", "dst": "any"},
    }
    assert matches_diff_op(op, rule.detection.selection)
    bad_path = dict(op, path="/users/admin")
    assert not matches_diff_op(bad_path, rule.detection.selection)


def test_eval_rule_emits_event_per_match() -> None:
    rule = _build_rule(
        diff_path=["/acls/*/entries/*"],
        diff_op=["add"],
        diff_value={"action": "permit", "src": "any"},
    )
    diff_ops = [
        {"op": "add", "path": "/acls/A/entries/5", "value": {"action": "permit", "src": "any"}},
        {"op": "remove", "path": "/acls/A/entries/20"},
        {"op": "add", "path": "/acls/B/entries/10", "value": {"action": "permit", "src": "any"}},
        {"op": "add", "path": "/users/admin", "value": {"name": "admin"}},
    ]
    events = eval_rule(diff_ops, rule, _ctx())
    assert len(events) == 2
    assert {e.diff_op["path"] for e in events} == {
        "/acls/A/entries/5",
        "/acls/B/entries/10",
    }


def test_eval_rule_no_match_returns_empty() -> None:
    rule = _build_rule(diff_path=["/never/matches"])
    events = eval_rule([{"op": "add", "path": "/users/admin"}], rule, _ctx())
    assert events == []


def test_event_fingerprint_stable_for_same_inputs() -> None:
    op = {"op": "add", "path": "/users/admin", "value": {"name": "admin", "privilege": 15}}
    fp1 = compute_fingerprint("R1", "r1", op)
    fp2 = compute_fingerprint("R1", "r1", op)
    assert fp1 == fp2
    assert len(fp1) == 64


@pytest.mark.parametrize(
    ("rule_id", "device", "op_overrides"),
    [
        ("R2", "r1", {}),  # different rule
        ("R1", "r2", {}),  # different device
        ("R1", "r1", {"path": "/users/operator"}),  # different op
    ],
)
def test_event_fingerprint_changes_with_inputs(rule_id, device, op_overrides) -> None:
    base_op = {"op": "add", "path": "/users/admin", "value": {"name": "admin"}}
    other_op = {**base_op, **op_overrides}
    fp_base = compute_fingerprint("R1", "r1", base_op)
    fp_other = compute_fingerprint(rule_id, device, other_op)
    assert fp_base != fp_other


def test_actions_for_response_default_minimal() -> None:
    actions = actions_for_response(CustomResponse())
    assert actions == ["alert_siem"]


def test_actions_for_response_full() -> None:
    actions = actions_for_response(
        CustomResponse(
            alert_siem=True,
            notify_slack={"channel": "#x"},
            page_oncall={"service": "pd"},
            snapshot_full_config=True,
            auto_rollback={"enabled": True, "category": "acl"},
            trigger_image_integrity_check=True,
        )
    )
    assert "alert_siem" in actions
    assert "notify_slack" in actions
    assert "page_oncall" in actions
    assert "snapshot_full_config" in actions
    assert "auto_rollback" in actions
    assert "trigger_image_integrity_check" in actions


def test_actions_for_response_disabled_auto_rollback() -> None:
    actions = actions_for_response(
        CustomResponse(auto_rollback={"enabled": False, "category": "acl"})
    )
    assert "auto_rollback" not in actions


def test_eval_rules_aggregates_versions_from_pairs() -> None:
    rule1 = _build_rule(diff_op=["add"], diff_path=["/users/*"])
    rule1.id = "NET-T1078-001"  # type: ignore[misc]
    rule2 = _build_rule(diff_op=["remove"], diff_path=["/users/*"])
    rule2.id = "NET-T1078-002"  # type: ignore[misc]
    diff_ops = [
        {"op": "add", "path": "/users/x"},
        {"op": "remove", "path": "/users/y"},
    ]
    events = eval_rules(
        diff_ops,
        [(rule1, "v_one"), (rule2, "v_two")],
        EvalContext(device_hostname="r1", timestamp=datetime.now(UTC)),
    )
    by_rule = {e.rule_id: e for e in events}
    assert by_rule["NET-T1078-001"].rule_version == "v_one"
    assert by_rule["NET-T1078-002"].rule_version == "v_two"


def test_eval_rules_with_demo_rule_against_synthetic_diff() -> None:
    rule, version = load_rule_with_version(
        REPO / "config" / "detections" / "T1562_004_001_acl_permit_any.yaml"
    )
    diff_ops = [
        {
            "op": "add",
            "path": "/acls/EDGE-IN/entries/5",
            "value": {"action": "permit", "proto": "ip", "src": "any", "dst": "any"},
        }
    ]
    events = eval_rules(diff_ops, [(rule, version)], _ctx())
    assert len(events) == 1
    e = events[0]
    assert e.rule_id == "NET-T1562.004-001"
    assert e.severity == "critical"
    assert e.attack.subtechnique == "T1562.004"
    assert "auto_rollback" in e.response_actions
