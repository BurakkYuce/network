"""Purple-team end-to-end test for NET-T1562.004-001 (permissive ACL entry).

Loads the rule + scenario from disk, builds pre/post DeviceStateV1, runs the
diff and detection engine, asserts a critical event with correct ATT&CK
metadata.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from netauto.detection.engine import EvalContext, eval_rules
from netauto.detection.rule import load_rule_with_version
from netauto.state.diff import diff_states
from netauto.state.models.v1 import (
    ACL,
    ACLEntry,
    DeviceStateV1,
    Interface,
    LocalUser,
)

REPO = Path(__file__).resolve().parents[2]


def _build_acl(name: str, data: dict[str, Any]) -> ACL:
    entries = [ACLEntry(**e) for e in data.get("entries", [])]
    return ACL(name=name, type=data.get("type", "extended"), entries=entries)


def _build_state(device: dict[str, str], section: dict[str, Any]) -> DeviceStateV1:
    acls = {n: _build_acl(n, d) for n, d in (section.get("acls") or {}).items()}
    interfaces = {n: Interface(name=n, **d) for n, d in (section.get("interfaces") or {}).items()}
    users = {n: LocalUser(name=n, **d) for n, d in (section.get("users") or {}).items()}
    return DeviceStateV1(
        hostname=device["hostname"],
        platform=device["platform"],  # type: ignore[arg-type]
        captured_at=datetime.now(UTC),
        acls=acls,
        interfaces=interfaces,
        users=users,
    )


def test_T1562_004_001_acl_permit_any_any() -> None:
    rule_path = REPO / "config" / "detections" / "T1562_004_001_acl_permit_any.yaml"
    scenario_path = REPO / "tests" / "fixtures" / "attack_scenarios" / "T1562_004_001.yaml"

    rule, version = load_rule_with_version(rule_path)
    scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))

    pre = _build_state(scenario["device"], scenario["pre_state"])
    post = _build_state(scenario["device"], scenario["post_state"])

    diff = diff_states(pre, post)
    assert not diff.is_empty, "scenario must produce a non-empty diff"

    ctx = EvalContext(
        device_hostname=scenario["device"]["hostname"],
        timestamp=datetime.now(UTC),
    )
    events = eval_rules(diff.ops, [(rule, version)], ctx)

    expected = scenario["expectations"]["events"]
    assert len(events) == len(expected), (
        f"expected {len(expected)} events, got {len(events)}: {[e.rule_id for e in events]}"
    )

    for ev, exp in zip(events, expected, strict=True):
        assert ev.rule_id == exp["rule_id"]
        assert ev.severity == exp["severity"]
        assert ev.attack.technique == exp["attack_technique"]
        assert ev.attack.subtechnique == exp["attack_subtechnique"]
        assert ev.diff_op["path"] == exp["diff_op_path"]
        assert ev.rule_version == version
        assert ev.fingerprint  # set
        assert "alert_siem" in ev.response_actions
        assert "auto_rollback" in ev.response_actions
        assert ev.replay_safe is True


def test_T1562_004_001_does_not_fire_when_only_legitimate_change() -> None:
    """Adding a *scoped* permit (tcp/443 from 10.0.0.0/8) should NOT fire."""
    rule_path = REPO / "config" / "detections" / "T1562_004_001_acl_permit_any.yaml"
    rule, version = load_rule_with_version(rule_path)

    pre = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime.now(UTC),
        acls={
            "EDGE-IN": ACL(
                name="EDGE-IN",
                entries=[
                    ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any"),
                    ACLEntry(seq=20, action="deny", proto="ip", src="any", dst="any"),
                ],
            )
        },
    )
    post = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime.now(UTC),
        acls={
            "EDGE-IN": ACL(
                name="EDGE-IN",
                entries=[
                    ACLEntry(
                        seq=5,
                        action="permit",
                        proto="tcp",
                        src="10.0.0.0/8",
                        dst="any",
                        dst_port="443",
                    ),
                    ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any"),
                    ACLEntry(seq=20, action="deny", proto="ip", src="any", dst="any"),
                ],
            )
        },
    )

    diff = diff_states(pre, post)
    ctx = EvalContext(device_hostname="r1", timestamp=datetime.now(UTC))
    events = eval_rules(diff.ops, [(rule, version)], ctx)
    assert events == [], f"rule should not fire on scoped permit; got {events}"
