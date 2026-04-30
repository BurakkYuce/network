import textwrap
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from netauto.detection.rule import (
    compute_rule_version,
    load_rule,
    load_rule_with_version,
    load_rules_from_dir,
)

REPO = Path(__file__).resolve().parents[2]


def _minimal_yaml() -> str:
    return textwrap.dedent(
        """
        title: Test rule
        id: NET-T1562.004-001
        description: test
        logsource:
          product: cisco
          service: config-drift
        detection:
          selection:
            diff_op: [add]
          condition: selection
        level: critical
        custom:
          attack:
            tactic: defense-evasion
            technique: T1562
            subtechnique: T1562.004
        """
    )


def test_load_rule_minimal(tmp_path: Path) -> None:
    p = tmp_path / "r.yaml"
    p.write_text(_minimal_yaml())
    rule = load_rule(p)
    assert rule.id == "NET-T1562.004-001"
    assert rule.level == "critical"
    assert rule.custom.attack.subtechnique == "T1562.004"


def test_load_rule_with_version_is_deterministic(tmp_path: Path) -> None:
    p = tmp_path / "r.yaml"
    p.write_text(_minimal_yaml())
    _, v1 = load_rule_with_version(p)
    _, v2 = load_rule_with_version(p)
    assert v1 == v2
    assert len(v1) == 64  # sha256 hex


def test_compute_rule_version_changes_with_content() -> None:
    a = compute_rule_version("a")
    b = compute_rule_version("b")
    assert a != b


def test_invalid_rule_id_format(tmp_path: Path) -> None:
    bad = _minimal_yaml().replace("NET-T1562.004-001", "T1562-001")
    p = tmp_path / "r.yaml"
    p.write_text(bad)
    with pytest.raises(ValidationError):
        load_rule(p)


def test_extra_top_level_field_forbidden(tmp_path: Path) -> None:
    data = yaml.safe_load(_minimal_yaml())
    data["unknown_top_level"] = "x"
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(ValidationError):
        load_rule(p)


def test_invalid_level_rejected(tmp_path: Path) -> None:
    bad = _minimal_yaml().replace("level: critical", "level: extreme")
    p = tmp_path / "r.yaml"
    p.write_text(bad)
    with pytest.raises(ValidationError):
        load_rule(p)


def test_load_rules_from_dir_returns_sorted(tmp_path: Path) -> None:
    (tmp_path / "b.yaml").write_text(_minimal_yaml())
    (tmp_path / "a.yaml").write_text(_minimal_yaml().replace("NET-T1562.004-001", "NET-T1556-001"))
    rules = load_rules_from_dir(tmp_path)
    assert [r.id for r, _ in rules] == ["NET-T1556-001", "NET-T1562.004-001"]


def test_load_rules_from_dir_missing_returns_empty(tmp_path: Path) -> None:
    assert load_rules_from_dir(tmp_path / "nope") == []


def test_demo_rule_T1562_004_001_loads() -> None:
    rule, version = load_rule_with_version(
        REPO / "config" / "detections" / "T1562_004_001_acl_permit_any.yaml"
    )
    assert rule.id == "NET-T1562.004-001"
    assert rule.level == "critical"
    assert rule.custom.attack.subtechnique == "T1562.004"
    assert rule.custom.test is not None
    assert rule.custom.response.snapshot_full_config is True
    assert rule.custom.response.auto_rollback == {
        "enabled": True,
        "requires_approval": False,
        "category": "acl",
    }
    assert len(version) == 64


def test_rule_with_response_extra_field_forbidden(tmp_path: Path) -> None:
    data = yaml.safe_load(_minimal_yaml())
    data["custom"]["response"] = {"alert_siem": True, "unknown_action": True}
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(ValidationError):
        load_rule(p)
