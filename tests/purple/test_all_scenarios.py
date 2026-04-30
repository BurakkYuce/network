"""Generic purple-team scenario runner.

Discovers every YAML in ``tests/fixtures/attack_scenarios/`` and runs it
through the full pipeline (build pre/post DeviceStateV1 → diff_states →
eval_rules) against the ATT&CK rule set in ``config/detections/``.

Adding a new rule = drop a rule YAML + a scenario YAML; this test picks
both up automatically. The rule referenced by each scenario is resolved
by ``rule_id`` from ``expectations.events[*].rule_id`` — no path-coupling
in the scenario file.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from netauto.detection.engine import EvalContext, eval_rules
from netauto.detection.rule import load_rule_with_version
from netauto.state.diff import diff_states
from netauto.state.models.v1 import (
    ACL,
    AAAConfig,
    AAAMethodList,
    AAAServer,
    ACLEntry,
    BootConfig,
    DeviceStateV1,
    Interface,
    LineConfig,
    LocalUser,
    LoggingConfig,
    LoggingHost,
    SNMPCommunity,
    SNMPConfig,
    SNMPHost,
)

REPO = Path(__file__).resolve().parents[2]
SCENARIOS_DIR = REPO / "tests" / "fixtures" / "attack_scenarios"
RULES_DIR = REPO / "config" / "detections"

SCENARIO_FILES = sorted(SCENARIOS_DIR.glob("*.yaml"))


def _build_aaa(data: dict[str, Any] | None) -> AAAConfig | None:
    if data is None:
        return None
    return AAAConfig(
        servers=[AAAServer(**s) for s in data.get("servers", [])],
        method_lists=[AAAMethodList(**m) for m in data.get("method_lists", [])],
    )


def _build_logging(data: dict[str, Any] | None) -> LoggingConfig | None:
    if data is None:
        return None
    return LoggingConfig(
        enabled=data.get("enabled", True),
        hosts=[LoggingHost(**h) for h in data.get("hosts", [])],
        facility=data.get("facility"),
        buffered_size=data.get("buffered_size"),
    )


def _build_snmp(data: dict[str, Any] | None) -> SNMPConfig | None:
    if data is None:
        return None
    return SNMPConfig(
        communities=[SNMPCommunity(**c) for c in data.get("communities", [])],
        hosts=[SNMPHost(**h) for h in data.get("hosts", [])],
    )


def _build_boot(data: dict[str, Any] | None) -> BootConfig | None:
    if data is None:
        return None
    return BootConfig(
        boot_system=list(data.get("boot_system") or []),
        confreg=data.get("confreg"),
        rommon_vars=dict(data.get("rommon_vars") or {}),
    )


def _build_interfaces(data: dict[str, Any] | None) -> dict[str, Interface]:
    if not data:
        return {}
    return {n: Interface(name=n, **(d or {})) for n, d in data.items()}


def _build_users(data: dict[str, Any] | None) -> dict[str, LocalUser]:
    if not data:
        return {}
    return {n: LocalUser(name=n, **(d or {})) for n, d in data.items()}


def _build_acls(data: dict[str, Any] | None) -> dict[str, ACL]:
    if not data:
        return {}
    out: dict[str, ACL] = {}
    for name, d in data.items():
        entries = [ACLEntry(**e) for e in (d or {}).get("entries", [])]
        out[name] = ACL(name=name, type=(d or {}).get("type", "extended"), entries=entries)
    return out


def _build_lines(data: dict[str, Any] | None) -> dict[str, LineConfig]:
    if not data:
        return {}
    return {n: LineConfig(**(d or {})) for n, d in data.items()}


def _build_state(device: dict[str, str], section: dict[str, Any]) -> DeviceStateV1:
    return DeviceStateV1(
        hostname=device["hostname"],
        platform=device["platform"],  # type: ignore[arg-type]
        captured_at=datetime.now(UTC),
        interfaces=_build_interfaces(section.get("interfaces")),
        users=_build_users(section.get("users")),
        acls=_build_acls(section.get("acls")),
        aaa=_build_aaa(section.get("aaa")),
        logging=_build_logging(section.get("logging")),
        snmp=_build_snmp(section.get("snmp")),
        lines=_build_lines(section.get("lines")),
        boot=_build_boot(section.get("boot")),
    )


def _build_rule_index() -> dict[str, Path]:
    """Map rule_id (from each rule YAML) to its file path on disk."""
    index: dict[str, Path] = {}
    for rule_path in RULES_DIR.glob("*.yaml"):
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        index[data["id"]] = rule_path
    return index


_RULE_INDEX = _build_rule_index()


@pytest.mark.parametrize(
    "scenario_path",
    SCENARIO_FILES,
    ids=[p.stem for p in SCENARIO_FILES],
)
def test_attack_scenario(scenario_path: Path) -> None:
    scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))

    expected_events = scenario["expectations"]["events"]
    assert expected_events, f"{scenario_path.name}: must declare at least one expected event"

    rule_id = expected_events[0]["rule_id"]
    rule_path = _RULE_INDEX.get(rule_id)
    assert rule_path is not None, f"{scenario_path.name}: rule {rule_id} not found in {RULES_DIR}"

    rule, version = load_rule_with_version(rule_path)
    pre = _build_state(scenario["device"], scenario.get("pre_state") or {})
    post = _build_state(scenario["device"], scenario.get("post_state") or {})

    diff = diff_states(pre, post)
    assert not diff.is_empty, f"{scenario_path.name}: pre/post produced no diff"

    ctx = EvalContext(device_hostname=scenario["device"]["hostname"], timestamp=datetime.now(UTC))
    events = eval_rules(diff.ops, [(rule, version)], ctx)

    matching = [e for e in events if e.rule_id == rule_id]
    assert matching, (
        f"{scenario_path.name}: rule {rule_id} did not fire. "
        f"Diff ops: {[op.get('path') for op in diff.ops]}"
    )

    for ev, exp in zip(matching, expected_events, strict=False):
        assert ev.rule_id == exp["rule_id"]
        assert ev.severity == exp["severity"]
        if "attack_technique" in exp:
            assert ev.attack.technique == exp["attack_technique"]
        if "attack_subtechnique" in exp:
            assert ev.attack.subtechnique == exp["attack_subtechnique"]
        assert ev.fingerprint
        assert ev.rule_version == version


def test_every_rule_has_a_scenario() -> None:
    """Coverage assertion: every rule YAML must have a matching scenario."""
    rule_ids = set(_RULE_INDEX.keys())
    scenario_rule_ids = set()
    for sp in SCENARIO_FILES:
        s = yaml.safe_load(sp.read_text(encoding="utf-8"))
        for ev in s["expectations"]["events"]:
            scenario_rule_ids.add(ev["rule_id"])
    missing = rule_ids - scenario_rule_ids
    assert not missing, f"rules without a purple-team scenario: {sorted(missing)}"


def test_every_scenario_references_an_existing_rule() -> None:
    """Coverage assertion: every scenario points at a rule that exists."""
    for sp in SCENARIO_FILES:
        s = yaml.safe_load(sp.read_text(encoding="utf-8"))
        for ev in s["expectations"]["events"]:
            assert ev["rule_id"] in _RULE_INDEX, f"{sp.name}: rule {ev['rule_id']} not found"
