import textwrap
from pathlib import Path

import pytest

from netauto.inventory.loader import InventoryError, load_testbed


def _write_testbed(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "testbed.yaml"
    p.write_text(textwrap.dedent(body))
    return p


def test_load_testbed_basic(tmp_path: Path) -> None:
    p = _write_testbed(
        tmp_path,
        """
        devices:
          r1:
            os: ios-xe
            custom:
              netauto:
                role: edge
                tier: 4
                criticality: 5
                tags: [dc-east, perimeter]
                site: dc-east
          r2:
            os: nx-os
            custom:
              netauto:
                role: core
        """,
    )
    devs = load_testbed(p)
    assert len(devs) == 2
    by_name = {d.hostname: d for d in devs}

    r1 = by_name["r1"]
    assert r1.platform == "ios-xe"
    assert r1.role == "edge"
    assert r1.tier == 4
    assert r1.criticality == 5
    assert r1.tags == ["dc-east", "perimeter"]
    assert r1.site == "dc-east"

    r2 = by_name["r2"]
    assert r2.platform == "nx-os"
    assert r2.role == "core"
    assert r2.tier == 3
    assert r2.criticality == 3
    assert r2.tags == []
    assert r2.site is None


def test_load_testbed_no_custom_block(tmp_path: Path) -> None:
    p = _write_testbed(
        tmp_path,
        """
        devices:
          r1:
            os: ios-xe
        """,
    )
    devs = load_testbed(p)
    assert len(devs) == 1
    assert devs[0].role == "unknown"
    assert devs[0].tier == 3


def test_load_testbed_no_os_falls_back_to_mock(tmp_path: Path) -> None:
    p = _write_testbed(
        tmp_path,
        """
        devices:
          r1: {}
        """,
    )
    devs = load_testbed(p)
    assert devs[0].platform == "mock"


def test_load_testbed_empty_devices(tmp_path: Path) -> None:
    p = _write_testbed(tmp_path, "devices: {}\n")
    devs = load_testbed(p)
    assert devs == []


def test_load_testbed_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "does-not-exist.yaml"
    with pytest.raises(InventoryError, match="not found"):
        load_testbed(p)


def test_load_testbed_devices_not_mapping(tmp_path: Path) -> None:
    p = _write_testbed(tmp_path, "devices:\n  - r1\n  - r2\n")
    with pytest.raises(InventoryError, match="must be a mapping"):
        load_testbed(p)


def test_load_testbed_with_maintenance(tmp_path: Path) -> None:
    p = _write_testbed(
        tmp_path,
        """
        devices:
          r1:
            os: ios-xe
            custom:
              netauto:
                role: edge
                maintenance:
                  active: true
                  until: 2026-12-31T22:00:00Z
                  reason: "scheduled upgrade"
                  suppress_severity_max: high
        """,
    )
    devs = load_testbed(p)
    m = devs[0].maintenance
    assert m is not None
    assert m.active is True
    assert m.reason == "scheduled upgrade"
    assert m.suppress_severity_max == "high"


def test_load_testbed_real_demo_fixture() -> None:
    repo = Path(__file__).resolve().parents[2]
    testbed = repo / "config" / "inventory" / "testbed.yaml"
    devs = load_testbed(testbed)
    names = {d.hostname for d in devs}
    assert {"r1-mock", "r2-mock", "fw1-mock"} <= names
