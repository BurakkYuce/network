from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from netauto.inventory.facts import Device, Maintenance


def test_device_defaults() -> None:
    d = Device(hostname="x", platform="ios-xe")
    assert d.role == "unknown"
    assert d.tier == 3
    assert d.criticality == 3
    assert d.tags == []
    assert d.site is None
    assert d.maintenance is None


def test_device_full() -> None:
    d = Device(
        hostname="rtr1",
        platform="ios-xe",
        role="edge",
        tier=4,
        criticality=5,
        tags=["dc-east", "perimeter"],
        site="dc-east",
    )
    assert d.role == "edge"
    assert d.tier == 4
    assert d.criticality == 5
    assert d.has_tag("dc-east") is True
    assert d.has_tag("missing") is False


@pytest.mark.parametrize("tier", [0, 6, 100])
def test_tier_out_of_range(tier: int) -> None:
    with pytest.raises(ValidationError):
        Device(hostname="x", platform="ios-xe", tier=tier)


@pytest.mark.parametrize("crit", [0, 6, -1])
def test_criticality_out_of_range(crit: int) -> None:
    with pytest.raises(ValidationError):
        Device(hostname="x", platform="ios-xe", criticality=crit)


def test_invalid_platform() -> None:
    with pytest.raises(ValidationError):
        Device(hostname="x", platform="cisco-xyz")  # type: ignore[arg-type]


def test_maintenance_inactive_means_not_in_maintenance() -> None:
    d = Device(hostname="x", platform="ios-xe", maintenance=Maintenance(active=False))
    assert d.is_in_maintenance() is False


def test_maintenance_active_no_until_means_in_maintenance() -> None:
    d = Device(hostname="x", platform="ios-xe", maintenance=Maintenance(active=True))
    assert d.is_in_maintenance() is True


def test_maintenance_active_until_in_future() -> None:
    future = datetime.now(UTC) + timedelta(hours=1)
    d = Device(
        hostname="x",
        platform="ios-xe",
        maintenance=Maintenance(active=True, until=future),
    )
    assert d.is_in_maintenance() is True


def test_maintenance_active_until_in_past() -> None:
    past = datetime.now(UTC) - timedelta(hours=1)
    d = Device(
        hostname="x",
        platform="ios-xe",
        maintenance=Maintenance(active=True, until=past),
    )
    assert d.is_in_maintenance() is False
