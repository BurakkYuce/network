from pathlib import Path

import pytest

from netauto.audit.log import AuditLog
from netauto.collector.runner import Collector, CollectorError
from netauto.inventory.facts import Device
from netauto.state.store import StateStore


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "genie_learn"


@pytest.fixture
def collector(tmp_path: Path, fixtures_dir: Path) -> tuple[Collector, StateStore, AuditLog]:
    store = StateStore(f"sqlite:///{tmp_path}/test.db", create_schema=True)
    audit = AuditLog(tmp_path / "audit.jsonl")
    snapshots = tmp_path / "snapshots"
    return Collector(store, audit, snapshots, fixtures_dir), store, audit


def test_collect_mock_device_from_fixture(
    collector: tuple[Collector, StateStore, AuditLog],
) -> None:
    coll, store, audit = collector
    device = Device(hostname="r1-mock", platform="mock", role="edge")
    state, snap_id = coll.collect(device)

    assert state.hostname == "r1-mock"
    assert state.platform == "ios-xe"  # normalize_ios_xe sets platform per its scope
    assert "GigabitEthernet0/0" in state.interfaces
    assert "admin" in state.users
    assert "EDGE-IN" in state.acls
    assert snap_id > 0

    records = audit.read_all()
    assert len(records) == 1
    assert records[0]["event_type"] == "state.collected"
    assert records[0]["payload"]["device"] == "r1-mock"
    assert records[0]["payload"]["interfaces_count"] == 3
    assert records[0]["payload"]["users_count"] == 3
    assert records[0]["payload"]["acls_count"] == 2

    assert store.get_device_id("r1-mock") is not None


def test_collect_unsupported_platform(
    collector: tuple[Collector, StateStore, AuditLog],
) -> None:
    coll, _, _ = collector
    device = Device(hostname="x", platform="asa", role="firewall")
    with pytest.raises(CollectorError, match="unsupported"):
        coll.collect(device)


def test_collect_real_platform_not_yet_implemented(
    collector: tuple[Collector, StateStore, AuditLog],
) -> None:
    coll, _, _ = collector
    device = Device(hostname="r1", platform="ios-xe", role="edge")
    with pytest.raises(CollectorError, match="not yet implemented"):
        coll.collect(device)


def test_collect_mock_without_fixtures_dir(tmp_path: Path) -> None:
    store = StateStore(f"sqlite:///{tmp_path}/test.db", create_schema=True)
    audit = AuditLog(tmp_path / "audit.jsonl")
    coll = Collector(store, audit, tmp_path / "snap", fixtures_dir=None)
    device = Device(hostname="x", platform="mock")
    with pytest.raises(CollectorError, match="fixtures_dir"):
        coll.collect(device)


def test_two_collects_produce_two_snapshots(
    collector: tuple[Collector, StateStore, AuditLog],
) -> None:
    coll, store, _ = collector
    device = Device(hostname="r1-mock", platform="mock", role="edge")
    coll.collect(device)
    coll.collect(device)

    device_id = store.get_device_id("r1-mock")
    assert device_id is not None
    assert store.snapshot_count(device_id) == 2


def test_collect_missing_fixture_returns_empty_state(tmp_path: Path, fixtures_dir: Path) -> None:
    """Mock device with hostname that has no fixture → state has empty interfaces/users/acls."""
    store = StateStore(f"sqlite:///{tmp_path}/test.db", create_schema=True)
    audit = AuditLog(tmp_path / "audit.jsonl")
    coll = Collector(store, audit, tmp_path / "snap", fixtures_dir)
    device = Device(hostname="ghost-mock", platform="mock", role="edge")
    state, _ = coll.collect(device)
    assert state.interfaces == {}
    assert state.users == {}
    assert state.acls == {}
