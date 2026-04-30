from datetime import UTC, datetime
from pathlib import Path

import pytest

from netauto.state.models.v1 import DeviceStateV1, Interface, LocalUser
from netauto.state.store import StateStore


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    db = tmp_path / "test.db"
    return StateStore(f"sqlite:///{db}", create_schema=True)


def _state(hostname: str = "r1", **kw: object) -> DeviceStateV1:
    return DeviceStateV1(
        hostname=hostname,
        platform="ios-xe",
        captured_at=kw.pop("captured_at", datetime.now(UTC)),  # type: ignore[arg-type]
        interfaces=kw.pop("interfaces", {}),  # type: ignore[arg-type]
        users=kw.pop("users", {}),  # type: ignore[arg-type]
    )


def test_upsert_device_insert(store: StateStore) -> None:
    id_ = store.upsert_device(
        hostname="r1",
        platform="ios-xe",
        role="edge",
        tier=4,
        criticality=4,
        tags=["dc-east"],
        site="dc-east",
    )
    assert id_ > 0
    assert store.get_device_id("r1") == id_


def test_upsert_device_update_same_hostname(store: StateStore) -> None:
    id1 = store.upsert_device(hostname="r1", platform="ios-xe", role="edge")
    id2 = store.upsert_device(hostname="r1", platform="ios-xe", role="core")
    assert id1 == id2


def test_get_device_id_missing(store: StateStore) -> None:
    assert store.get_device_id("nonexistent") is None


def test_save_and_retrieve_snapshot(store: StateStore) -> None:
    device_id = store.upsert_device(hostname="r1", platform="ios-xe")
    state = _state(
        interfaces={"Gi0/0": Interface(name="Gi0/0", description="lan")},
        users={"admin": LocalUser(name="admin", privilege=15, password_set=True)},
    )
    snap_id = store.save_snapshot(device_id=device_id, state=state)
    assert snap_id > 0

    latest = store.latest_snapshot(device_id)
    assert latest is not None
    assert latest.hostname == "r1"
    assert "Gi0/0" in latest.interfaces
    assert latest.users["admin"].privilege == 15


def test_latest_snapshot_no_data(store: StateStore) -> None:
    device_id = store.upsert_device(hostname="r2", platform="ios-xe")
    assert store.latest_snapshot(device_id) is None


def test_latest_snapshot_picks_most_recent(store: StateStore) -> None:
    device_id = store.upsert_device(hostname="r1", platform="ios-xe")
    state_old = _state(
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        interfaces={"Gi0/0": Interface(name="Gi0/0", description="old")},
    )
    state_new = _state(
        captured_at=datetime(2026, 4, 30, tzinfo=UTC),
        interfaces={"Gi0/0": Interface(name="Gi0/0", description="new")},
    )
    store.save_snapshot(device_id=device_id, state=state_old)
    store.save_snapshot(device_id=device_id, state=state_new)

    latest = store.latest_snapshot(device_id)
    assert latest is not None
    assert latest.interfaces["Gi0/0"].description == "new"


def test_snapshot_count(store: StateStore) -> None:
    device_id = store.upsert_device(hostname="r1", platform="ios-xe")
    assert store.snapshot_count(device_id) == 0
    store.save_snapshot(device_id=device_id, state=_state())
    store.save_snapshot(device_id=device_id, state=_state())
    assert store.snapshot_count(device_id) == 2


def test_alembic_upgrade_head_creates_same_schema(tmp_path: Path) -> None:
    """End-to-end: alembic upgrade head produces a usable schema."""
    from alembic import command
    from alembic.config import Config

    repo_root = Path(__file__).resolve().parents[2]
    db = tmp_path / "alembic.db"
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    cfg.set_main_option("script_location", str(repo_root / "ops" / "alembic"))
    command.upgrade(cfg, "head")

    store = StateStore(f"sqlite:///{db}", create_schema=False)
    device_id = store.upsert_device(hostname="x", platform="ios-xe")
    store.save_snapshot(device_id=device_id, state=_state(hostname="x"))
    assert store.latest_snapshot(device_id) is not None
