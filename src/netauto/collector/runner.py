import json
from datetime import UTC, datetime
from pathlib import Path

from netauto.audit.log import AuditLog
from netauto.inventory.facts import Device
from netauto.state.canonical import DeviceState
from netauto.state.normalize.ios_xe import normalize_ios_xe
from netauto.state.store import StateStore


class CollectorError(Exception):
    pass


class Collector:
    """Read-only state collector.

    Faz 1a: mock devices read pre-recorded Genie JSON from ``fixtures_dir``.
    Real platforms (ios-xe etc.) raise — pyATS connect lands in Faz 7+ with
    worker pool + per-device affinity.
    """

    def __init__(
        self,
        store: StateStore,
        audit: AuditLog,
        snapshots_dir: Path,
        fixtures_dir: Path | None = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self.snapshots_dir = snapshots_dir
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.fixtures_dir = fixtures_dir

    def collect(self, device: Device) -> tuple[DeviceState, int]:
        if device.platform == "mock":
            state = self._collect_from_fixture(device)
        elif device.platform in ("ios-xe", "ios-xr", "nx-os", "ios"):
            state = self._collect_via_pyats(device)
        else:
            raise CollectorError(f"unsupported platform for Faz 1a: {device.platform}")

        device_id = self.store.upsert_device(
            hostname=device.hostname,
            platform=device.platform,
            role=device.role,
            tier=device.tier,
            criticality=device.criticality,
            tags=list(device.tags),
            site=device.site,
        )
        snapshot_id = self.store.save_snapshot(device_id=device_id, state=state)

        self.audit.append(
            "state.collected",
            {
                "device": device.hostname,
                "platform": device.platform,
                "snapshot_id": snapshot_id,
                "schema_version": state.schema_version,
                "captured_at": state.captured_at.isoformat(),
                "interfaces_count": len(state.interfaces),
                "users_count": len(state.users),
                "acls_count": len(state.acls),
            },
        )
        return state, snapshot_id

    def _collect_from_fixture(self, device: Device) -> DeviceState:
        if self.fixtures_dir is None:
            raise CollectorError(
                f"mock device {device.hostname} requires fixtures_dir to be configured"
            )
        intf_path = self.fixtures_dir / f"{device.hostname}_interface.json"
        cfg_path = self.fixtures_dir / f"{device.hostname}_running_config.json"
        intf = json.loads(intf_path.read_text()) if intf_path.exists() else {}
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        return normalize_ios_xe(
            hostname=device.hostname,
            interfaces=intf,
            parsed_config=cfg,
            captured_at=datetime.now(UTC),
        )

    def _collect_via_pyats(self, device: Device) -> DeviceState:
        raise CollectorError(
            "pyATS connect — not yet implemented (Faz 1a; comes in Faz 7+ with worker pool)"
        )
