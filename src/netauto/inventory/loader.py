from pathlib import Path
from typing import Any

import yaml

from netauto.inventory.facts import Device, Maintenance


class InventoryError(Exception):
    pass


def load_testbed(path: Path | str) -> list[Device]:
    """Load a pyATS-compatible testbed.yaml and extract netauto facts.

    Each device entry may include `custom.netauto.{role,tier,criticality,tags,site,maintenance}`.
    Missing custom fields fall back to Device defaults.
    """
    p = Path(path)
    if not p.exists():
        raise InventoryError(f"testbed file not found: {p}")

    raw: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
    devices_raw = raw.get("devices", {})
    if not isinstance(devices_raw, dict):
        raise InventoryError(f"testbed.devices must be a mapping, got {type(devices_raw).__name__}")

    devices: list[Device] = []
    for hostname, entry in devices_raw.items():
        entry = entry or {}
        platform = entry.get("os", "mock")
        custom = (entry.get("custom") or {}).get("netauto", {}) or {}

        maintenance: Maintenance | None = None
        if "maintenance" in custom and custom["maintenance"] is not None:
            maintenance = Maintenance(**custom["maintenance"])

        devices.append(
            Device(
                hostname=hostname,
                platform=platform,
                role=custom.get("role", "unknown"),
                tier=custom.get("tier", 3),
                criticality=custom.get("criticality", 3),
                tags=custom.get("tags", []) or [],
                site=custom.get("site"),
                maintenance=maintenance,
            )
        )
    return devices
