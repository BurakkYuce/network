from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Platform = Literal["ios", "ios-xe", "ios-xr", "nx-os", "asa", "ftd", "mock"]
SeverityLevel = Literal["info", "low", "medium", "high", "critical"]


class Maintenance(BaseModel):
    active: bool = False
    until: datetime | None = None
    reason: str | None = None
    suppress_severity_max: SeverityLevel | None = None


class Device(BaseModel):
    hostname: str
    platform: Platform
    role: str = "unknown"
    tier: int = Field(default=3, ge=1, le=5)
    criticality: int = Field(default=3, ge=1, le=5)
    tags: list[str] = Field(default_factory=list)
    site: str | None = None
    maintenance: Maintenance | None = None

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def is_in_maintenance(self, now: datetime | None = None) -> bool:
        if self.maintenance is None or not self.maintenance.active:
            return False
        if self.maintenance.until is None:
            return True
        ts = now or datetime.now(self.maintenance.until.tzinfo)
        return ts < self.maintenance.until
