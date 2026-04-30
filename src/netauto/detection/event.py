from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from netauto.detection.attack import AttackMetadata
from netauto.detection.rule import SeverityLevel


class DetectionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_version: str
    title: str
    severity: SeverityLevel
    attack: AttackMetadata
    device_hostname: str
    timestamp: datetime
    diff_op: dict[str, Any]
    fingerprint: str
    response_actions: list[str]
    replay_safe: bool = True
