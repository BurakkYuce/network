import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# A subset of MITRE ATT&CK enterprise tactics relevant to network device threats.
AttackTactic = Literal[
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_TECHNIQUE_RE = re.compile(r"^T\d{4}$")
_SUBTECHNIQUE_RE = re.compile(r"^T\d{4}\.\d{3}$")


class AttackMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactic: AttackTactic
    technique: str = Field(description="ATT&CK technique id, e.g. T1562")
    subtechnique: str | None = Field(
        default=None, description="ATT&CK subtechnique id, e.g. T1562.004"
    )

    @field_validator("technique")
    @classmethod
    def _validate_technique(cls, v: str) -> str:
        if not _TECHNIQUE_RE.match(v):
            raise ValueError(f"technique must match T####, got {v!r}")
        return v

    @field_validator("subtechnique")
    @classmethod
    def _validate_subtechnique(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _SUBTECHNIQUE_RE.match(v):
            raise ValueError(f"subtechnique must match T####.###, got {v!r}")
        return v
