"""Detection rule DSL — Sigma 2.0-shaped header + ``custom:`` namespace.

For Faz 1c the rule is validated with Pydantic only (pySigma compat lands
later). The on-disk shape preserves Sigma section names so a future compat
layer can compile to/from sigma rules without restructuring.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from netauto.detection.attack import AttackMetadata

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
RULE_ID_RE = re.compile(r"^NET-T\d{4}(\.\d{3})?-\d{3}$")


class SigmaSelection(BaseModel):
    """Match clause for a single diff op (one JSON Patch entry)."""

    model_config = ConfigDict(extra="forbid")

    diff_path: list[str] = Field(
        default_factory=list,
        description="Glob patterns matched against the JSON Pointer path of "
        "each diff op. '*' matches a single path segment.",
    )
    diff_op: list[str] = Field(
        default_factory=list,
        description="Allowed JSON Patch op types (add|remove|replace|move|copy).",
    )
    diff_value: dict[str, Any] | None = Field(
        default=None,
        description="Subset match against op['value']: every key/value here "
        "must equal the corresponding key in the op's value.",
    )


class SigmaDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selection: SigmaSelection
    condition: str = Field(default="selection")


class SigmaLogsource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product: str
    service: str


class CustomResponse(BaseModel):
    """Orchestration actions to dispatch when the rule fires."""

    model_config = ConfigDict(extra="forbid")

    alert_siem: bool = True
    notify_slack: dict[str, str] | None = None
    notify_teams: dict[str, str] | None = None
    page_oncall: dict[str, str] | None = None
    snapshot_full_config: bool = False
    auto_rollback: dict[str, Any] | None = None
    trigger_image_integrity_check: bool = False


class CustomTest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str


class CustomBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack: AttackMetadata
    response: CustomResponse = Field(default_factory=CustomResponse)
    fingerprint: dict[str, Any] | None = None
    test: CustomTest | None = None
    replay_safe: bool = True


class Rule(BaseModel):
    """A detection rule. Sigma-shaped header + custom: orchestration block."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=RULE_ID_RE.pattern)
    title: str
    status: str = "experimental"
    description: str
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    logsource: SigmaLogsource
    detection: SigmaDetection
    falsepositives: list[str] = Field(default_factory=list)
    level: SeverityLevel
    custom: CustomBlock


def compute_rule_version(yaml_text: str) -> str:
    """Deterministic content-addressed version for a rule YAML."""
    return hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()


def load_rule(path: Path | str) -> Rule:
    """Parse one Sigma+custom YAML file into a Rule."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    return Rule.model_validate(raw)


def load_rule_with_version(path: Path | str) -> tuple[Rule, str]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    rule = Rule.model_validate(yaml.safe_load(text))
    return rule, compute_rule_version(text)


def load_rules_from_dir(directory: Path | str) -> list[tuple[Rule, str]]:
    """Load all *.yaml rules from a directory, sorted by filename.

    Returns list of (rule, version_sha256) pairs.
    """
    d = Path(directory)
    if not d.exists():
        return []
    return [load_rule_with_version(p) for p in sorted(d.glob("*.yaml"))]
