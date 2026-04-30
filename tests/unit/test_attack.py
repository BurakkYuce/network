import pytest
from pydantic import ValidationError

from netauto.detection.attack import AttackMetadata


def test_attack_metadata_minimal() -> None:
    a = AttackMetadata(tactic="defense-evasion", technique="T1562")
    assert a.subtechnique is None


def test_attack_metadata_full() -> None:
    a = AttackMetadata(tactic="defense-evasion", technique="T1562", subtechnique="T1562.004")
    assert a.subtechnique == "T1562.004"


def test_attack_metadata_invalid_technique() -> None:
    with pytest.raises(ValidationError, match="must match T####"):
        AttackMetadata(tactic="defense-evasion", technique="T123")


def test_attack_metadata_invalid_subtechnique() -> None:
    with pytest.raises(ValidationError, match="must match T####\\.###"):
        AttackMetadata(tactic="defense-evasion", technique="T1562", subtechnique="T1562.04")


def test_attack_metadata_invalid_tactic() -> None:
    with pytest.raises(ValidationError):
        AttackMetadata(tactic="not-a-tactic", technique="T1562")  # type: ignore[arg-type]


def test_attack_metadata_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        AttackMetadata(tactic="defense-evasion", technique="T1562", unknown="x")  # type: ignore[call-arg]
