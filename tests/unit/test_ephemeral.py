from pathlib import Path

import pytest

from netauto.state.ephemeral import (
    load_ephemeral_patterns,
    path_matches,
    strip_ephemeral,
)


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        (["interfaces", "Gi0/0", "counters"], ["interfaces", "*", "counters"], True),
        (["interfaces", "Gi0/1", "counters"], ["interfaces", "*", "counters"], True),
        (["interfaces", "Gi0/0", "description"], ["interfaces", "*", "counters"], False),
        (["interfaces", "Gi0/0"], ["interfaces", "*", "counters"], False),
        (["bgp", "neighbors", "10.0.0.1", "uptime"], ["bgp", "neighbors", "*", "uptime"], True),
        (["system", "uptime"], ["system", "uptime"], True),
        (["system", "uptime"], ["system", "*"], True),
        (["a", "b"], ["a", "b", "c"], False),
    ],
)
def test_path_matches(path: list[str], pattern: list[str], expected: bool) -> None:
    assert path_matches(path, pattern) is expected


def test_strip_ephemeral_removes_matching_paths() -> None:
    data = {
        "interfaces": {
            "Gi0/0": {"description": "lan", "counters": {"rx": 100, "tx": 200}},
            "Gi0/1": {"description": "wan", "counters": {"rx": 5, "tx": 10}},
        },
        "system": {"uptime": 3600, "hostname": "r1"},
    }
    patterns = [
        ["interfaces", "*", "counters"],
        ["system", "uptime"],
    ]
    result = strip_ephemeral(data, patterns)

    assert result["interfaces"]["Gi0/0"] == {"description": "lan"}
    assert result["interfaces"]["Gi0/1"] == {"description": "wan"}
    assert result["system"] == {"hostname": "r1"}


def test_strip_ephemeral_no_patterns_is_identity() -> None:
    data = {"a": {"b": 1, "c": 2}}
    assert strip_ephemeral(data, []) == data


def test_strip_ephemeral_does_not_mutate_input() -> None:
    data = {"interfaces": {"Gi0/0": {"counters": {"rx": 1}}}}
    original = {"interfaces": {"Gi0/0": {"counters": {"rx": 1}}}}
    patterns = [["interfaces", "*", "counters"]]
    strip_ephemeral(data, patterns)
    assert data == original


def test_strip_ephemeral_handles_lists() -> None:
    data = {"items": [{"v": 1, "counters": {}}, {"v": 2, "counters": {}}]}
    # patterns operate on dict keys; lists pass through, items walked by key path
    # Since list items don't have a "key" in our walker, "items.*.counters" won't match.
    # This test pins that behavior.
    patterns = [["items", "*", "counters"]]
    result = strip_ephemeral(data, patterns)
    assert result == data  # unchanged


def test_load_ephemeral_patterns(tmp_path: Path) -> None:
    p = tmp_path / "ephemeral.yaml"
    p.write_text(
        """
- interfaces.*.counters
- system.uptime
""",
        encoding="utf-8",
    )
    patterns = load_ephemeral_patterns(p)
    assert patterns == [["interfaces", "*", "counters"], ["system", "uptime"]]


def test_load_ephemeral_patterns_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_ephemeral_patterns(tmp_path / "nope.yaml") == []


def test_load_ephemeral_patterns_invalid_format(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("not_a_list: true\n")
    with pytest.raises(ValueError, match="must be a YAML list"):
        load_ephemeral_patterns(p)


def test_load_real_demo_patterns_file() -> None:
    repo = Path(__file__).resolve().parents[2]
    patterns = load_ephemeral_patterns(repo / "config" / "ephemeral_paths.yaml")
    assert len(patterns) > 0
    assert ["interfaces", "*", "counters"] in patterns
    assert ["system", "uptime"] in patterns
