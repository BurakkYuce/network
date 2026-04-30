import pytest

from netauto.detection.operators import is_subset, path_glob_match


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("/acls/EDGE-IN/entries/5", "/acls/*/entries/*", True),
        ("/acls/EDGE-IN/entries/5", "/acls/EDGE-IN/entries/*", True),
        ("/acls/EDGE-IN/entries/5", "/acls/MGMT-IN/entries/*", False),
        ("/users/admin", "/users/*", True),
        ("/users/admin/privilege", "/users/*", False),
        ("/users/admin/privilege", "/users/*/privilege", True),
        ("/hostname", "/hostname", True),
        ("/hostname", "/*", True),
        ("", "/*", False),
        ("/a/b/c", "/a/*", False),  # length mismatch
    ],
)
def test_path_glob_match(path: str, pattern: str, expected: bool) -> None:
    assert path_glob_match(path, pattern) is expected


def test_is_subset_flat_match() -> None:
    target = {"action": "permit", "proto": "ip", "src": "any", "dst": "any"}
    template = {"action": "permit", "proto": "ip"}
    assert is_subset(template, target) is True


def test_is_subset_value_mismatch() -> None:
    target = {"action": "deny", "proto": "ip"}
    template = {"action": "permit"}
    assert is_subset(template, target) is False


def test_is_subset_missing_key() -> None:
    target = {"action": "permit"}
    template = {"action": "permit", "proto": "ip"}
    assert is_subset(template, target) is False


def test_is_subset_target_not_dict() -> None:
    assert is_subset({"a": 1}, None) is False
    assert is_subset({"a": 1}, "string") is False
    assert is_subset({"a": 1}, [1, 2]) is False


def test_is_subset_empty_template_always_matches_dict() -> None:
    assert is_subset({}, {"anything": "here"}) is True


def test_is_subset_nested() -> None:
    target = {"a": {"b": {"c": 1, "d": 2}}}
    template = {"a": {"b": {"c": 1}}}
    assert is_subset(template, target) is True
    template_bad = {"a": {"b": {"c": 99}}}
    assert is_subset(template_bad, target) is False
