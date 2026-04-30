from typing import Any


def path_glob_match(path: str, pattern: str) -> bool:
    """Match a JSON Pointer ``path`` against a glob ``pattern``.

    Both are split on ``/``; a pattern segment of ``*`` matches any single
    real-path segment. Lengths must match (no recursive wildcard).

    Examples:
        path_glob_match("/acls/EDGE-IN/entries/5", "/acls/*/entries/*") -> True
        path_glob_match("/users/admin",            "/users/*")          -> True
        path_glob_match("/users/admin/privilege",  "/users/*")          -> False
    """
    path_parts = path.lstrip("/").split("/") if path else []
    pat_parts = pattern.lstrip("/").split("/") if pattern else []
    if len(path_parts) != len(pat_parts):
        return False
    return all(p == pat or pat == "*" for p, pat in zip(path_parts, pat_parts, strict=True))


def is_subset(template: dict[str, Any], target: Any) -> bool:
    """Return True if every key/value in ``template`` is present in ``target``."""
    if not isinstance(target, dict):
        return False
    for key, expected in template.items():
        if key not in target:
            return False
        if isinstance(expected, dict):
            if not is_subset(expected, target[key]):
                return False
        elif target[key] != expected:
            return False
    return True
