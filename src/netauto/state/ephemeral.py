from pathlib import Path
from typing import Any

import yaml


def load_ephemeral_patterns(path: Path | str) -> list[list[str]]:
    """Load ephemeral path patterns from YAML; return as list of segment lists.

    Patterns are dotted paths with ``*`` as a single-segment wildcard.
    Example: ``interfaces.*.counters`` → ``["interfaces", "*", "counters"]``.
    """
    p = Path(path)
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text()) or []
    if not isinstance(raw, list):
        raise ValueError(f"{p}: ephemeral patterns file must be a YAML list")
    return [str(item).split(".") for item in raw]


def path_matches(path: list[str], pattern: list[str]) -> bool:
    """Return True if ``path`` matches ``pattern`` (with ``*`` wildcard)."""
    if len(path) != len(pattern):
        return False
    return all(p == pat or pat == "*" for p, pat in zip(path, pattern, strict=True))


def strip_ephemeral(data: Any, patterns: list[list[str]]) -> Any:
    """Deep-copy ``data`` with keys whose path matches any pattern removed."""
    return _strip_recursive(data, patterns, [])


def _strip_recursive(obj: Any, patterns: list[list[str]], here: list[str]) -> Any:
    if isinstance(obj, dict):
        result: dict[str, Any] = {}
        for key, value in obj.items():
            current = [*here, str(key)]
            if any(path_matches(current, p) for p in patterns):
                continue
            result[key] = _strip_recursive(value, patterns, current)
        return result
    if isinstance(obj, list):
        return [_strip_recursive(item, patterns, here) for item in obj]
    return obj
