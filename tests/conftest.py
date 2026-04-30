from pathlib import Path

import pytest


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture
def fixtures_dir(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures"
