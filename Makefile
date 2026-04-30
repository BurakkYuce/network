.PHONY: install install-min install-collector test lint format typecheck ci clean inventory-list

install:
	uv sync --extra dev

install-collector:
	uv sync --extra dev --extra collector

test:
	uv run pytest

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

typecheck:
	uv run mypy src

ci: lint typecheck test

inventory-list:
	uv run netauto inventory list

clean:
	rm -rf .venv .pytest_cache .ruff_cache .mypy_cache dist build
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
