.PHONY: install fmt lint typecheck security test docs check build clean

install:
	pip install -e ".[dev]"

fmt:
	ruff format .
	ruff check --fix .

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy

security:
	bandit -r src
	pip-audit --skip-editable

docs:
	python scripts/gen_docs.py

test:
	pytest --cov --cov-report=term-missing

check: lint typecheck security test

build:
	python -m build

clean:
	rm -rf dist build *.egg-info .mypy_cache .ruff_cache .pytest_cache .coverage
