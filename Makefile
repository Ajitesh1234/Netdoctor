.PHONY: install fmt lint typecheck test check build clean

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

test:
	pytest --cov --cov-report=term-missing

check: lint typecheck test

build:
	python -m build

clean:
	rm -rf dist build *.egg-info .mypy_cache .ruff_cache .pytest_cache .coverage
