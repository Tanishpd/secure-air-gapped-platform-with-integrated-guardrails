# sagp — the only supported entrypoint for every task.
# The repo path contains spaces, so every path is quoted everywhere.
.SHELLFLAGS := -eu -o pipefail -c
SHELL := /bin/bash
.DEFAULT_GOAL := help

PY311   := $(HOME)/.local/bin/python3.11
VENV    := .venv
VENV_PROVISION := .venv-provision
PIP     := "$(VENV)/bin/pip"
PYTHON  := "$(VENV)/bin/python"
RUFF    := "$(VENV)/bin/ruff"
MYPY    := "$(VENV)/bin/mypy"
PYTEST  := "$(VENV)/bin/pytest"

.PHONY: help doctor venvs install lint format typecheck test clean

help:  ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

doctor:  ## Read-only preflight: Python 3.11, interpreter present
	@test -x "$(PY311)" || { echo "missing interpreter: $(PY311)"; exit 1; }
	@"$(PY311)" -c 'import sys; v=sys.version_info; assert (v.major,v.minor)==(3,11), f"need 3.11, got {v.major}.{v.minor}"; print(f"python {sys.version.split()[0]} OK at {sys.executable}")'

venvs:  ## Create .venv (sealed runtime) and .venv-provision (online only)
	@test -x "$(PY311)" || { echo "missing interpreter: $(PY311)"; exit 1; }
	"$(PY311)" -m venv "$(VENV)"
	"$(PY311)" -m venv "$(VENV_PROVISION)"
	$(PIP) install --quiet --upgrade pip
	@echo "created $(VENV) and $(VENV_PROVISION)"

install:  ## Install the runtime closure + [dev] into .venv (online)
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev]'

lint:  ## ruff check + format --check
	$(RUFF) check src tests
	$(RUFF) format --check src tests

format:  ## ruff format (writes)
	$(RUFF) format src tests
	$(RUFF) check --fix src tests

typecheck:  ## mypy (strict) over src/sagp
	$(MYPY)

test:  ## Unit + integration suites (FakeLLM/FakeScorer, no models)
	$(PYTEST) -q

clean:  ## Remove venvs and caches
	rm -rf "$(VENV)" "$(VENV_PROVISION)" .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
