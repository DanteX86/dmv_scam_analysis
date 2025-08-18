# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Repository: DMV Scam Analysis (Python)

Common commands

- Setup
  - Create venv (macOS/arm64): python3 -m venv venv && source venv/bin/activate
  - Install deps: python3 -m pip install -r requirements.txt
  - Install in dev/editable mode: python3 -m pip install -e .
  - Pre-commit (optional, recommended):
    - Install hooks: pre-commit install
    - Run on all files: pre-commit run --all-files
- Lint/format
  - Lint (flake8 over src/ and tests/): python3 -m flake8 src/ tests/
  - Format (black): python3 -m black src/ tests/
  - isort (imports): python3 -m isort --profile black src/ tests/
  - Type check (mypy): mypy .
  - Security scan (bandit): bandit -c pyproject.toml -r src
- Tests (pytest configured via pytest.ini)
  - Run all: python3 -m pytest -v
  - Run by marker: python3 -m pytest -m unit, python3 -m pytest -m integration, etc.
  - Single file: python3 -m pytest tests/unit/test_config_manager.py -v
  - Single test: python3 -m pytest tests/unit/test_config_manager.py::TestConfigManager::test_load -v
  - Coverage output paths: htmlcov/ (HTML), coverage.xml, plus JUnit at test-results/junit.xml
- Make targets (shortcuts)
  - make install # pip install -r requirements.txt
  - make setup # pip install -e .
  - make test # pytest tests/ -v
  - make lint # flake8 src/ tests/
  - make format # black src/ tests/
  - make clean # remove caches and outputs
  - make structure # tree/find summary
  - make quick-check # run CLI quick-check against a sample message
  - make model-info # print model information
  - make api # run FastAPI app (see Architecture for module path)
  - make analyze FILE=path/to/messages.json
  - make extract-iocs FILE=path/to/messages.json
  - make generate-report START=YYYY-MM-DD END=YYYY-MM-DD
  - make full-analysis # clean → tests → quick-check → recommendations

Running the CLI

- Installed console entry point: dmv-analyze (from setup.py), equivalent to: python3 -m dmv_scam_analysis.cli.main
- Examples:
  - Quick check: python3 -m dmv_scam_analysis.cli.main quick-check "Suspicious message text"
  - Analyze file: python3 -m dmv_scam_analysis.cli.main analyze data/messages.json
  - Extract IOCs: python3 -m dmv_scam_analysis.cli.main extract-iocs data/messages.json
  - Model info: python3 -m dmv_scam_analysis.cli.main model-info
  - Debug mode: python3 -m dmv_scam_analysis.cli.main --debug quick-check "Test"

API and services

- Local API (FastAPI): module path src/dmv_scam_analysis/api/app.py exposes app
  - Run via Makefile: make api (PYTHONPATH=src python3 src/dmv_scam_analysis/api/app.py)
  - Uvicorn (manual): uvicorn src.dmv_scam_analysis.api.app:app --host 127.0.0.1 --port 8000 --workers 4
  - Health: GET http://127.0.0.1:8000/health
- Docker
  - Build: docker build -t dmv-api .
  - Compose (root compose): docker compose up --build
    - Exposes 8000→8000; mounts ./logs, ./models, ./data
    - Healthcheck: GET /health
    - Optional services: redis (6379), postgres (5432), prometheus (9090)
  - Compose (deployment/docker): docker compose -f deployment/docker/docker-compose.yml up --build

Testing details

- pytest.ini:
  - Test paths: tests
  - Markers: unit, integration, functional, performance, security
  - Addopts include coverage for scripts (term-missing, html, xml) and JUnit XML
- Examples:
  - By marker: python3 -m pytest -m "security and not integration" -v
  - With locals and short tracebacks already enabled via ini

Development tooling

- Code style and sorting configured in pyproject.toml:
  - black line-length 88, target Python 3.9
  - isort profile=black
  - mypy strictness enabled; numpy plugin; common DS libs ignored
- Pre-commit hooks (.pre-commit-config.yaml):
  - black, isort, flake8 (+docstrings, bugbear, comprehensions, simplify), mypy, bandit, plus basic file/format checks
  - Run pre-commit install once; hooks will run on commit

High-level architecture (big picture)

- Package layout (src/dmv_scam_analysis):
  - cli: Click/Rich-based CLI (main.py) and subcommands; optional TUI (tui.py)
  - api: FastAPI application (app.py) exposing /analyze, /stats, /health; uses in-memory rate limiting
  - core: Orchestrators and models:
    - analyzer (CampaignAnalyzer), classifier (MLThreatClassifier), extractor (iMessage/file), model_manager
  - analysis: Domain analyzers for temporal, automation, risk, and sentiment; threat_detector
  - dashboard/visualization: ThreatDashboard and helpers to emit HTML dashboards (Plotly optional)
  - utils: ConfigManager, LogManager, RateLimiter, validation, helpers
- Entry points
  - dmv-analyze → dmv_scam_analysis.cli.main:main (installed console script)
  - API app import path: src.dmv_scam_analysis.api.app:app (for uvicorn)
- Data flow
  1. Input (files or iMessage DB) → core.extractor
  2. Orchestration via core.analyzer → invokes analysis.\* modules
  3. Outputs: reports/JSON, optional dashboards via dashboard/visualization
  4. API wraps analyzers and classifier for programmatic access; CLI provides user-facing commands
- Notable notes from docs/ARCHITECTURE.md
  - Prefer package-relative imports in CLI subcommands
  - Defer heavy model loads to runtime (startup handlers) rather than import-time if adjusting API

Data, logs, and models

- Local directories used by various components:
  - data/ (inputs), logs/, models/, analysis_output/
  - Docker mounts these into /app/{data,logs,models}

CI

- .github/workflows/ci.yml runs tests and likely linting (see workflow for specifics)

Environment

- macOS, zsh; Python via Homebrew usually at /opt/homebrew/bin/python3 on arm64
- Respect existing Brew initialization in ~/.zprofile when spawning shells

Notes

- When composing commands that use secrets, prefer environment variables; do not echo secrets. For example:
  - export API_KEY={{API_KEY}}
  - docker compose up with API_KEY passed via environment.
