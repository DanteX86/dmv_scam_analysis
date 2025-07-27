# DMV Scam Analysis Makefile
# Provides convenient targets for analysis, testing, and report generation

.PHONY: help install setup test clean lint format analyze quick-check recommendations model-info extract-iocs api structure

# Default target
.DEFAULT_GOAL := help

# Python and environment setup
PYTHON := python3
PYTHONPATH := src
VENV := venv

help: ## Show this help message
	@echo "DMV Scam Analysis - Available Make Targets:"
	@echo "=============================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install: ## Install dependencies
	$(PYTHON) -m pip install -r requirements.txt

setup: ## Set up the project in development mode
	$(PYTHON) -m pip install -e .

test: ## Run the test suite
	$(PYTHON) -m pytest tests/ -v

lint: ## Run linting
	$(PYTHON) -m flake8 src/ tests/

format: ## Run code formatting
	$(PYTHON) -m black src/ tests/

clean: ## Clean up generated files and cache
	rm -rf __pycache__ .pytest_cache *.pyc
	rm -rf analysis_output/
	rm -rf test_output/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +

structure: ## Show project structure
	@which tree >/dev/null 2>&1 && tree -I '__pycache__|*.pyc|.git|venv|.pytest_cache' || find . -type f -not -path './.git/*' -not -path './venv/*' -not -path './__pycache__/*' -not -name '*.pyc' | head -50

quick-check: ## Run a quick threat analysis on a sample scam message
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m dmv_scam_analysis.cli.main quick-check "URGENT: Your DMV license will be suspended! Pay the fine immediately or face arrest. Click here now: http://malicious-site.com/pay"

model-info: ## Show model information and statistics
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m dmv_scam_analysis.cli.main model-info

api: ## Start the FastAPI server
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) src/dmv_scam_analysis/api/app.py

debug: ## Run with debug mode
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m dmv_scam_analysis.cli.main --debug quick-check "Test message for debugging"

project-version: ## Show version info
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -c "print('DMV Scam Analysis v1.0.0')"

# Data analysis targets
analyze: ## Analyze messages from a file (usage: make analyze FILE=path/to/messages.json)
	@if [ -z "$(FILE)" ]; then \
		echo "Error: Please specify a file to analyze. Usage: make analyze FILE=path/to/messages.json"; \
		exit 1; \
	fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m dmv_scam_analysis.cli.main analyze "$(FILE)"

extract-iocs: ## Extract IOCs from messages (usage: make extract-iocs FILE=path/to/messages.json)
	@if [ -z "$(FILE)" ]; then \
		echo "Error: Please specify a file to analyze. Usage: make extract-iocs FILE=path/to/messages.json"; \
		exit 1; \
	fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m dmv_scam_analysis.cli.main extract-iocs "$(FILE)"

generate-report: ## Generate a report for a date range (usage: make generate-report START=2024-01-01 END=2024-12-31)
	@if [ -z "$(START)" ] || [ -z "$(END)" ]; then \
		echo "Error: Please specify start and end dates. Usage: make generate-report START=2024-01-01 END=2024-12-31"; \
		exit 1; \
	fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m dmv_scam_analysis.cli.main generate-report "$(START)" "$(END)"

recommendations: ## Generate risk-based recommendations for analyzed data
	$(PYTHON) generate_recommendations.py

# Test specific functionality
test-recommendations: ## Test the recommendation generation functionality
	$(PYTHON) generate_recommendations.py test

# Comprehensive analysis workflow
full-analysis: ## Run complete analysis workflow with recommendations
	@echo "🔄 Running full analysis workflow..."
	$(MAKE) clean
	$(MAKE) test
	$(MAKE) quick-check
	$(MAKE) recommendations
	@echo "✅ Full analysis workflow complete!"
