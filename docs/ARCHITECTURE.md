# DMV Scam Analysis - Architecture and Module Map

This document maps the current Python modules, their import relationships, project entry points, and highlights potential circular or problematic import patterns. It also identifies core modules, CLI components, API, and dashboard HTML handling code, and references a dependency graph (Graphviz .dot) for visualization.

Sections

- Project structure overview
- Entry points and CLIs
- Core modules and responsibilities
- API and dashboard components
- Import relationships and potential issues
- Dependency graph (how to render)

Project structure overview

- src/dmv_scam_analysis/

  - **init**.py: Exposes top-level symbols
  - analysis/
    - **init**.py
    - automation_analyzer.py
    - behavioral.py
    - risk_analyzer.py
    - sentiment.py
    - sentiment_analyzer.py
    - temporal_analyzer.py
    - threat_detector.py
  - api/
    - **init**.py
    - app.py (FastAPI)
  - cli/
    - **init**.py
    - main.py (Click CLI)
    - tui.py (Rich-based TUI used by CLI)
    - commands/
      - behavioral.py (argparse CLI)
      - debug.py (Click debug CLI)
  - core/
    - **init**.py
    - analyzer.py (CampaignAnalyzer orchestrator)
    - classifier.py (MLThreatClassifier)
    - extractor.py (iMessageAnalyzer & file readers)
    - model_manager.py
  - dashboard/
    - **init**.py
    - threat_dashboard.py (generates HTML dashboards; Plotly optional)
  - ml/
    - **init**.py
    - model_trainer.py
  - utils/
    - **init**.py
    - config_manager.py
    - log_maintenance.py
    - logger.py (LogManager)
    - rate_limiter.py
    - test_helpers.py
    - validation.py
  - visualization/
    - **init**.py
    - threat_visualizer.py

- visualizations/
  - executive_dashboard.html
  - risk_dashboard.html
  - visualization_index.html
- web_interface.html
- setup.py, pyproject.toml
- requirements\*.txt
- launcher.py, dmv_cli_enhanced.py (standalone scripts)
- tests/ and assorted test\_\*.py files
- scripts/ (utility scripts)

Entry points and CLIs

- Console script (packaged): setup.py defines console_scripts -> dmv-analyze = dmv_scam_analysis.cli.main:main
  - Provides commands: tui, analyze, quick_check, generate_report, model_info, extract_iocs
- Module entry guards:
  - src/dmv_scam_analysis/cli/main.py -> if **name** == "**main**": main()
  - src/dmv_scam_analysis/cli/commands/behavioral.py -> argparse CLI with its own main()
  - src/dmv_scam_analysis/cli/commands/debug.py -> Click CLI with its own main()
  - src/dmv_scam_analysis/api/app.py -> uvicorn.run(...) in **main** for local run
  - src/dmv_scam_analysis/dashboard/threat_dashboard.py -> demo_dashboard() in **main**
- Root scripts (standalone, not installed via setup):
  - launcher.py (content truncated in scan; likely orchestrator demo)
  - dmv_cli_enhanced.py (enhanced CLI demo)

Core modules and responsibilities

- analysis.behavioral.BehavioralAnalyzer: Behavioral indicators, temporal/automation helpers (via analyzers) and report generation
- analysis.automation_analyzer.AutomationAnalyzer: Pattern detection for automation
- analysis.temporal_analyzer.TemporalAnalyzer: Temporal patterns
- analysis.risk_analyzer.RiskAnalyzer: Risk scoring/report generation
- analysis.sentiment.AdvancedNLPAnalyzer: NLP scoring and report generation
- core.classifier.MLThreatClassifier: ML-based threat scoring and features
- core.extractor.iMessageAnalyzer: Read messages from files and iMessage DB
- core.model_manager.ModelManager: Model lifecycle and persistence
- core.analyzer.CampaignAnalyzer: Orchestrates multi-contact campaign analysis
- utils.logger.LogManager: Logging configuration, used across modules (e.g., dashboard)
- utils.config_manager.ConfigManager: Configuration access
- utils.rate_limiter.RateLimiter: API rate limiting (used by FastAPI app)
- dashboard.threat_dashboard.ThreatDashboard: Accumulates metrics and generates an HTML dashboard (Plotly optional)
- visualization.threat_visualizer: Rendering and plotting helpers (optional)

API and dashboard components

- API (FastAPI): src/dmv_scam_analysis/api/app.py
  - Imports: BehavioralAnalyzer, MLThreatClassifier (ThreatClassifier), RateLimiter
  - Endpoints: POST /analyze, GET /stats, GET /health
  - Security: HTTPBearer token + in-memory rate limiter
  - Middleware: performance monitoring, audit log to logs/api_audit.log
  - Local dev entry: uvicorn.run(app, host=..., port=8000)
- Dashboard HTML handling:
  - src/dmv_scam_analysis/dashboard/threat_dashboard.py
    - Records threat analyses and performance metrics to JSON files under dashboard_data/
    - Generates Plotly dashboard HTML if Plotly available; otherwise a basic HTML page
  - Pre-rendered HTML pages in visualizations/ and web_interface.html

Import relationships and potential issues

- Top-level package exports (src/dmv_scam_analysis/**init**.py):

  - from .analysis.behavioral import BehavioralAnalyzer
  - from .core.analyzer import CampaignAnalyzer
  - from .core.classifier import MLThreatClassifier as ThreatClassifier
  - from .core.extractor import MessageExtractor
    Observation: Importing core and analysis classes at package import time increases risk of circular imports and import-time side effects. If any of those modules import from dmv_scam_analysis (package-level), it may create cycles. Consider moving heavy imports behind functions or avoiding re-export unless required by API.

- CLI (src/dmv_scam_analysis/cli/main.py):

  - Imports BehavioralAnalyzer, ThreatClassifier, iMessageAnalyzer, ConfigManager
  - Lazily imports .tui.run_tui at command invocation to avoid unnecessary TUI deps
  - This is a good pattern to minimize import-time overhead

- TUI (src/dmv_scam_analysis/cli/tui.py):

  - Imports BehavioralAnalyzer, AdvancedNLPAnalyzer, iMessageAnalyzer, ThreatClassifier
  - Uses rich and click; interacts with webbrowser to open HTML

- API (src/dmv_scam_analysis/api/app.py):

  - Imports ThreatClassifier and BehavioralAnalyzer globally; these models are instantiated at import time
  - Consider deferring heavy model loads to a startup event to reduce cold start impact

- Dashboard (src/dmv_scam_analysis/dashboard/threat_dashboard.py):

  - Imports LogManager from utils.logger; optionally uses pandas and plotly

- Core orchestrator (src/dmv_scam_analysis/core/analyzer.py):

  - Imports analysis submodules (AutomationAnalyzer, RiskAnalyzer, TemporalAnalyzer)
  - No obvious cycles based on imports observed

- Potentially problematic imports (actionable):

  1. src/dmv_scam_analysis/cli/commands/behavioral.py uses from behavioral_analyzer import BehavioralAnalyzer rather than a package-relative import. This will fail when running as installed package and may shadow/duplicate code if a similarly named module exists in PYTHONPATH. Recommendation: change to from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer.
  2. src/dmv_scam_analysis/cli/commands/debug.py imports BehavioralAnalyzer and MLThreatClassifier from behavioral_analyzer and ml_threat_classifier respectively (non-package-local names). Recommendation: change to from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer and from dmv_scam_analysis.core.classifier import MLThreatClassifier.
  3. Package **init** re-exports multiple heavy objects. If any analysis/core modules import the package root, this could cause circular import (not directly observed but is a risk). Consider reducing re-exports or wrapping them in lightweight accessors.
  4. API and CLI instantiate MLThreatClassifier at import time. If model loading is heavy, prefer lazy initialization (e.g., FastAPI startup event, or inside command function) to avoid import-time failures in constrained environments.

- Circular imports identified: None confirmed from current scan. Risk hotspots are the package **init** re-exports and any bi-directional imports between analysis._ and core._ (not observed in files we opened). If circular import errors occur, inspect modules mentioned above first.

Dependency graph
See docs/module_dependency_graph.dot for a Graphviz representation. To render it (if Graphviz is installed):

- dot -Tpng docs/module_dependency_graph.dot -o docs/module_dependency_graph.png

Appendix: Observed external libraries per area

- CLI: click, rich
- API: fastapi, pydantic, uvicorn (for **main**)
- ML/DS: pandas, numpy, scikit-learn (likely), scipy (potential), plotly (optional), seaborn/matplotlib (maybe via visualizations)
- Testing: pytest and friends (dev extras)
- Config/Logging: standard logging; custom LogManager
