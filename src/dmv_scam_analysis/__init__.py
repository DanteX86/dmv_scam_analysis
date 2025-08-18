"""
DMV Scam Analysis Framework

A comprehensive framework for analyzing messaging-based scam campaigns.

Note: Avoid heavy imports at package import time to keep initialization fast and
stable in environments without optional dependencies (e.g., SciPy). Use lazy
imports for optional components.
"""

from importlib import import_module

__version__ = "0.1.0"
__author__ = "Cybersecurity Research Team"
__email__ = "security@example.com"

# Public API (lazy-loaded)
__all__ = [
    "CampaignAnalyzer",
    "ThreatClassifier",
    "MessageExtractor",
    "BehavioralAnalyzer",
]


from typing import Any


def __getattr__(name: str) -> Any:
    """Lazily import public API symbols on first access.

    This prevents importing optional heavy dependencies (like SciPy) during
    package initialization. Accessing these attributes will import the
    corresponding submodules on demand.
    """
    if name == "BehavioralAnalyzer":
        return import_module(".analysis.behavioral", __name__).__dict__[name]
    if name == "CampaignAnalyzer":
        return import_module(".core.analyzer", __name__).__dict__[name]
    if name == "ThreatClassifier":
        return import_module(".core.classifier", __name__).__dict__[
            "MLThreatClassifier"
        ]
    if name == "MessageExtractor":
        return import_module(".core.extractor", __name__).__dict__[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
