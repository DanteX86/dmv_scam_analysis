"""
DMV Scam Analysis Framework

A comprehensive framework for analyzing messaging-based scam campaigns.
"""

__version__ = "0.1.0"
__author__ = "Cybersecurity Research Team"
__email__ = "security@example.com"

from .core.analyzer import CampaignAnalyzer
from .core.classifier import MLThreatClassifier as ThreatClassifier
from .core.extractor import MessageExtractor
from .analysis.behavioral import BehavioralAnalyzer

__all__ = [
    "CampaignAnalyzer",
    "ThreatClassifier", 
    "MessageExtractor",
    "BehavioralAnalyzer"
]
