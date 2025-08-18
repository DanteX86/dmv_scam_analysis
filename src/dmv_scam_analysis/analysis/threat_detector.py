"""
Threat Detector for DMV Scam Analysis
"""

from datetime import datetime
from typing import Any, Dict, Optional


class ThreatDetector:
    """
    Detects potential threat indicators and intrusions in communications
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the threat detector

        Args:
            config: Configuration object with threat detection settings
        """
        self.config = config
        self.key_phrases = [
            "unauthorized access",
            "account locked",
            "reset password",
            "login attempt",
            "security warning",
            "suspicious activity",
            "compromised account",
            "verification needed",
        ]

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for potential threats

        Args:
            text (str): Message text to analyze

        Returns:
            dict: Threat detection results
        """
        if not text or not isinstance(text, str):
            return {
                "threat_detected": False,
                "confidence": 0.0,
                "key_phrases": [],
                "analysis_timestamp": datetime.now().isoformat(),
            }

        # Search for key phrases
        text_lower = text.lower()
        detected_phrases = [
            phrase for phrase in self.key_phrases if phrase in text_lower
        ]
        threat_detected = bool(detected_phrases)

        # Calculate confidence as heuristic based on number of key phrases detected
        confidence = len(detected_phrases) / len(self.key_phrases)

        return {
            "threat_detected": threat_detected,
            "confidence": confidence,
            "key_phrases": detected_phrases,
            "analysis_timestamp": datetime.now().isoformat(),
        }
