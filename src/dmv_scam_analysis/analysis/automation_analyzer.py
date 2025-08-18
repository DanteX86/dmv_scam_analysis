"""
Automation Analysis Module
Detects automated behavior patterns in message data.
"""

from typing import Any, Dict, Optional, Set

import numpy as np
import pandas as pd


class AutomationAnalyzer:
    """Analyzes potential automation indicators in message data"""

    def __init__(self) -> None:
        self.automation_indicators: Dict[str, Any] = {}

    def detect_automation(self, messages_df: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """
        Detect indicators of automated messaging systems

        Args:
            messages_df (pd.DataFrame): Message data

        Returns:
            dict: Automation detection results
        """
        if messages_df is None or messages_df.empty:
            return None

        self.automation_indicators = {
            "timing_regularity": self._analyze_timing_regularity(messages_df),
            "content_similarity": self._analyze_content_patterns(messages_df),
            "volume_consistency": self._analyze_volume_patterns(messages_df),
            "response_predictability": self._analyze_response_predictability(messages_df),
        }

        # Calculate overall automation score
        automation_score = self._calculate_automation_score(self.automation_indicators)
        self.automation_indicators["overall_automation_score"] = automation_score

        return self.automation_indicators

    def _analyze_timing_regularity(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze timing regularity as indicator of automation"""
        if len(messages_df) < 3:
            return {"regularity_score": 0.0, "analysis": "insufficient_data"}

        messages_sorted = messages_df.sort_values("datetime")
        time_deltas = messages_sorted["datetime"].diff().dt.total_seconds().dropna()

        if len(time_deltas) == 0:
            return {"regularity_score": 0.0, "analysis": "no_time_intervals"}

        # Calculate coefficient of variation (lower = more regular)
        cv = float(time_deltas.std() / time_deltas.mean()) if time_deltas.mean() > 0 else float("inf")

        # Convert to regularity score (higher = more regular)
        regularity_score = 1 / (1 + cv) if cv != float("inf") else 0.0

        # Check for exact intervals (strong automation indicator)
        unique_intervals = len(set(time_deltas.round()))
        interval_diversity = unique_intervals / len(time_deltas)

        return {
            "regularity_score": float(regularity_score),
            "coefficient_of_variation": cv,
            "interval_diversity": float(interval_diversity),
            "mean_interval_seconds": float(time_deltas.mean()),
            "analysis": self._interpret_timing_regularity(regularity_score, interval_diversity),
        }

    def _interpret_timing_regularity(self, regularity_score: float, interval_diversity: float) -> str:
        """Interpret timing regularity results"""
        if regularity_score > 0.8 and interval_diversity < 0.3:
            return "HIGH_AUTOMATION_LIKELIHOOD"
        elif regularity_score > 0.6:
            return "MODERATE_AUTOMATION_LIKELIHOOD"
        else:
            return "LOW_AUTOMATION_LIKELIHOOD"

    def _analyze_content_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze content patterns for automation indicators"""
        if "text" not in messages_df.columns:
            return {"similarity_score": 0, "analysis": "no_text_data"}

        text_messages = messages_df.dropna(subset=["text"])
        if len(text_messages) < 2:
            return {"similarity_score": 0, "analysis": "insufficient_text_data"}

        # Simple content similarity analysis
        message_texts = text_messages["text"].astype(str).tolist()

        # Calculate character-level similarity
        similarities = []
        for i in range(len(message_texts)):
            for j in range(i + 1, len(message_texts)):
                similarity = self._calculate_text_similarity(message_texts[i], message_texts[j])
                similarities.append(similarity)

        average_similarity: float = float(np.mean(similarities)) if similarities else 0.0

        # Check for exact duplicates
        unique_messages = len(set(message_texts))
        duplicate_ratio: float = 1 - (unique_messages / len(message_texts))

        return {
            "similarity_score": float(average_similarity),
            "duplicate_ratio": float(duplicate_ratio),
            "unique_message_count": unique_messages,
            "total_message_count": len(message_texts),
            "analysis": self._interpret_content_similarity(float(average_similarity), float(duplicate_ratio)),
        }

    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple character-level similarity between two texts"""

        # Simple Jaccard similarity on character bigrams
        def get_bigrams(text: str) -> Set[str]:
            return set(text[i : i + 2] for i in range(len(text) - 1))

        bigrams1 = get_bigrams(text1.lower())
        bigrams2 = get_bigrams(text2.lower())

        if not bigrams1 and not bigrams2:
            return 1.0
        if not bigrams1 or not bigrams2:
            return 0.0

        intersection = len(bigrams1.intersection(bigrams2))
        union = len(bigrams1.union(bigrams2))

        return intersection / union if union > 0 else 0

    def _interpret_content_similarity(self, similarity_score: float, duplicate_ratio: float) -> str:
        """Interpret content similarity results"""
        if duplicate_ratio > 0.5 or similarity_score > 0.8:
            return "HIGH_TEMPLATE_USAGE"
        elif similarity_score > 0.6:
            return "MODERATE_TEMPLATE_USAGE"
        else:
            return "LOW_TEMPLATE_USAGE"

    def _analyze_volume_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze volume consistency patterns"""
        if len(messages_df) < 7:  # Need at least a week of data
            return {"consistency_score": 0, "analysis": "insufficient_temporal_data"}

        # Group by day and count messages
        daily_counts = messages_df.groupby(messages_df["datetime"].dt.date).size()

        # Calculate consistency metrics
        cv = daily_counts.std() / daily_counts.mean() if daily_counts.mean() > 0 else float("inf")
        consistency_score = 1 / (1 + cv) if cv != float("inf") else 0

        return {
            "consistency_score": consistency_score,
            "daily_volume_cv": cv,
            "mean_daily_messages": float(daily_counts.mean()),
            "std_daily_messages": float(daily_counts.std()),
            "analysis": (
                "HIGH_VOLUME_CONSISTENCY" if consistency_score > 0.7 else "VARIABLE_VOLUME_PATTERN"
            ),
        }

    def _analyze_response_predictability(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze predictability of response patterns"""
        sent_messages = messages_df[messages_df["is_from_me"] == 1]
        received_messages = messages_df[messages_df["is_from_me"] == 0]

        if len(sent_messages) == 0 or len(received_messages) == 0:
            return {"predictability_score": 0, "analysis": "no_bidirectional_communication"}

        # Simple analysis: check if responses follow consistent patterns
        response_ratio = (
            len(received_messages) / len(sent_messages) if len(sent_messages) > 0 else 0
        )

        # Analyze if there's a 1:1 response pattern (indicator of automation)
        predictability_score = 1 - abs(response_ratio - 1) if response_ratio <= 2 else 0

        return {
            "predictability_score": predictability_score,
            "response_ratio": response_ratio,
            "analysis": (
                "HIGH_PREDICTABILITY" if predictability_score > 0.8 else "VARIABLE_RESPONSE_PATTERN"
            ),
        }

    def _calculate_automation_score(self, indicators: Dict[str, Any]) -> float:
        """Calculate overall automation likelihood score"""
        scores = []

        if "timing_regularity" in indicators:
            scores.append(indicators["timing_regularity"].get("regularity_score", 0))

        if "content_similarity" in indicators:
            scores.append(indicators["content_similarity"].get("similarity_score", 0))

        if "volume_consistency" in indicators:
            scores.append(indicators["volume_consistency"].get("consistency_score", 0))

        if "response_predictability" in indicators:
            scores.append(indicators["response_predictability"].get("predictability_score", 0))

        return np.mean(scores) if scores else 0
