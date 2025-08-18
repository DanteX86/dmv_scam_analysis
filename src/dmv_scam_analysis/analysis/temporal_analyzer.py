"""
Temporal Analysis Module
Analyzes temporal patterns in message data.
"""

from typing import Any, Dict, Optional

import numpy as np
import pandas as pd
from scipy import stats


class TemporalAnalyzer:
    """Analyzes temporal patterns in message data"""

    def __init__(self) -> None:
        self.analysis_results: Dict[str, Any] = {}

    def analyze_patterns(self, messages_df: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """
        Analyze temporal patterns in message communications

        Args:
            messages_df (pd.DataFrame): Message data with timestamps

        Returns:
            dict: Temporal analysis results
        """
        if messages_df is None or messages_df.empty:
            return None

        # Convert timestamps
        messages_df["datetime"] = pd.to_datetime(messages_df["readable_date"])
        messages_df["hour"] = messages_df["datetime"].dt.hour.astype(str)
        messages_df["day_of_week"] = messages_df["datetime"].dt.dayofweek
        messages_df["is_weekend"] = messages_df["day_of_week"].isin([5, 6])

        self.analysis_results = {
            "hourly_distribution": self._analyze_hourly_patterns(messages_df),
            "weekly_distribution": self._analyze_weekly_patterns(messages_df),
            "burst_detection": self._detect_message_bursts(messages_df),
            "anomalous_timing": self._detect_timing_anomalies(messages_df),
            "response_patterns": self._analyze_response_patterns(messages_df),
        }

        return self.analysis_results

    def _analyze_hourly_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze hourly message distribution patterns"""
        hourly_counts = messages_df.groupby("hour").size()

        # Calculate statistics
        mean_hourly = hourly_counts.mean()
        std_hourly = hourly_counts.std()

        # Identify peak hours
        peak_hours = hourly_counts[
            hourly_counts > mean_hourly + std_hourly
        ].index.tolist()

        # Calculate anomaly score for timing
        z_scores = np.abs(stats.zscore(hourly_counts.values))
        anomalous_hours = hourly_counts[z_scores > 2].index.tolist()

        return {
            "distribution": hourly_counts.to_dict(),
            "peak_hours": peak_hours,
            "anomalous_hours": anomalous_hours,
            "statistics": {
                "mean_messages_per_hour": mean_hourly,
                "std_deviation": std_hourly,
                "most_active_hour": hourly_counts.idxmax(),
                "least_active_hour": hourly_counts.idxmin(),
            },
        }

    def _analyze_weekly_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze weekly patterns and weekend vs weekday behavior"""
        weekly_stats = {
            "weekday_messages": messages_df[~messages_df["is_weekend"]].shape[0],
            "weekend_messages": messages_df[messages_df["is_weekend"]].shape[0],
            "daily_distribution": messages_df.groupby("day_of_week").size().to_dict(),
        }

        # Calculate weekend anomaly score
        total_messages = len(messages_df)
        weekend_ratio = (
            weekly_stats["weekend_messages"] / total_messages
            if total_messages > 0
            else 0
        )

        # Normal expectation: ~28.6% weekend activity (2/7 days)
        expected_weekend_ratio = 2 / 7
        weekend_anomaly_score = (
            abs(weekend_ratio - expected_weekend_ratio) / expected_weekend_ratio
        )

        weekly_stats["weekend_anomaly_score"] = weekend_anomaly_score
        weekly_stats["weekend_ratio"] = weekend_ratio

        return weekly_stats

    def _detect_message_bursts(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Detect unusual bursts of message activity"""
        # Resample messages by hour to detect bursts
        hourly_messages = messages_df.set_index("datetime").resample("H").size()

        # Calculate rolling statistics
        window_size = 6  # 6-hour window
        rolling_mean = hourly_messages.rolling(window=window_size).mean()
        rolling_std = hourly_messages.rolling(window=window_size).std()

        # Detect bursts (messages > mean + 2*std)
        burst_threshold = rolling_mean + (2 * rolling_std)
        bursts = hourly_messages[hourly_messages > burst_threshold]

        burst_events = []
        for timestamp, count in bursts.items():
            if not pd.isna(count):
                burst_events.append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "message_count": int(count),
                        "threshold": (
                            float(burst_threshold[timestamp])
                            if not pd.isna(burst_threshold[timestamp])
                            else 0
                        ),
                        "severity": self._calculate_burst_severity(
                            count, burst_threshold[timestamp]
                        ),
                    }
                )

        return {
            "burst_events": burst_events,
            "total_bursts": len(burst_events),
            "max_burst_intensity": (
                max([e["message_count"] for e in burst_events]) if burst_events else 0
            ),
        }

    def _calculate_burst_severity(self, count: float, threshold: float) -> Any:
        """Calculate burst severity score"""
        if pd.isna(threshold) or threshold == 0:
            return 0
        severity = (count - threshold) / threshold
        if severity > 2:
            return "CRITICAL"
        elif severity > 1:
            return "HIGH"
        elif severity > 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def _detect_timing_anomalies(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Detect anomalous timing patterns"""
        if len(messages_df) < 3:
            return {"anomalies": [], "anomaly_score": 0}

        # Calculate time deltas between messages
        messages_sorted = messages_df.sort_values("datetime")
        time_deltas = messages_sorted["datetime"].diff().dt.total_seconds().dropna()

        if len(time_deltas) == 0:
            return {"anomalies": [], "anomaly_score": 0}

        # Calculate statistics
        mean_interval = time_deltas.mean()
        std_interval = time_deltas.std()

        # Identify anomalies (> 2 standard deviations)
        anomalies = []
        for idx, delta in enumerate(time_deltas):
            if abs(delta - mean_interval) > 2 * std_interval:
                if idx < len(messages_sorted) - 1:
                    anomalies.append(
                        {
                            "message_timestamp": messages_sorted.iloc[idx + 1][
                                "datetime"
                            ].isoformat(),
                            "time_delta_seconds": float(delta),
                            "anomaly_type": "unusual_interval",
                        }
                    )

        return {
            "anomalies": anomalies,
            "anomaly_score": (
                len(anomalies) / len(time_deltas) if len(time_deltas) > 0 else 0
            ),
            "statistics": {
                "mean_interval_seconds": float(mean_interval),
                "std_interval_seconds": float(std_interval),
                "median_interval_seconds": float(time_deltas.median()),
            },
        }

    def _analyze_response_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze response time patterns between messages"""
        if len(messages_df) < 2:
            return {"response_analysis": "insufficient_data"}

        sent_messages = messages_df[messages_df["is_from_me"] == 1].sort_values(
            "datetime"
        )
        received_messages = messages_df[messages_df["is_from_me"] == 0].sort_values(
            "datetime"
        )

        if len(sent_messages) == 0 or len(received_messages) == 0:
            return {"response_analysis": "no_bidirectional_communication"}

        response_times = []

        for _, sent_msg in sent_messages.iterrows():
            subsequent_received = received_messages[
                received_messages["datetime"] > sent_msg["datetime"]
            ]

            if not subsequent_received.empty:
                next_received = subsequent_received.iloc[0]
                response_time = (
                    next_received["datetime"] - sent_msg["datetime"]
                ).total_seconds()
                response_times.append(
                    {
                        "sent_timestamp": sent_msg["datetime"].isoformat(),
                        "received_timestamp": next_received["datetime"].isoformat(),
                        "response_time_seconds": response_time,
                    }
                )

        if not response_times:
            return {"response_analysis": "no_response_patterns_found"}

        response_seconds = [rt["response_time_seconds"] for rt in response_times]

        return {
            "response_times": response_times,
            "statistics": {
                "average_response_time_seconds": np.mean(response_seconds),
                "median_response_time_seconds": np.median(response_seconds),
                "min_response_time_seconds": min(response_seconds),
                "max_response_time_seconds": max(response_seconds),
                "total_exchanges": len(response_times),
            },
            "rapid_responses": [
                rt for rt in response_times if rt["response_time_seconds"] < 60
            ],
            "delayed_responses": [
                rt for rt in response_times if rt["response_time_seconds"] > 3600
            ],
        }
