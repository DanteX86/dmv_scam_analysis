"""Functional tests for the complete analysis workflow."""

import json
import os
from datetime import datetime

import pytest

from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer
from dmv_scam_analysis.core.extractor import MessageExtractor
from dmv_scam_analysis.visualization import ThreatVisualizer


@pytest.fixture
def test_data_dir(tmp_path):
    """Create a temporary directory with test data."""
    data_dir = tmp_path / "test_data"
    data_dir.mkdir()

    # Create sample message files
    messages = [
        {
            "id": "msg001",
            "text": "URGENT: Your driver's license will be suspended. Pay $200 now.",
            "source": "email",
            "timestamp": "2025-06-27T10:00:00Z",
            "metadata": {
                "sender": "fake-dmv@scammer.com",
                "subject": "License Suspension Notice",
                "ip_address": "192.168.1.100",
            },
        },
        {
            "id": "msg002",
            "text": "DMV Alert: Click here to verify your license status",
            "source": "sms",
            "timestamp": "2025-06-27T11:00:00Z",
            "metadata": {"sender": "+1234567890", "carrier": "Unknown"},
        },
    ]

    with open(data_dir / "messages.json", "w") as f:
        json.dump(messages, f)

    return data_dir


@pytest.fixture
def analysis_components(test_data_dir):
    """Initialize analysis components."""
    # Create a dummy database file for the extractor
    dummy_db = test_data_dir / "dummy.db"
    dummy_db.touch()  # Create empty file

    return {
        "extractor": MessageExtractor(
            db_path=str(dummy_db), output_dir=str(test_data_dir)
        ),
        "analyzer": BehavioralAnalyzer(),
        "visualizer": ThreatVisualizer(output_dir=str(test_data_dir)),
    }


def test_complete_analysis_workflow(test_data_dir, analysis_components):
    """Test the complete analysis workflow from data extraction to visualization."""
    # Extract messages
    messages = analysis_components["extractor"].extract_all()
    assert len(messages) == 2
    assert all(isinstance(msg["timestamp"], str) for msg in messages)

    # Analyze behavior patterns
    analysis_results = analysis_components["analyzer"].analyze(messages)
    assert "threat_patterns" in analysis_results
    assert "risk_scores" in analysis_results
    assert len(analysis_results["risk_scores"]) == len(messages)

    # Generate visualizations
    visualization_paths = analysis_components["visualizer"].create_visualizations(
        messages=messages, analysis_results=analysis_results
    )
    assert "timeline" in visualization_paths
    assert "network" in visualization_paths
    assert all(os.path.exists(path) for path in visualization_paths.values())


def test_incremental_analysis(test_data_dir, analysis_components):
    """Test analyzing new messages incrementally."""
    # Initial analysis
    initial_messages = analysis_components["extractor"].extract_all()
    initial_results = analysis_components["analyzer"].analyze(initial_messages)

    # Add new message
    new_message = {
        "id": "msg003",
        "text": "Final warning: DMV license expiration",
        "source": "email",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "metadata": {
            "sender": "another-scam@fake.com",
            "subject": "License Expiration",
        },
    }

    with open(test_data_dir / "new_messages.json", "w") as f:
        json.dump([new_message], f)

    # Update analysis
    updated_messages = analysis_components["extractor"].extract_all()
    updated_results = analysis_components["analyzer"].analyze(updated_messages)

    assert (
        len(updated_results["risk_scores"]) == len(initial_results["risk_scores"]) + 1
    )


def test_error_handling(analysis_components):
    """Test error handling in the analysis workflow."""
    # Test with invalid message format
    invalid_messages = [{"id": "invalid1", "text": ""}]  # Missing required fields

    with pytest.raises(ValueError):
        analysis_components["analyzer"].analyze(invalid_messages)

    # Test with invalid timestamps
    invalid_messages = [
        {
            "id": "invalid2",
            "text": "Test message",
            "source": "email",
            "timestamp": "invalid-timestamp",
        }
    ]

    with pytest.raises(ValueError):
        analysis_components["analyzer"].analyze(invalid_messages)


def test_analysis_output_validation(test_data_dir, analysis_components):
    """Test validation of analysis outputs."""
    messages = analysis_components["extractor"].extract_all()
    results = analysis_components["analyzer"].analyze(messages)

    # Validate risk scores
    assert all(0 <= score <= 1 for score in results["risk_scores"])

    # Validate threat patterns
    assert all(
        isinstance(pattern, dict) and "pattern_type" in pattern
        for pattern in results["threat_patterns"]
    )

    # Validate visualization outputs
    visualizations = analysis_components["visualizer"].create_visualizations(
        messages=messages, analysis_results=results
    )

    assert all(
        path.endswith((".html", ".png", ".pdf")) for path in visualizations.values()
    )
