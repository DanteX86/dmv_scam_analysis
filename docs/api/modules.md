# Module Documentation

## Message Extractor Module

`scripts/message_extractor.py`

### Overview

The message extractor module handles the extraction of scam messages from various sources and formats them for analysis.

### Classes

#### MessageExtractor

```python
class MessageExtractor:
    """Handles extraction of scam messages from various sources."""

    def __init__(self, db_path: str):
        """
        Initialize message extractor.

        Args:
            db_path: Path to the SQLite database
        """
```

### Key Methods

- `extract_messages()`: Extracts messages from the database
- `filter_messages(start_date: str)`: Filters messages by date
- `sanitize_message(message: str)`: Removes sensitive information

---

## ML Threat Classifier Module

`scripts/ml_threat_classifier.py`

### Overview

Implements machine learning models for classifying scam messages and identifying threat patterns.

### Classes

#### ThreatClassifier

```python
class ThreatClassifier:
    """Classifies scam messages using ML models."""

    def __init__(self, model_path: str):
        """
        Initialize threat classifier.

        Args:
            model_path: Path to the trained model
        """
```

### Key Methods

- `predict(message: str)`: Predicts threat level
- `train(X: np.array, y: np.array)`: Trains the model
- `evaluate(X: np.array, y: np.array)`: Evaluates model performance

---

## NLP Analyzer Module

`scripts/nlp_analyzer.py`

### Overview

Natural Language Processing module for analyzing scam message content and patterns.

### Classes

#### NLPAnalyzer

```python
class NLPAnalyzer:
    """Analyzes text content using NLP techniques."""

    def __init__(self, config: Dict):
        """
        Initialize NLP analyzer.

        Args:
            config: Configuration dictionary
        """
```

### Key Methods

- `extract_entities(text: str)`: Extracts named entities
- `analyze_sentiment(text: str)`: Analyzes message sentiment
- `identify_patterns(text: str)`: Identifies common scam patterns

---

## Behavioral Analyzer Module

`scripts/behavioral_analyzer.py`

### Overview

Analyzes behavioral patterns in scam attempts and generates threat profiles.

### Classes

#### BehaviorAnalyzer

```python
class BehaviorAnalyzer:
    """Analyzes scammer behavior patterns."""

    def __init__(self, data_path: str):
        """
        Initialize behavior analyzer.

        Args:
            data_path: Path to behavioral data
        """
```

### Key Methods

- `analyze_patterns()`: Analyzes behavioral patterns
- `generate_profile()`: Generates threat actor profile
- `identify_tactics()`: Identifies scam tactics

---

## Threat Visualizer Module

`scripts/threat_visualizer.py`

### Overview

Generates visualizations of threat data and analysis results.

### Classes

#### ThreatVisualizer

```python
class ThreatVisualizer:
    """Creates visualizations of threat data."""

    def __init__(self, style_config: Dict):
        """
        Initialize visualizer.

        Args:
            style_config: Visualization style configuration
        """
```

### Key Methods

- `plot_trends()`: Plots trend analysis
- `create_heatmap()`: Creates threat heatmap
- `generate_dashboard()`: Generates interactive dashboard
