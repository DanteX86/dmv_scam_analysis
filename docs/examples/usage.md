# Usage Examples

## Basic Usage

### 1. Message Extraction

Extract messages from the database:

```python
from scripts.message_extractor import MessageExtractor

# Initialize extractor
extractor = MessageExtractor(db_path="data/raw/messages.db")

# Extract recent messages
messages = extractor.extract_messages(
    start_date="2025-01-01",
    end_date="2025-06-27"
)

# Filter and sanitize messages
clean_messages = extractor.filter_messages(messages)
```

### 2. Threat Classification

Classify potential threats:

```python
from scripts.ml_threat_classifier import ThreatClassifier

# Initialize classifier
classifier = ThreatClassifier(model_path="models/threat_classifier.pkl")

# Classify a message
result = classifier.predict(
    message="Urgent: Your DMV registration needs immediate attention..."
)

print(f"Threat Score: {result['threat_score']}")
print(f"Confidence: {result['confidence']}")
```

### 3. Pattern Analysis

Analyze message patterns:

```python
from scripts.nlp_analyzer import NLPAnalyzer

# Initialize analyzer
analyzer = NLPAnalyzer(config={
    "use_spacy": True,
    "models": ["en_core_web_sm"]
})

# Analyze text
analysis = analyzer.analyze_text(
    text="Your license will be suspended unless you pay...",
    features=["entities", "sentiment", "patterns"]
)

# Print results
print("Entities:", analysis["entities"])
print("Sentiment:", analysis["sentiment"])
print("Patterns:", analysis["patterns"])
```

## Advanced Usage

### 1. Behavioral Analysis

Track and analyze scammer behavior:

```python
from scripts.behavioral_analyzer import BehaviorAnalyzer
from datetime import datetime, timedelta

# Initialize analyzer
analyzer = BehaviorAnalyzer(data_path="data/processed/")

# Set analysis timeframe
end_date = datetime.now()
start_date = end_date - timedelta(days=30)

# Analyze behavior patterns
patterns = analyzer.analyze_patterns(
    start_date=start_date,
    end_date=end_date,
    group_by="source"
)

# Generate threat actor profile
profile = analyzer.generate_profile(
    actor_id="ACTOR_123",
    patterns=patterns
)
```

### 2. Visualization

Create analysis visualizations:

```python
from scripts.threat_visualizer import ThreatVisualizer
import pandas as pd

# Initialize visualizer
visualizer = ThreatVisualizer(style_config={
    "theme": "dark",
    "colorscale": "Viridis"
})

# Load data
data = pd.read_csv("data/processed/threat_metrics.csv")

# Create trend plot
fig = visualizer.plot_trends(
    data=data,
    metrics=["threat_score", "message_volume"],
    timeframe="1D"
)

# Generate heatmap
heatmap = visualizer.create_heatmap(
    data=data,
    x_axis="time",
    y_axis="source",
    values="threat_score"
)

# Save visualizations
fig.write_html("reports/threat_trends.html")
heatmap.write_html("reports/threat_heatmap.html")
```

### 3. Custom Pipeline

Create a custom analysis pipeline:

```python
from scripts.message_extractor import MessageExtractor
from scripts.ml_threat_classifier import ThreatClassifier
from scripts.nlp_analyzer import NLPAnalyzer
from scripts.behavioral_analyzer import BehaviorAnalyzer
import pandas as pd

class AnalysisPipeline:
    def __init__(self):
        self.extractor = MessageExtractor(db_path="data/raw/messages.db")
        self.classifier = ThreatClassifier(model_path="models/classifier.pkl")
        self.nlp = NLPAnalyzer(config={"use_spacy": True})
        self.behavior = BehaviorAnalyzer(data_path="data/processed/")

    def run_analysis(self, start_date: str, end_date: str):
        # Extract messages
        messages = self.extractor.extract_messages(
            start_date=start_date,
            end_date=end_date
        )

        # Process each message
        results = []
        for msg in messages.itertuples():
            # Classify threat
            threat = self.classifier.predict(msg.content)

            # Analyze text
            analysis = self.nlp.analyze_text(msg.content)

            # Combine results
            results.append({
                "message_id": msg.message_id,
                "threat_score": threat["threat_score"],
                "sentiment": analysis["sentiment"],
                "entities": analysis["entities"]
            })

        # Create results DataFrame
        results_df = pd.DataFrame(results)

        # Analyze patterns
        patterns = self.behavior.analyze_patterns(results_df)

        return {
            "results": results_df,
            "patterns": patterns
        }

# Use the pipeline
pipeline = AnalysisPipeline()
analysis = pipeline.run_analysis(
    start_date="2025-05-01",
    end_date="2025-06-27"
)
```

## Error Handling

### 1. Handling Extraction Errors

```python
from scripts.message_extractor import MessageExtractor
from scripts.utils.error_handler import handle_extraction_error

try:
    extractor = MessageExtractor(db_path="data/raw/messages.db")
    messages = extractor.extract_messages()
except Exception as e:
    error_info = handle_extraction_error(
        error=e,
        context={
            "operation": "message_extraction",
            "db_path": "data/raw/messages.db"
        }
    )
    log_error(error_info, "logs/extraction_errors.log")
```

### 2. Data Validation

```python
from scripts.utils.validators import validate_data
import pandas as pd

# Load data
data = pd.read_csv("data/raw/messages.csv")

# Define schema
schema = {
    "required_columns": ["message_id", "content", "timestamp"],
    "column_types": {
        "message_id": str,
        "content": str,
        "timestamp": "datetime64[ns]"
    }
}

# Validate data
is_valid, errors = validate_data(data, schema)
if not is_valid:
    print("Validation errors:", errors)
    raise ValueError("Data validation failed")
```

## Configuration

### 1. Loading Configuration

```python
from scripts.utils.config import load_config

# Load main config
config = load_config("config/analysis_config.yaml")

# Load specific configs
preprocessing_config = load_config("config/preprocessing_config.yaml")
model_config = load_config("config/model_config.yaml")

# Use configurations
extractor = MessageExtractor(**config["extraction"])
classifier = ThreatClassifier(**config["classification"])
```

### 2. Updating Configuration

```python
import yaml

def update_config(config_path: str, updates: dict):
    # Load current config
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Update values
    for key, value in updates.items():
        config[key] = value

    # Save updated config
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)

# Update configuration
update_config(
    config_path="config/analysis_config.yaml",
    updates={
        "extraction": {
            "batch_size": 1000,
            "max_retries": 3
        }
    }
)
```
