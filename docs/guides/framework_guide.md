# Campaign Analysis Framework Guide

## Overview

The Campaign Analysis Framework is a flexible system for analyzing messaging-based campaigns. It provides:

- Configurable input/output handling
- Data validation
- Behavioral analysis
- Automation detection
- Risk assessment

## Configuration

### Input Configuration

The framework supports multiple input formats and configurations:

```yaml
input:
  # Required columns and their data types
  required_columns:
    datetime: datetime64[ns]
    contact_id: str
    text: str
    is_from_me: bool

  # Column name mappings for flexible input
  column_mappings:
    timestamp: datetime
    user_id: contact_id
    message: text
    content: text
    is_sent: is_from_me
    direction: is_from_me
```

### Output Configuration

Configure output formats and locations:

```yaml
output:
  # Base output directory
  output_dir: ./analysis_output

  # Output formats
  formats:
    detailed_report: json
    summary_report: txt
    statistics: json
    visualizations: html
```

## Usage Examples

### Basic Usage

```bash
# Analyze campaign with default settings
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "Campaign_01" \
    --type sms
```

### Custom Configuration

```bash
# Use custom configuration
python scripts/campaign_analyzer.py \
    --input data.json \
    --name "Campaign_01" \
    --config config/custom_config.yaml
```

### Different Output Formats

```bash
# Specify output format
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "Campaign_01" \
    --output-format txt
```

## Input Data Format

### CSV Format

```csv
datetime,contact_id,text,is_from_me
2025-01-01T10:00:00,user123,"Hello",true
2025-01-01T10:05:00,user123,"Response",false
```

### JSON Format

```json
{
  "messages": [
    {
      "datetime": "2025-01-01T10:00:00",
      "contact_id": "user123",
      "text": "Hello",
      "is_from_me": true
    }
  ]
}
```

## Analysis Modules

### 1. Temporal Analysis

- Message timing patterns
- Activity bursts
- Response time analysis
- Weekly/hourly distributions

### 2. Automation Detection

- Timing regularity
- Content similarity
- Volume consistency
- Response predictability

### 3. Risk Assessment

- Behavioral risk scoring
- Threat pattern recognition
- Anomaly detection
- Risk factor identification

## Output Formats

### 1. Detailed JSON Report

```json
{
    "analysis_metadata": {
        "campaign_name": "Campaign_01",
        "analysis_timestamp": "2025-06-27T12:00:00",
        "campaign_type": "sms"
    },
    "temporal_patterns": {...},
    "automation_indicators": {...},
    "risk_assessment": {...}
}
```

### 2. Summary Text Report

```
Campaign Analysis Summary: Campaign_01
====================================

Campaign Overview
----------------
Analysis Date: 2025-06-27T12:00:00
Campaign Type: sms
Total Messages: 1000
Date Range: 2025-01-01 to 2025-06-01

Key Statistics
----------------
Contacts Analyzed: 100
High Risk Contacts: 15.5%
Automated Behavior: 25.0%
```

## Validation

### Input Validation

- Required columns presence
- Data type validation
- Null value checking
- Format consistency

### Output Validation

- Path validation
- Format validation
- Permission checking
- Directory structure

## Error Handling

The framework provides comprehensive error handling:

```python
try:
    results = analyzer.analyze_campaign(data)
except ValidationError as e:
    print(f"Validation error: {e}")
except IOError as e:
    print(f"IO error: {e}")
except Exception as e:
    print(f"Analysis error: {e}")
```

## Configuration Examples

### Different Input Formats

```yaml
# CSV with custom columns
input:
  column_mappings:
    message_time: datetime
    sender_id: contact_id
    message_text: text
    is_outbound: is_from_me

# JSON with nested structure
input:
  json_path:
    datetime: $.message.timestamp
    contact_id: $.sender.id
    text: $.content.text
    is_from_me: $.metadata.direction
```

### Custom Output Structure

```yaml
output:
  directory_structure:
    reports: "{output_dir}/campaign_reports"
    visualizations: "{output_dir}/viz"
    statistics: "{output_dir}/stats"
    raw_data: "{output_dir}/data"
```

## Best Practices

1. **Data Preparation**

   - Validate input data before analysis
   - Handle missing values appropriately
   - Convert timestamps to consistent format

2. **Configuration Management**

   - Use version control for configurations
   - Document custom configurations
   - Validate configurations before use

3. **Output Organization**

   - Use consistent naming patterns
   - Organize outputs by campaign
   - Include timestamps in filenames

4. **Error Handling**
   - Implement proper validation
   - Log errors appropriately
   - Provide clear error messages

## Testing

Run the test suite:

```bash
# Run all tests
python -m pytest tests/

# Run specific test category
python -m pytest tests/test_configuration.py
```

## Troubleshooting

Common issues and solutions:

1. **Invalid Input Format**

   - Check column names match configuration
   - Verify data types are correct
   - Ensure required columns are present

2. **Output Errors**

   - Verify write permissions
   - Check disk space
   - Validate output paths

3. **Configuration Issues**
   - Validate YAML/JSON syntax
   - Check for required fields
   - Verify file paths

## Contributing

Guidelines for contributing:

1. **Code Style**

   - Follow PEP 8
   - Add docstrings
   - Include type hints

2. **Testing**

   - Add tests for new features
   - Maintain test coverage
   - Use appropriate fixtures

3. **Documentation**
   - Update relevant docs
   - Include examples
   - Document edge cases
