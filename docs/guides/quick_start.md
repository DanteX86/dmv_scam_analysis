# Quick Start Guide

## Setup

1. **Clone the Repository**
```bash
git clone <repository-url>
cd campaign-analysis-framework
```

2. **Install Dependencies**
```bash
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

3. **Prepare Your Data**
Ensure your data includes these columns:
- datetime: Message timestamp
- contact_id: Unique identifier for each contact
- text: Message content
- is_from_me: Boolean indicating message direction

## Basic Usage

### 1. Simple Analysis
```bash
python scripts/campaign_analyzer.py \
    --input data/messages.csv \
    --name "First_Campaign" \
    --type sms
```

### 2. Custom Configuration
```bash
# Create config file
cat > config.yaml << EOL
input:
  column_mappings:
    timestamp: datetime
    user_id: contact_id
    message: text
output:
  output_dir: ./results
  formats:
    detailed_report: json
    summary_report: txt
EOL

# Run analysis with config
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "Custom_Campaign" \
    --config config.yaml
```

### 3. View Results
```bash
# View summary
cat results/campaign_summary_Custom_Campaign.txt

# Examine detailed report
cat results/campaign_analysis_Custom_Campaign.json
```

## Key Features

### 1. Input Flexibility
- CSV or JSON input
- Configurable column mappings
- Data validation

### 2. Analysis Capabilities
- Temporal pattern analysis
- Automation detection
- Risk assessment

### 3. Output Options
- JSON detailed reports
- Text summaries
- Custom output formats

## Next Steps

1. **Customize Configuration**
   - Edit config/analysis_config.yaml
   - Adjust validation rules
   - Configure output formats

2. **Add Data Sources**
   - Prepare input data
   - Map column names
   - Validate formats

3. **Review Documentation**
   - Check framework_guide.md
   - Review configuration options
   - Explore advanced features

## Common Commands

### Different Input Formats
```bash
# CSV input
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "CSV_Campaign"

# JSON input
python scripts/campaign_analyzer.py \
    --input data.json \
    --name "JSON_Campaign" \
    --input-format json
```

### Output Formats
```bash
# JSON output
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "JSON_Output" \
    --output-format json

# Text output
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "Text_Output" \
    --output-format txt
```

### Analysis Options
```bash
# Specify campaign type
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "SMS_Campaign" \
    --type sms

# Custom output directory
python scripts/campaign_analyzer.py \
    --input data.csv \
    --name "Custom_Output" \
    --output-dir ./my_results
```

## Troubleshooting

### Common Issues

1. **Invalid Input Format**
```bash
# Check data format
head -n 5 data.csv
# Verify column names match configuration
```

2. **Missing Dependencies**
```bash
# Update dependencies
pip install -r requirements.txt
# Check Python version
python --version
```

3. **Output Errors**
```bash
# Check permissions
ls -l results/
# Verify disk space
df -h
```

## Getting Help

1. **Documentation**
   - Read framework_guide.md
   - Check configuration examples
   - Review troubleshooting guide

2. **Test Data**
   - Use sample_messages.json
   - Try example configurations
   - Review test cases

3. **Support**
   - Open GitHub issues
   - Check existing issues
   - Review pull requests
