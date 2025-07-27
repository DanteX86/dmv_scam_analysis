# Analysis Tools Configuration
## DMV Scam Analysis Project

### Overview
This document provides detailed configuration instructions for the analysis tools used in the DMV scam investigation project. Proper configuration ensures efficient execution and accurate analysis results.

## Core Configuration

### 1. Python Environment
- **Python Version**: 3.9+
- **Package Management**: pip, virtualenv

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Database Settings
- **Database Type**: SQLite
- **Database Path**: `data/chat.db`

```ini
# Configure .env file
DB_PATH=/path/to/chat.db
```

### 3. Logging Configuration
- **Logging Level**: INFO
- **Log File Path**: `logs/analysis.log`

```python
# logging_config.py
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("logs/analysis.log"),
                              logging.StreamHandler()])
```

## Analysis Tool Settings

### 4. Sentiment Analysis
- **Threshold**: 0.5
- **Model**: Pre-trained sentiment model

```bash
# Configuration
SENTIMENT_THRESHOLD=0.5
```

### 5. IOC Validation
- **Validation Server**: Remote IOC database
- **Connection String**: `https://ioc-validation.example.com`

```ini
# IOC configuration
IOC_VALIDATION_URL=https://ioc-validation.example.com
```

### 6. Visualization
- **Resolution**: 300 DPI
- **Figure Size**: (12, 8)

```python
# visualization_config.py
VIZ_DPI = 300
VIZ_SIZE = (12, 8)
```

### 7. Risk Assessment
- **Risk Levels**: Low, Medium, High
- **Score Calculation**: Weighted scoring model

```yaml
# risk_config.yaml
risk_levels:
  low: 0-30
  medium: 31-70
  high: 71-100

score_weights:
  government_impersonation: 50
  financial_threats: 30
  infra_compromise: 20
```

## Integration and Deployment

### 8. API Keys and Secrets
- **Secure Storage**: Use environment variables or secure vaults

```bash
# Set API keys
export API_KEY=your_api_key_here
```

### 9. Cron Jobs for Automation
- **Schedule**: Nightly analysis run

```crontab
# Crontab entry
0 3 * * * /path/to/project/scripts/run_analysis.sh
```

### 10. Cloud Deployment
- **Provider**: AWS, GCP, or Azure
- **Environment**: Docker containers for scalability

```dockerfile
# Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "scripts/run_analysis.py"]
```

## Troubleshooting

### Common Issues
- **Python Version Errors**: Make sure virtual environment is activated
- **Database Access Issues**: Check DB_PATH and file permissions
- **Missing Packages**: Reinstall dependencies with pip

### Support
- **Documentation**: Check README.md for setup instructions
- **Contact**: [your-email@example.com] for technical support

---

## Version Control

### Document History
- **Version 1.0** (June 2025): Initial configuration documentation
- **Future versions** will be tracked in CHANGELOG.md

### Review Schedule
- **Monthly configuration review**
- **Annual comprehensive update**

---

**Document Version**: 1.0  
**Last Updated**: June 2025  
**Status**: Active  
**Review Date**: December 2025

