# Installation and Setup Guide

## DMV Scam Analysis Environment

### Overview

This guide provides step-by-step instructions for setting up the analysis environment used in the DMV scam investigation. It covers all required dependencies, tools, and configuration steps needed to reproduce the analysis environment.

## Prerequisites

### System Requirements

- **Operating System**: macOS 12.0+ (ARM64/Intel)
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 10GB free space
- **Python**: 3.9+ required
- **Git**: 2.30.0+

### Development Tools

- Command-line tools (Terminal)
- Text editor or IDE (VS Code recommended)
- Web browser for interactive visualizations
- SQLite database browser (optional)

## Installation Steps

### 1. Python Environment Setup

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.9+ via Homebrew
brew install python@3.9

# Verify Python installation
python3 --version
```

### 2. Project Setup

```bash
# Clone the repository
git clone https://github.com/your-org/dmv-scam-analysis.git
cd dmv-scam-analysis

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt

# Verify installations
python3 -c "import pandas; import matplotlib; import plotly; import seaborn; import numpy; print('All packages installed successfully!')"
```

### 4. Database Configuration

```bash
# Set up SQLite database permissions
chmod 644 data/chat.db

# Test database connection
python3 scripts/test_db_connection.py
```

### 5. Visualization Dependencies

```bash
# Install additional visualization dependencies
pip install notebook  # For Jupyter notebooks
pip install kaleido  # For static image export
pip install -U plotly  # Ensure latest Plotly version
```

## Configuration

### 1. Environment Variables

Create a `.env` file in the project root:

```ini
# Database Configuration
DB_PATH=/path/to/chat.db
EXPORT_PATH=/path/to/exports

# Analysis Configuration
TIMEZONE=America/New_York
DATE_FORMAT="%Y-%m-%d %H:%M:%S"
LOG_LEVEL=INFO

# Visualization Settings
DPI=300
FIG_SIZE_DEFAULT=(12, 8)
INTERACTIVE_PORT=8050
```

### 2. Directory Structure Setup

```bash
# Create necessary directories
mkdir -p data/raw
mkdir -p data/processed
mkdir -p exports/visualizations
mkdir -p exports/reports
mkdir -p logs
```

### 3. Tool Configuration

#### SQLite Configuration

```bash
# Configure SQLite settings
cat << EOF > .sqliterc
.headers on
.mode column
.timer on
EOF
```

#### Matplotlib Configuration

Create `matplotlibrc` in the project root:

```ini
# Figure settings
figure.figsize: 12, 8
figure.dpi: 300
figure.autolayout: True

# Font settings
font.size: 12
font.family: sans-serif

# Save settings
savefig.dpi: 300
savefig.format: png
savefig.bbox: tight
```

## Verification Steps

### 1. Environment Check

```bash
# Run environment verification script
python3 scripts/verify_environment.py
```

### 2. Data Access Test

```bash
# Test data access and processing
python3 scripts/test_data_access.py
```

### 3. Visualization Test

```bash
# Generate test visualization
python3 scripts/test_visualization.py
```

## Common Issues and Solutions

### 1. Database Access

**Issue**: Permission denied when accessing chat.db

```bash
# Solution
chmod 644 data/chat.db
```

### 2. Python Dependencies

**Issue**: Package conflicts

```bash
# Solution
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir
```

### 3. Visualization Errors

**Issue**: Plotly displays not rendering

```bash
# Solution
pip install -U plotly
pip install --upgrade nbformat
```

## Development Environment Setup

### 1. VS Code Configuration

Install recommended extensions:

- Python
- Jupyter
- SQLite
- Git Lens

settings.json configuration:

```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true
}
```

### 2. Git Configuration

```bash
# Configure Git
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Set up Git hooks
cp scripts/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

## Running the Analysis

### 1. Data Processing

```bash
# Process raw data
python3 scripts/process_raw_data.py

# Generate analysis datasets
python3 scripts/generate_analysis_data.py
```

### 2. Generate Visualizations

```bash
# Create all visualizations
python3 scripts/generate_visualizations.py

# Create specific visualization
python3 scripts/generate_visualizations.py --type timeline
```

### 3. Generate Reports

```bash
# Generate all reports
python3 scripts/generate_reports.py

# Generate specific report
python3 scripts/generate_reports.py --type executive
```

## Maintenance and Updates

### 1. Environment Updates

```bash
# Update all packages
pip install -U -r requirements.txt

# Export updated requirements
pip freeze > requirements.txt
```

### 2. Data Updates

```bash
# Update analysis datasets
python3 scripts/update_datasets.py

# Regenerate visualizations
python3 scripts/regenerate_visualizations.py
```

## Support and Documentation

### Additional Resources

- Project Wiki: [Internal Wiki Link]
- API Documentation: [API Docs Link]
- Team Contact: [Team Email]

### Troubleshooting

For additional help:

1. Check the logs in `logs/`
2. Review error messages in terminal
3. Contact the development team

---

**Document Version**: 1.0
**Last Updated**: June 2025
**Author**: [Your Name]
**Status**: Active
