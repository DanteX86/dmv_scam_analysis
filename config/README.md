# Configuration System

## Overview

This directory contains the configuration system for the DMV scam analysis project. The configuration is designed to be flexible, environment-aware, and secure.

## Directory Structure

```
config/
├── settings.yaml           # Main configuration file
├── schema.json            # JSON schema for validation
├── environments/          # Environment-specific settings
│   ├── development.yaml
│   ├── staging.yaml
│   └── production.yaml
├── secrets/              # Sensitive configuration (not in VCS)
│   └── encryption.key
└── README.md            # This file
```

## Configuration Files

### Main Settings (settings.yaml)
- Core application settings
- Default values
- Common configuration
- Feature toggles

### Environment Settings (environments/*.yaml)
- Environment-specific overrides
- Local development settings
- Production configurations
- Testing parameters

### Schema (schema.json)
- Configuration validation rules
- Required fields
- Data types
- Value constraints

## Usage

### Basic Usage
```python
from scripts.utils.config_manager import get_config

# Get configuration instance
config = get_config()

# Access configuration values
db_path = config.get('storage.database.path')
model_path = config.get('analysis.ml_models.classifier.model_path')

# Check environment
if config.is_development():
    # Development-specific code
    pass
```

### Environment Variables
Configuration can be overridden using environment variables:
```bash
# Set environment
export ENV=development

# Override configuration
export DMV_ANALYSIS_DATABASE_PATH=/custom/path/to/db
export DMV_ANALYSIS_DEBUG=true
```

### Configuration Validation
```python
# Validate required settings
config.validate_required([
    'storage.database.path',
    'analysis.ml_models.classifier.model_path'
])

# Reload configuration
config.reload()
```

## Configuration Sections

### 1. Environment
```yaml
environment:
  name: development
  debug: true
  timezone: UTC
  encoding: utf-8
```

### 2. Application
```yaml
application:
  name: DMV Scam Analysis
  version: 1.0.0
  description: Analysis toolkit
  max_workers: 4
```

### 3. Storage
```yaml
storage:
  database:
    type: sqlite
    path: data/messages.db
  files:
    raw_data: data/raw/
    processed_data: data/processed/
```

### 4. Analysis
```yaml
analysis:
  ml_models:
    classifier:
      model_path: models/classifier.pkl
      threshold: 0.75
  nlp:
    language: en
    models:
      - en_core_web_sm
```

## Security

### Sensitive Data
- Never commit secrets to VCS
- Use environment variables
- Keep encryption keys secure
- Sanitize logged values

### Configuration Storage
- Separate sensitive configs
- Use appropriate permissions
- Encrypt sensitive values
- Regular key rotation

## Environment Management

### Development
- Debug mode enabled
- Verbose logging
- Mock services
- Local resources

### Production
- Performance optimized
- Security enforced
- Real services
- Production resources

### Testing
- Isolated environment
- Test databases
- Mocked services
- Debug features

## Best Practices

1. Configuration
   - Use YAML for readability
   - Keep configs DRY
   - Version control safe
   - Environment aware

2. Security
   - No secrets in code
   - Use environment vars
   - Validate input
   - Secure storage

3. Maintenance
   - Regular reviews
   - Keep documentation updated
   - Monitor for issues
   - Version control

4. Development
   - Local overrides
   - Easy debugging
   - Quick iteration
   - Clear errors

## Troubleshooting

### Common Issues

1. Configuration Not Found
```python
# Check environment variable
echo $ENV

# Verify file existence
ls config/environments/
```

2. Validation Errors
```python
# Check required fields
config.validate_required(['key.path'])

# Verify schema
config._validate_config()
```

3. Environment Issues
```python
# Print current environment
print(config.environment())

# Check settings
print(config.as_dict())
```

### Support

For configuration issues:
1. Check environment variables
2. Verify file permissions
3. Validate configuration
4. Review error messages

## Additional Resources

### Internal Documentation
- Architecture diagrams
- Deployment guides
- Security policies
- Best practices

### Related Tools
- JSON Schema validators
- YAML linters
- Configuration managers
- Security scanners
