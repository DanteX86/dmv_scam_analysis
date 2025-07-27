# IOC Validator Usage Guide

## Overview
The IOC Validator is a tool to verify indicators of compromise (IOCs) against known patterns from the DMV scam analysis.

## Files
- `ioc_validator.py` - Full-featured version (requires external dependencies)
- `ioc_validator_simple.py` - Standalone version (no external dependencies)

## Usage Examples

### Basic Validation
```bash
# Check phone number
python3 scripts/ioc_validator_simple.py "+639127911810"

# Check domain
python3 scripts/ioc_validator_simple.py "pa.gov-jad.vip"

# Check message content
python3 scripts/ioc_validator_simple.py "DMV license suspension notice"
```

### Pattern-Specific Validation
```bash
# Check only phone number patterns
python3 scripts/ioc_validator_simple.py --pattern phone_numbers "+639127911810"

# Check only domain patterns
python3 scripts/ioc_validator_simple.py --pattern domains "pa.gov-jad.vip"

# Check only content patterns
python3 scripts/ioc_validator_simple.py --pattern content_patterns "urgent payment required"
```

### JSON Output (for integration)
```bash
# JSON output for automation
python3 scripts/ioc_validator_simple.py --json "+639127911810"

# Verbose JSON output
python3 scripts/ioc_validator_simple.py --json --verbose "pa.gov-jad.vip"
```

## Pattern Types
- `phone_numbers` - Philippines-based phone numbers
- `domains` - Government impersonation domains
- `content_patterns` - Scam message content patterns
- `urls` - Fraudulent URLs
- `ips` - IP addresses

## Output Format

### Standard Output
```
=== IOC Validation Results ===
Input: +639127911810
Timestamp: 2025-07-14T02:43:11.892539
Risk Score: 60/100

🚨 KNOWN MALICIOUS: phone_numbers

📋 Pattern Matches:
  - Philippines-based phone numbers (HIGH)

💡 Recommendations:
  - CRITICAL: This indicator is confirmed malicious - block immediately
  - Monitor for additional related indicators
```

### JSON Output
```json
{
  "input": "+639127911810",
  "timestamp": "2025-07-14T02:43:32.890662",
  "hashes": {
    "md5": "76557739c95e04ed701b7401f5d6485f",
    "sha256": "92723fa307475c767ab69a12916ffb8f2ccba938093fc58957850f4a75bd1c68"
  },
  "pattern_matches": [
    {
      "pattern": "\\+639\\d{9}",
      "match": true,
      "risk_level": "HIGH",
      "description": "Philippines-based phone numbers"
    }
  ],
  "known_malicious": true,
  "malicious_category": "phone_numbers",
  "risk_score": 60,
  "recommendations": [
    "CRITICAL: This indicator is confirmed malicious - block immediately",
    "Monitor for additional related indicators"
  ]
}
```

## Risk Levels
- **CRITICAL**: 50 points - Immediate blocking required
- **HIGH**: 30 points - High threat level
- **MEDIUM**: 20 points - Moderate threat level
- **LOW**: 10 points - Low threat level

## Integration Examples

### Bash Integration
```bash
# Check if indicator is malicious
RESULT=$(python3 scripts/ioc_validator_simple.py --json "+639127911810")
IS_MALICIOUS=$(echo "$RESULT" | jq -r '.known_malicious')

if [ "$IS_MALICIOUS" = "true" ]; then
    echo "BLOCKING: Malicious indicator detected"
    # Add blocking logic here
fi
```

### Python Integration
```python
import subprocess
import json

def validate_ioc(indicator):
    result = subprocess.run([
        'python3', 'scripts/ioc_validator_simple.py', 
        '--json', indicator
    ], capture_output=True, text=True)
    
    return json.loads(result.stdout)

# Usage
validation_result = validate_ioc("+639127911810")
if validation_result['known_malicious']:
    print("CRITICAL: Known malicious indicator!")
```

## Known Malicious Indicators
- **Phone Numbers**: +639127911810
- **Domains**: pa.gov-jad.vip
- **IP Addresses**: (None currently identified)

## Adding New Indicators
To add new indicators, modify the `KNOWN_MALICIOUS` dictionary in the script:

```python
KNOWN_MALICIOUS = {
    'phone_numbers': [
        '+639127911810',  # Primary threat actor
        '+639XXXXXXXXX',  # Add new malicious numbers
    ],
    'domains': [
        'pa.gov-jad.vip',  # Primary fraudulent domain
        'new-malicious-domain.com',  # Add new malicious domains
    ],
    'ips': [
        '192.168.1.100',  # Add malicious IP addresses
    ]
}
```

## Performance Notes
- The simple version has no external dependencies
- DNS resolution adds ~1-2 seconds per domain check
- Use `--pattern` flag for faster specific pattern matching
- JSON output is suitable for automated processing
