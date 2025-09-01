# 🎯 DMV Scam Analysis - CLI Usage Guide

## Quick Start Commands

### 🔍 **Analyze a Single Message**
```bash
python3 dmv_cli_enhanced.py analyze "Your DMV license expires soon. Click here to renew."
```

### 📄 **Batch Analyze Multiple Messages**
```bash
# From a text file (one message per line)
python3 dmv_cli_enhanced.py batch-analyze messages.txt

# From a JSON file
python3 dmv_cli_enhanced.py batch-analyze messages.json -o results.json
```

### 🎮 **Interactive Mode**
```bash
python3 dmv_cli_enhanced.py interactive
```
Then type messages to analyze in real-time!

### 🏥 **System Health Checks**
```bash
python3 dmv_cli_enhanced.py test-system
```

### 💻 **System Information**
```bash
python3 dmv_cli_enhanced.py system-info
```

### 🤖 **Model Status**
```bash
python3 dmv_cli_enhanced.py model-status
```

## Example Output

```
🔍 Analyzing message from cli...
Message: "Your DMV license expires soon. Click here to renew."

✅ THREAT ASSESSMENT: LOW RISK
🎯 Threat Score: 0.000
📊 Confidence: 0.0%
⚡ Analysis Time: 0.105s

🔍 Threat Indicators Detected:
  • Urgency language detected
  • Call-to-action language detected
  • Government/official impersonation

💡 Recommendations:
  • ✅ Message appears legitimate
  • ℹ️ Always verify important information independently
```

## Tips & Tricks

- Use `--save` flag with analyze to save results
- Interactive mode supports commands: 'help', 'status', 'clear', 'quit'
- Batch analysis automatically detects JSON vs text file format
- All results are saved with timestamps for tracking
