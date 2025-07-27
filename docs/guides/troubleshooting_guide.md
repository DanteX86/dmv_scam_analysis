# Troubleshooting Guide
## DMV Scam Analysis Project

### Common Issues and Solutions

#### 1. Environment Setup Issues

##### Python Virtual Environment
**Problem**: Virtual environment activation fails
```bash
# Error: command not found: venv
```
**Solution**:
1. Install virtualenv if not present:
```bash
pip install virtualenv
```
2. Create new virtual environment:
```bash
python3 -m venv venv
```
3. Activate virtual environment:
```bash
source venv/bin/activate  # On Unix/macOS
```

##### Package Installation
**Problem**: Package installation errors
```bash
# Error: Permission denied during pip install
```
**Solution**:
1. Use `--user` flag:
```bash
pip install --user -r requirements.txt
```
2. Or fix permissions:
```bash
sudo chown -R $USER /path/to/project
```

#### 2. Database Access Issues

##### SQLite Permission Errors
**Problem**: Cannot access database file
```bash
# Error: Permission denied: data/chat.db
```
**Solution**:
1. Check file permissions:
```bash
ls -l data/chat.db
```
2. Fix permissions:
```bash
chmod 644 data/chat.db
```
3. Ensure directory permissions:
```bash
chmod 755 data/
```

##### Database Lock Issues
**Problem**: Database is locked
**Solution**:
1. Check for other processes:
```bash
lsof | grep chat.db
```
2. Kill blocking processes if necessary:
```bash
kill -9 <process_id>
```

#### 3. Script Execution Problems

##### Permission Denied
**Problem**: Cannot execute Python scripts
```bash
# Error: Permission denied: ./script.py
```
**Solution**:
1. Add execute permission:
```bash
chmod +x scripts/*.py
```
2. Run with Python interpreter:
```bash
python3 scripts/script.py
```

##### Path Issues
**Problem**: Module not found errors
**Solution**:
1. Add project root to PYTHONPATH:
```bash
export PYTHONPATH="${PYTHONPATH}:${PWD}"
```
2. Use absolute imports in scripts

#### 4. Data Processing Issues

##### Memory Errors
**Problem**: Process killed due to memory usage
**Solution**:
1. Implement batch processing
2. Increase system swap space
3. Use memory-efficient data structures

##### Performance Issues
**Problem**: Slow processing speed
**Solution**:
1. Enable multiprocessing
2. Implement caching
3. Optimize database queries

#### 5. Visualization Problems

##### Display Issues
**Problem**: Plots not showing or corrupted
**Solution**:
1. Check backend:
```python
import matplotlib
matplotlib.get_backend()
```
2. Set appropriate backend:
```python
matplotlib.use('Agg')  # for non-interactive
```

##### Resolution Issues
**Problem**: Low quality output
**Solution**:
1. Set DPI in configuration:
```python
plt.figure(dpi=300)
```
2. Use vector formats:
```python
plt.savefig('output.svg')
```

#### 6. Integration Issues

##### API Connection
**Problem**: Cannot connect to external services
**Solution**:
1. Check network connectivity
2. Verify API credentials
3. Check SSL certificates
4. Implement retry logic

##### Data Format
**Problem**: Data format mismatches
**Solution**:
1. Implement data validation
2. Add format conversion utilities
3. Use schema validation

### Logging and Debugging

#### Enable Debug Logging
```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

#### Log File Location
- Application logs: `logs/app.log`
- Error logs: `logs/error.log`
- Debug logs: `logs/debug.log`

### System Requirements

#### Minimum Requirements
- Python 3.9+
- 8GB RAM
- 10GB free disk space
- macOS 12.0+

#### Recommended Requirements
- Python 3.11+
- 16GB RAM
- 50GB free disk space
- macOS 13.0+

### Contact Support

#### Technical Issues
- GitHub Issues: [Project Issues Page]
- Email: [technical-support@example.com]

#### Documentation
- Wiki: [Project Wiki]
- Documentation: [Project Docs]

---

**Document Version**: 1.0  
**Last Updated**: June 2025  
**Status**: Active  
**Review Date**: December 2025
