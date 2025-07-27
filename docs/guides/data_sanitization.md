# Data Sanitization and Compliance Procedures
## DMV Scam Analysis Project

### Overview
This document outlines the procedures and requirements for data sanitization in the DMV scam analysis project. These procedures ensure compliance with privacy regulations while maintaining the analytical value of the data.

## 1. Data Classification

### Sensitive Data Categories
1. **Personal Identifiable Information (PII)**
   - Full names
   - Physical addresses
   - Email addresses
   - Phone numbers
   - Driver's license numbers
   - Social Security numbers

2. **Financial Information**
   - Credit card numbers
   - Bank account details
   - Transaction records
   - Payment information

3. **Government-Issued Identifiers**
   - License numbers
   - State ID numbers
   - Passport numbers
   - Tax identification numbers

4. **Device and Network Information**
   - IP addresses
   - Device identifiers
   - MAC addresses
   - Browser fingerprints

## 2. Sanitization Procedures

### 2.1 Text Data Sanitization

#### Regular Expression Patterns
```python
SANITIZATION_PATTERNS = {
    'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
    'phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    'license': r'\b[A-Z]{2}\d{6,8}\b',
    'address': r'\b\d{1,5}\s[A-Za-z\s]{1,30}\s(?:st|ST|street|STREET|ave|AVE|avenue|AVENUE|rd|RD|road|ROAD|blvd|BLVD|boulevard|BOULEVARD)[.,]?\s*(?:[A-Za-z\s]{1,30}[.,]?)?\s*(?:[A-Z]{2}\s*)?\d{5}(?:-\d{4})?\b'
}

def sanitize_text(text: str) -> str:
    """
    Sanitizes text by replacing sensitive information with placeholders.
    
    Args:
        text: Input text containing potentially sensitive information
        
    Returns:
        Sanitized text with placeholders
    """
    sanitized = text
    for data_type, pattern in SANITIZATION_PATTERNS.items():
        sanitized = re.sub(pattern, f'[REDACTED-{data_type.upper()}]', sanitized)
    return sanitized
```

### 2.2 Database Sanitization

#### Sanitization Queries
```sql
-- Example sanitization queries
UPDATE messages SET
    content = REGEXP_REPLACE(content, '\d{3}-\d{2}-\d{4}', '[REDACTED-SSN]'),
    sender = REGEXP_REPLACE(sender, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[REDACTED-EMAIL]');

-- Remove exact timestamps, keep only date
UPDATE messages SET
    timestamp = DATE(timestamp);
```

### 2.3 Data Anonymization

#### Hash Generation
```python
def generate_anonymous_identifier(value: str, salt: str) -> str:
    """
    Generates a consistent but anonymous identifier for a value.
    
    Args:
        value: Original identifier value
        salt: Project-specific salt for hashing
        
    Returns:
        Anonymized identifier
    """
    hash_input = f"{value}{salt}"
    return hashlib.sha256(hash_input.encode()).hexdigest()[:12]
```

## 3. Compliance Requirements

### 3.1 Legal Framework
- Personal information protection
- Data privacy regulations
- Cross-border data handling
- Data retention policies

### 3.2 Documentation Requirements
- Data handling procedures
- Sanitization methods
- Verification processes
- Compliance audits

### 3.3 Audit Trail
```python
class SanitizationAudit:
    def __init__(self, logger):
        self.logger = logger
        
    def log_sanitization_event(self, 
                             data_type: str,
                             count: int,
                             timestamp: datetime) -> None:
        """
        Logs a sanitization event for audit purposes.
        """
        self.logger.info(
            f"Sanitized {count} instances of {data_type} at {timestamp}"
        )
        
    def generate_audit_report(self, 
                            start_date: datetime,
                            end_date: datetime) -> Dict:
        """
        Generates an audit report for a specified time period.
        """
        return {
            'period': f"{start_date} to {end_date}",
            'records_processed': self.get_record_count(),
            'sanitization_events': self.get_sanitization_events(),
            'verification_status': self.verify_sanitization()
        }
```

## 4. Verification Procedures

### 4.1 Automated Verification
```python
def verify_sanitization(data: pd.DataFrame) -> Dict[str, bool]:
    """
    Verifies that all sensitive data has been properly sanitized.
    
    Args:
        data: DataFrame containing potentially sensitive information
        
    Returns:
        Dictionary of verification results by data type
    """
    results = {}
    for data_type, pattern in SANITIZATION_PATTERNS.items():
        matches = data.apply(lambda x: bool(re.search(pattern, str(x)))).any()
        results[data_type] = not matches
    return results
```

### 4.2 Manual Review Process
1. Sample Selection
   - Random sampling of sanitized records
   - Focus on high-risk data categories
   - Cross-section of data types

2. Review Checklist
   - [ ] PII completely removed
   - [ ] Financial data sanitized
   - [ ] Government IDs redacted
   - [ ] Network information anonymized
   - [ ] Temporal data generalized

## 5. Data Retention and Disposal

### 5.1 Retention Policies
- Raw data: 30 days maximum
- Sanitized data: Project duration
- Audit logs: 1 year minimum
- Analysis results: Permanent (sanitized)

### 5.2 Secure Disposal
```python
def secure_delete(file_path: str) -> None:
    """
    Securely deletes a file containing sensitive information.
    
    Args:
        file_path: Path to the file to be deleted
    """
    # Overwrite with random data
    with open(file_path, 'wb') as f:
        f.write(os.urandom(os.path.getsize(file_path)))
    
    # Delete file
    os.remove(file_path)
```

## 6. Implementation Guidelines

### 6.1 Data Processing Pipeline
```python
class DataSanitizationPipeline:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.audit = SanitizationAudit(logger)
        
    def process_dataset(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Processes a dataset through the sanitization pipeline.
        
        Args:
            data: Raw input data
            
        Returns:
            Sanitized dataset
        """
        # 1. Initial sanitization
        sanitized = self.apply_sanitization(data)
        
        # 2. Verification
        verification = verify_sanitization(sanitized)
        
        # 3. Additional processing if needed
        if not all(verification.values()):
            sanitized = self.enhanced_sanitization(sanitized)
        
        # 4. Audit logging
        self.audit.log_sanitization_event(
            data_type='dataset',
            count=len(data),
            timestamp=datetime.now()
        )
        
        return sanitized
```

### 6.2 Quality Assurance
- Regular expression pattern validation
- Sanitization effectiveness testing
- Performance impact assessment
- Error handling and logging

## 7. Compliance Checklist

### 7.1 Pre-Processing
- [ ] Data classification completed
- [ ] Sensitive fields identified
- [ ] Sanitization patterns verified
- [ ] Audit logging configured

### 7.2 Processing
- [ ] All PII removed or anonymized
- [ ] Financial data sanitized
- [ ] Government IDs redacted
- [ ] Network information anonymized
- [ ] Temporal data generalized

### 7.3 Post-Processing
- [ ] Verification procedures completed
- [ ] Audit logs generated
- [ ] Compliance documentation updated
- [ ] Secure disposal confirmed

## 8. Emergency Procedures

### 8.1 Data Breach Response
1. Immediate containment
2. Impact assessment
3. Stakeholder notification
4. Enhanced sanitization
5. Process review and update

### 8.2 Recovery Procedures
```python
def emergency_sanitization(data_path: str) -> None:
    """
    Performs emergency sanitization of data in case of potential exposure.
    
    Args:
        data_path: Path to data requiring emergency sanitization
    """
    # 1. Create secure backup
    backup_path = create_secure_backup(data_path)
    
    # 2. Enhanced sanitization
    apply_enhanced_sanitization(data_path)
    
    # 3. Verification
    verify_emergency_sanitization(data_path)
    
    # 4. Audit logging
    log_emergency_event(data_path)
```

---

## Version Control

### Document History
- Version 1.0 (June 2025): Initial procedures documentation
- Future versions will be tracked in CHANGELOG.md

### Review Schedule
- Monthly procedure review
- Quarterly compliance audit
- Annual comprehensive update

---

**Document Version**: 1.0  
**Last Updated**: June 2025  
**Status**: Active  
**Review Date**: July 2025
