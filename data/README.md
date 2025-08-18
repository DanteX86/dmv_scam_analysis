# Data Directory Structure

This directory contains all data files for the DMV scam analysis project. The directory is organized as follows:

## Directory Structure

```
data/
├── raw/                  # Original, immutable data files
├── interim/             # Intermediate data that has been transformed
├── processed/           # Final, canonical datasets for analysis
├── external/            # Data from external sources
├── backup/              # Dataset version backups
├── versions.json        # Dataset version tracking information
└── README.md           # This file
```

## Data Types

### Raw Data

- Location: `raw/`
- Contains original, untouched data files
- Never modify these files directly
- Format: CSV files with the following columns:
  - message_id: Unique identifier for each message
  - timestamp: Time when the message was recorded
  - message: Raw message text
  - source: Source of the message
  - metadata: Additional contextual information

### Interim Data

- Location: `interim/`
- Contains partially processed data
- Intermediate steps between raw and final datasets
- Includes:
  - Cleaned text files
  - Feature extraction results
  - Temporary analysis outputs

### Processed Data

- Location: `processed/`
- Contains final, cleaned datasets ready for analysis
- Features:
  - Cleaned and normalized text
  - Extracted features
  - Removed PII
  - Added derived variables

### External Data

- Location: `external/`
- Contains third-party data used in analysis
- May include:
  - Reference datasets
  - Validation data
  - Benchmark datasets

### Backup Data

- Location: `backup/`
- Contains versioned backups of datasets
- Managed by data versioning system
- Format: `{dataset_name}_{version_hash}.csv`

## Version Control

Dataset versions are tracked in `versions.json` with the following information:

- Version hash
- Timestamp
- File path
- Version notes
- Parent version (if applicable)
- Creator

## Data Management Scripts

The following scripts are available for data management:

1. `scripts/data_validation.py`

   - Validates data quality and consistency
   - Checks required columns, data types, and value ranges
   - Generates validation reports

2. `scripts/data_preprocessing.py`

   - Cleans and transforms raw data
   - Removes PII
   - Extracts features
   - Generates processed datasets

3. `scripts/data_versioning.py`
   - Manages dataset versions
   - Tracks data lineage
   - Handles backups and restoration

## Usage Guidelines

1. Never modify raw data files directly
2. Always use the preprocessing script for data transformation
3. Validate data before and after processing
4. Create new versions for significant changes
5. Document all data transformations
6. Keep sensitive information out of version control

## File Naming Convention

- Raw files: `YYYYMMDD_description.csv`
- Interim files: `YYYYMMDD_description_stage.csv`
- Processed files: `YYYYMMDD_description_final.csv`
- Version backups: `dataset_name_hash.csv`

## Data Quality Checks

All datasets must pass the following quality checks:

1. Required columns present
2. Correct data types
3. No invalid values
4. PII properly removed
5. Consistent formatting
6. Valid value ranges

## Contact

For questions about the data structure or management:

- Data Manager: [Name]
- Email: [Email]
