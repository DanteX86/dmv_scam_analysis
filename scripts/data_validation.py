#!/usr/bin/env python3
"""
Data validation script for DMV scam analysis project.
Validates input data against predefined schemas and quality checks.
"""

import json
import logging
from typing import Any, Dict, List

import pandas as pd
import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ValidationResult:
    """Class to encapsulate validation results."""

    def __init__(self, is_valid: bool, details: Dict[str, Any]) -> None:
        self.is_valid: bool = is_valid
        self.details: Dict[str, Any] = details


class DataValidator:
    """Data validation class for checking data quality and consistency."""

    def __init__(self, config_path: str = "config/data_validation_config.yaml") -> None:
        """Initialize the validator with configuration."""
        self.config: Dict[str, Any] = self._load_config(config_path)
        self.validation_results: Dict[str, Any] = {}

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load validation configuration from YAML file."""
        try:
            with open(config_path, "r") as f:
                data: Any = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}

    def validate_dataframe(self, df: pd.DataFrame, dataset_name: str) -> Dict[str, Any]:
        """
        Validate a pandas DataFrame against defined rules.

        Args:
            df: DataFrame to validate
            dataset_name: Name of the dataset for reporting

        Returns:
            Dictionary containing validation results
        """
        results = {
            "dataset": dataset_name,
            "timestamp": pd.Timestamp.now().isoformat(),
            "checks": [],
        }

        # Check for required columns
        required_cols = self.config.get("required_columns", {}).get(dataset_name, [])
        missing_cols = [col for col in required_cols if col not in df.columns]
        results["checks"].append(
            {
                "check": "required_columns",
                "passed": len(missing_cols) == 0,
                "details": f"Missing columns: {missing_cols}"
                if missing_cols
                else "All required columns present",
            }
        )

        # Check for null values
        null_counts = df.isnull().sum()
        has_nulls = null_counts.any()
        results["checks"].append(
            {
                "check": "null_values",
                "passed": not has_nulls,
                "details": null_counts[null_counts > 0].to_dict()
                if has_nulls
                else "No null values found",
            }
        )

        # Check for empty text in text columns
        empty_text_issues = []
        if "text" in df.columns:
            empty_text_count = df["text"].str.strip().eq("").sum()
            if empty_text_count > 0:
                empty_text_issues.append(
                    f"Found {empty_text_count} messages with empty text"
                )

        results["checks"].append(
            {
                "check": "empty_text",
                "passed": len(empty_text_issues) == 0,
                "details": empty_text_issues
                if empty_text_issues
                else "No empty text found",
            }
        )

        # Check data types
        expected_types = self.config.get("column_types", {}).get(dataset_name, {})
        type_mismatches = []
        for col, expected_type in expected_types.items():
            if col in df.columns:
                actual_type = df[col].dtype.name
                if actual_type != expected_type:
                    type_mismatches.append(
                        f"{col}: expected {expected_type}, got {actual_type}"
                    )

        results["checks"].append(
            {
                "check": "data_types",
                "passed": len(type_mismatches) == 0,
                "details": type_mismatches
                if type_mismatches
                else "All data types match expected",
            }
        )

        # Check value ranges
        range_checks = self.config.get("value_ranges", {}).get(dataset_name, {})
        range_violations = []
        for col, ranges in range_checks.items():
            if col in df.columns:
                min_val, max_val = ranges.get("min"), ranges.get("max")
                if min_val is not None and df[col].min() < min_val:
                    range_violations.append(f"{col} has values below {min_val}")
                if max_val is not None and df[col].max() > max_val:
                    range_violations.append(f"{col} has values above {max_val}")

        results["checks"].append(
            {
                "check": "value_ranges",
                "passed": len(range_violations) == 0,
                "details": range_violations
                if range_violations
                else "All values within expected ranges",
            }
        )

        # Store results
        self.validation_results[dataset_name] = results
        return results

    def validate(self, messages: List[Dict[str, Any]]) -> ValidationResult:
        """
        Validate a list of messages.

        Args:
            messages: List of message dictionaries

        Returns:
            ValidationResult object
        """
        # Convert to DataFrame for validation
        df = pd.DataFrame(messages)

        # Run validation checks
        validation_results = self.validate_dataframe(df, "messages")

        # Determine if all checks passed
        all_passed = all(check["passed"] for check in validation_results["checks"])

        return ValidationResult(all_passed, validation_results)

    def save_validation_report(self, output_path: str) -> None:
        """Save validation results to a JSON file."""
        try:
            with open(output_path, "w") as f:
                json.dump(self.validation_results, f, indent=2)
            logger.info(f"Validation report saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving validation report: {e}")


def main() -> None:
    """Main function to run data validation."""
    validator = DataValidator()

    # Example usage
    try:
        # Validate raw data
        raw_data = pd.read_csv("data/raw/messages.csv")
        raw_results = validator.validate_dataframe(raw_data, "raw_messages")

        # Validate processed data
        processed_data = pd.read_csv("data/processed/cleaned_messages.csv")
        processed_results = validator.validate_dataframe(
            processed_data, "processed_messages"
        )

        # Save validation report
        validator.save_validation_report("data/validation_report.json")

    except Exception as e:
        logger.error(f"Validation failed: {e}")
        raise


if __name__ == "__main__":
    main()
