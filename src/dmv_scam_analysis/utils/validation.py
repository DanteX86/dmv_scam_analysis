"""
Data Validation and Error Handling Module
"""

from typing import Dict, Union, Any, List, Optional, TypedDict
import pandas as pd
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class ValidationResults(TypedDict):
    is_valid: bool
    errors: List[str]
    warnings: List[str]


class ValidationError(Exception):
    """Custom exception for validation errors"""

    pass


class DataValidator:
    """Validates input data against defined rules"""

    def __init__(self, config: Optional[Any] = None) -> None:
        """
        Initialize validator

        Args:
            config: Optional IOConfiguration instance
        """
        self.config = config
        # Ensure concrete types for collections to satisfy mypy
        self.validation_results: ValidationResults = {
            "is_valid": False,
            "errors": [],
            "warnings": [],
        }

    def validate_input_data(self, data: Union[pd.DataFrame, Dict]) -> ValidationResults:
        """
        Validate input data against configuration rules

        Args:
            data: Input data as DataFrame or dict

        Returns:
            dict: Validation results
        """
        self.validation_results = ValidationResults(is_valid=True, errors=[], warnings=[])

        # Convert dict to DataFrame if needed
        if isinstance(data, dict):
            data = pd.DataFrame(data)

        # Validate required columns
        self._validate_required_columns(data)

        # Validate data types
        self._validate_data_types(data)

        # Validate data rules
        self._validate_data_rules(data)

        return self.validation_results

    def _validate_required_columns(self, data: pd.DataFrame) -> None:
        """Validate presence of required columns"""
        if self.config and hasattr(self.config, "input_config"):
            required_columns = self.config.input_config.required_columns
        else:
            required_columns = {
                "datetime": "datetime64[ns]",
                "contact_id": "str",
                "text": "str",
                "is_from_me": "bool",
            }

        missing_columns = [col for col in required_columns if col not in data.columns]

        if missing_columns:
            self.validation_results["is_valid"] = False
            self.validation_results["errors"].append(
                f"Missing required columns: {', '.join(missing_columns)}"
            )

    def _validate_data_types(self, data: pd.DataFrame) -> None:
        """Validate data types of columns"""
        if self.config and hasattr(self.config, "input_config"):
            required_types = self.config.input_config.required_columns
        else:
            required_types = {
                "datetime": "datetime64[ns]",
                "contact_id": "str",
                "text": "str",
                "is_from_me": "bool",
            }

        for column, expected_type in required_types.items():
            if column in data.columns:
                try:
                    if expected_type == "datetime64[ns]":
                        data[column] = pd.to_datetime(data[column])
                    else:
                        # Skip type conversion for columns with null values
                        # The null check will be handled in _validate_data_rules
                        if not data[column].isnull().any():
                            data[column] = data[column].astype(expected_type)
                except Exception as e:
                    self.validation_results["is_valid"] = False
                    self.validation_results["errors"].append(
                        f"Invalid data type for column '{column}': {str(e)}"
                    )

    def _validate_data_rules(self, data: pd.DataFrame) -> None:
        """Validate data against defined rules"""
        if self.config and hasattr(self.config, "input_config"):
            validation_rules = self.config.input_config.validation_rules
        else:
            validation_rules = {
                "datetime": ["not_null", "valid_datetime"],
                "contact_id": ["not_null", "unique_values"],
                "text": ["not_null"],
                "is_from_me": ["boolean"],
            }

        for column, rules in validation_rules.items():
            if column not in data.columns:
                continue

            for rule in rules:
                self._apply_validation_rule(data, column, rule)

    def _apply_validation_rule(self, data: pd.DataFrame, column: str, rule: str) -> None:
        """Apply individual validation rule"""
        if rule == "not_null":
            null_count = data[column].isnull().sum()
            if null_count > 0:
                self.validation_results["warnings"].append(
                    f"Column '{column}' contains {null_count} null values"
                )

        elif rule == "valid_datetime":
            try:
                pd.to_datetime(data[column])
            except Exception as e:
                self.validation_results["is_valid"] = False
                self.validation_results["errors"].append(
                    f"Invalid datetime values in column '{column}': {str(e)}"
                )

        elif rule == "unique_values":
            duplicate_count = len(data) - len(data[column].unique())
            if duplicate_count > 0:
                self.validation_results["warnings"].append(
                    f"Column '{column}' contains {duplicate_count} duplicate values"
                )

        elif rule == "boolean":
            non_bool = data[~data[column].isin([0, 1, True, False])][column]
            if len(non_bool) > 0:
                self.validation_results["is_valid"] = False
                self.validation_results["errors"].append(
                    f"Column '{column}' contains non-boolean values"
                )


class OutputValidator:
    """Validates output data and paths"""

    def __init__(self, config: Optional[Any] = None) -> None:
        """
        Initialize validator

        Args:
            config: Optional IOConfiguration instance
        """
        self.config = config

    def validate_output_path(self, path: str) -> bool:
        """
        Validate output path

        Args:
            path: Output path to validate

        Returns:
            bool: True if valid
        """
        try:
            # Check if path is absolute
            if not path.startswith("/"):
                raise ValidationError("Output path must be absolute")

            # Check if directory exists or can be created
            output_dir = Path(path).parent
            if not output_dir.exists():
                try:
                    output_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    raise ValidationError(f"Cannot create output directory: {str(e)}")

            # Check if we have write permission
            if not os.access(str(output_dir), os.W_OK):
                raise ValidationError("No write permission for output directory")

            return True

        except Exception as e:
            logger.error(f"Output path validation failed: {str(e)}")
            return False

    def validate_output_format(self, format: str) -> bool:
        """
        Validate output format

        Args:
            format: Output format to validate

        Returns:
            bool: True if valid
        """
        valid_formats = ["json", "txt", "html", "csv"]

        if format.lower() not in valid_formats:
            raise ValidationError(
                f"Invalid output format. Must be one of: {', '.join(valid_formats)}"
            )

        return True
