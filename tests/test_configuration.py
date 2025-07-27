"""
Test suite for configuration and validation components
"""

import unittest
import pandas as pd
import numpy as np
from pathlib import Path
import tempfile
import json
import yaml
from datetime import datetime

from dmv_scam_analysis.utils.config_manager import ConfigManager
from dmv_scam_analysis.utils.validation import DataValidator, OutputValidator, ValidationError

class TestIOConfiguration(unittest.TestCase):
    """Test cases for IO configuration"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_config = {
            'input': {
                'required_columns': {
                    'datetime': 'datetime64[ns]',
                    'contact_id': 'str',
                    'text': 'str',
                    'is_from_me': 'bool'
                },
                'column_mappings': {
                    'timestamp': 'datetime',
                    'user_id': 'contact_id',
                    'message': 'text'
                }
            },
            'output': {
                'output_dir': './test_output',
                'formats': {
                    'detailed_report': 'json',
                    'summary_report': 'txt'
                }
            }
        }
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.test_config, f)
            self.config_file = f.name
    
    def tearDown(self):
        """Clean up test environment"""
        Path(self.config_file).unlink()
    
    def test_load_json_config(self):
        """Test loading JSON configuration"""
        config = IOConfiguration(self.config_file)
        
        self.assertEqual(
            config.input_config.required_columns['datetime'],
            'datetime64[ns]'
        )
        self.assertEqual(
            config.output_config.formats['detailed_report'],
            'json'
        )
    
    def test_load_yaml_config(self):
        """Test loading YAML configuration"""
        # Create YAML config
        yaml_file = Path(self.config_file).with_suffix('.yaml')
        with open(yaml_file, 'w') as f:
            yaml.dump(self.test_config, f)
        
        config = IOConfiguration(str(yaml_file))
        
        self.assertEqual(
            config.input_config.required_columns['datetime'],
            'datetime64[ns]'
        )
        
        yaml_file.unlink()
    
    def test_default_config(self):
        """Test default configuration values"""
        config = IOConfiguration()
        
        self.assertIn('datetime', config.input_config.required_columns)
        self.assertIn('detailed_report', config.output_config.formats)
    
    def test_update_config(self):
        """Test updating configuration"""
        config = IOConfiguration()
        
        new_formats = {
            'detailed_report': 'csv',
            'summary_report': 'json'
        }
        config.output_config.formats.update(new_formats)
        
        self.assertEqual(
            config.output_config.formats['detailed_report'],
            'csv'
        )

class TestDataValidator(unittest.TestCase):
    """Test cases for data validation"""
    
    def setUp(self):
        """Set up test environment"""
        self.validator = DataValidator()
        
        # Create test data
        self.valid_data = pd.DataFrame({
            'datetime': pd.date_range('2025-01-01', periods=3),
            'contact_id': ['user1', 'user2', 'user3'],
            'text': ['msg1', 'msg2', 'msg3'],
            'is_from_me': [True, False, True]
        })
        
        self.invalid_data = pd.DataFrame({
            'timestamp': ['invalid_date', '2025-01-01', '2025-01-02'],
            'user_id': [1, 2, 3],  # Wrong type
            'content': ['msg1', None, 'msg3'],  # Contains null
            'is_from_me': [1, 'true', 0]  # Mixed types
        })
    
    def test_valid_data(self):
        """Test validation of valid data"""
        results = self.validator.validate_input_data(self.valid_data)
        
        self.assertTrue(results['is_valid'])
        self.assertEqual(len(results['errors']), 0)
    
    def test_invalid_data(self):
        """Test validation of invalid data"""
        results = self.validator.validate_input_data(self.invalid_data)
        
        self.assertFalse(results['is_valid'])
        self.assertGreater(len(results['errors']), 0)
    
    def test_missing_columns(self):
        """Test validation of missing columns"""
        missing_cols_data = pd.DataFrame({
            'datetime': pd.date_range('2025-01-01', periods=3),
            'text': ['msg1', 'msg2', 'msg3']
        })
        
        results = self.validator.validate_input_data(missing_cols_data)
        
        self.assertFalse(results['is_valid'])
        self.assertTrue(any('Missing required columns' in err for err in results['errors']))
    
    def test_null_values(self):
        """Test validation of null values"""
        null_data = self.valid_data.copy()
        null_data.loc[0, 'text'] = None
        
        results = self.validator.validate_input_data(null_data)
        
        self.assertTrue(any('null values' in warn for warn in results['warnings']))

class TestOutputValidator(unittest.TestCase):
    """Test cases for output validation"""
    
    def setUp(self):
        """Set up test environment"""
        self.validator = OutputValidator()
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_valid_output_format(self):
        """Test validation of valid output formats"""
        self.assertTrue(self.validator.validate_output_format('json'))
        self.assertTrue(self.validator.validate_output_format('txt'))
        self.assertTrue(self.validator.validate_output_format('csv'))
    
    def test_invalid_output_format(self):
        """Test validation of invalid output formats"""
        with self.assertRaises(ValidationError):
            self.validator.validate_output_format('invalid')
    
    def test_output_path_validation(self):
        """Test validation of output paths"""
        valid_path = str(Path(self.test_dir) / 'output.json')
        self.assertTrue(self.validator.validate_output_path(valid_path))

if __name__ == '__main__':
    unittest.main()
