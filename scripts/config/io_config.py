"""
Input/Output Configuration Module
Handles configuration of data input and output parameters.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any
from pathlib import Path
from datetime import datetime
import yaml
import json

@dataclass
class InputConfig:
    """Configuration for input data sources"""
    
    # Required columns and their expected types
    required_columns: Dict[str, str] = field(default_factory=dict)
    
    # Column name mappings (for flexible column names)
    column_mappings: Dict[str, str] = field(default_factory=dict)
    
    # Data validation rules
    validation_rules: Dict[str, List[str]] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Initialize with default values if none provided"""
        if self.required_columns is None:
            self.required_columns = {
                'datetime': 'datetime64[ns]',
                'contact_id': 'str',
                'text': 'str',
                'is_from_me': 'bool'
            }
        
        if self.column_mappings is None:
            self.column_mappings = {
                'timestamp': 'datetime',
                'date': 'datetime',
                'user_id': 'contact_id',
                'message': 'text',
                'content': 'text',
                'is_sent': 'is_from_me',
                'direction': 'is_from_me'
            }
        
        if self.validation_rules is None:
            self.validation_rules = {
                'datetime': ['not_null', 'valid_datetime'],
                'contact_id': ['not_null', 'unique_values'],
                'text': ['not_null'],
                'is_from_me': ['boolean']
            }

@dataclass
class OutputConfig:
    """Configuration for analysis outputs"""
    
    # Base output directory
    output_dir: Path
    
    # Output formats for different components
    formats: Dict[str, str] = field(default_factory=dict)
    
    # File naming patterns
    naming_patterns: Dict[str, str] = field(default_factory=dict)
    
    # Output organization structure
    directory_structure: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Initialize with default values if none provided"""
        if self.formats is None:
            self.formats = {
                'detailed_report': 'json',
                'summary_report': 'txt',
                'statistics': 'json',
                'visualizations': 'html'
            }
        
        if self.naming_patterns is None:
            self.naming_patterns = {
                'detailed_report': 'campaign_analysis_{campaign_name}_{timestamp}',
                'summary_report': 'campaign_summary_{campaign_name}_{timestamp}',
                'statistics': 'campaign_stats_{campaign_name}_{timestamp}',
                'visualizations': 'campaign_viz_{campaign_name}_{timestamp}'
            }
        
        if self.directory_structure is None:
            self.directory_structure = {
                'reports': '{output_dir}/reports',
                'visualizations': '{output_dir}/visualizations',
                'statistics': '{output_dir}/statistics',
                'raw_data': '{output_dir}/raw_data'
            }

class IOConfiguration:
    """Manages input/output configuration for analysis framework"""
    
    def __init__(self, config_file: Optional[Union[str, Path]] = None) -> None:
        """
        Initialize IO configuration
        
        Args:
            config_file: Optional path to configuration file (YAML or JSON)
        """
        self.input_config = InputConfig()
        self.output_config = OutputConfig(Path('./analysis_output'))
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: Union[str, Path]) -> None:
        """Load configuration from file"""
        config_path = Path(config_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        # Load configuration based on file type
        if config_path.suffix == '.yaml' or config_path.suffix == '.yml':
            with open(config_path) as f:
                config = yaml.safe_load(f)
        elif config_path.suffix == '.json':
            with open(config_path) as f:
                config = json.load(f)
        else:
            raise ValueError("Configuration file must be YAML or JSON")
        
        # Update configurations
        if 'input' in config:
            self._update_input_config(config['input'])
        if 'output' in config:
            self._update_output_config(config['output'])
    
    def _update_input_config(self, config: Dict[str, Any]) -> None:
        """Update input configuration"""
        if 'required_columns' in config:
            self.input_config.required_columns.update(config['required_columns'])
        if 'column_mappings' in config:
            self.input_config.column_mappings.update(config['column_mappings'])
        if 'validation_rules' in config:
            self.input_config.validation_rules.update(config['validation_rules'])
    
    def _update_output_config(self, config: Dict[str, Any]) -> None:
        """Update output configuration"""
        if 'output_dir' in config:
            self.output_config.output_dir = Path(config['output_dir'])
        if 'formats' in config:
            self.output_config.formats.update(config['formats'])
        if 'naming_patterns' in config:
            self.output_config.naming_patterns.update(config['naming_patterns'])
        if 'directory_structure' in config:
            self.output_config.directory_structure.update(config['directory_structure'])
    
    def get_output_path(self, output_type: str, campaign_name: str) -> Path:
        """
        Get configured output path for a specific output type
        
        Args:
            output_type: Type of output (e.g., 'detailed_report', 'summary_report')
            campaign_name: Name of the campaign being analyzed
            
        Returns:
            Path: Configured output path
        """
        if output_type not in self.output_config.formats:
            raise ValueError(f"Unknown output type: {output_type}")
        
        # Get base directory
        base_dir = self.output_config.directory_structure.get(
            output_type.split('_')[0],
            str(self.output_config.output_dir)
        ).format(output_dir=self.output_config.output_dir)
        
        # Create directory if it doesn't exist
        Path(base_dir).mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        filename = self.output_config.naming_patterns[output_type].format(
            campaign_name=campaign_name,
            timestamp=datetime.now().strftime('%Y%m%d_%H%M%S')
        )
        
        # Add appropriate extension
        extension = self.output_config.formats[output_type]
        return Path(base_dir) / f"{filename}.{extension}"
    
    def save_config(self, config_file: Union[str, Path]) -> None:
        """Save current configuration to file"""
        config_path = Path(config_file)
        
        config = {
            'input': {
                'required_columns': self.input_config.required_columns,
                'column_mappings': self.input_config.column_mappings,
                'validation_rules': self.input_config.validation_rules
            },
            'output': {
                'output_dir': str(self.output_config.output_dir),
                'formats': self.output_config.formats,
                'naming_patterns': self.output_config.naming_patterns,
                'directory_structure': self.output_config.directory_structure
            }
        }
        
        # Save based on file extension
        if config_path.suffix in ['.yaml', '.yml']:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        elif config_path.suffix == '.json':
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
