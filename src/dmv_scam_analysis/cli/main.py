"""Command-line interface for DMV scam analysis tools."""
import click
import logging
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..core.classifier import MLThreatClassifier as ThreatClassifier
from ..analysis.behavioral import BehavioralAnalyzer
from ..utils.config_manager import ConfigManager
from ..core.extractor import iMessageAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AnalysisCLI:
    """CLI application class."""
    
    def __init__(self):
        """Initialize the CLI with necessary components"""
        self.config = ConfigManager()
        self.classifier = ThreatClassifier()
        self.analyzer = BehavioralAnalyzer()
        # Initialize extractor with default database path (can be overridden)
        default_db_path = self.config.get('extractor.db_path', '~/Library/Messages/chat.db')
        self.extractor = iMessageAnalyzer(default_db_path)

@click.group()
@click.option('--debug/--no-debug', default=False, help='Enable debug output')
@click.option('--config', type=click.Path(exists=True), help='Path to config file')
@click.pass_context
def cli(ctx, debug: bool, config: Optional[str]):
    """DMV scam analysis toolkit.
    
    This tool provides various commands for analyzing potential DMV-related scams.
    """
    # Initialize logging
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize CLI application
    ctx.obj = AnalysisCLI()
    if config:
        ctx.obj.config = ConfigManager(config)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'csv', 'txt']), default='json')
@click.pass_context
def analyze(ctx, input_file: str, output: Optional[str], format: str):
    """Analyze messages from input file for potential scams."""
    try:
        # Read input file
        messages = ctx.obj.extractor.read_messages(input_file)
        
        # Perform analysis
        results = []
        for message in messages:
            # Get threat score
            threat_score = ctx.obj.classifier.predict([message['text']])[0]
            
            # Get behavioral analysis
            behavior_analysis = ctx.obj.analyzer.analyze([message])
            
            # Combine results
            result = {
                'message_id': message.get('id', 'unknown'),
                'timestamp': message.get('timestamp', datetime.now().isoformat()),
                'threat_score': float(threat_score),
                'risk_level': 'high' if threat_score > 0.7 else 'medium' if threat_score > 0.3 else 'low',
                'indicators': behavior_analysis['indicators'],
                'confidence': behavior_analysis['confidence'],
                'analysis_id': behavior_analysis['analysis_id']
            }
            results.append(result)
        
        # Export results
        if output:
            output_path = Path(output)
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(results, f, indent=2)
            elif format == 'csv':
                import csv
                with open(output_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)
            else:  # txt
                with open(output_path, 'w') as f:
                    for result in results:
                        f.write(f"Message ID: {result['message_id']}\n")
                        f.write(f"Timestamp: {result['timestamp']}\n")
                        f.write(f"Threat Score: {result['threat_score']:.2f}\n")
                        f.write(f"Risk Level: {result['risk_level']}\n")
                        f.write(f"Indicators: {', '.join(result['indicators'])}\n")
                        f.write(f"Confidence: {result['confidence']:.2f}\n")
                        f.write(f"Analysis ID: {result['analysis_id']}\n")
                        f.write("-" * 50 + "\n")
        else:
            # Print to stdout
            click.echo(json.dumps(results, indent=2))
            
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
@click.argument('message_text')
@click.pass_context
def quick_check(ctx, message_text: str):
    """Quickly analyze a single message."""
    try:
        # Get threat score
        threat_score = ctx.obj.classifier.predict([message_text])[0]
        
        # Get behavioral analysis
        analysis = ctx.obj.analyzer.analyze([{'text': message_text}])
        
        # Print results
        click.echo(f"Threat Score: {threat_score:.2f}")
        click.echo(f"Risk Level: {'high' if threat_score > 0.7 else 'medium' if threat_score > 0.3 else 'low'}")
        click.echo(f"Indicators: {', '.join(analysis['indicators'])}")
        click.echo(f"Confidence: {analysis['confidence']:.2f}")
        
    except Exception as e:
        logger.error(f"Quick check failed: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
@click.argument('start_date', type=click.DateTime())
@click.argument('end_date', type=click.DateTime())
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.pass_context
def generate_report(ctx, start_date: datetime, end_date: datetime, output: Optional[str]):
    """Generate analysis report for a date range."""
    try:
        # Get statistics
        stats = ctx.obj.analyzer.get_statistics(start_date, end_date)
        
        # Generate report
        report = {
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'summary': {
                'total_analyzed': stats['total_analyzed'],
                'risk_distribution': stats['risk_distribution'],
                'top_indicators': stats.get('top_indicators', [])
            },
            'trends': {
                'daily_counts': stats.get('trend_data', []),
                'source_distribution': stats.get('source_distribution', {})
            },
            'generated_at': datetime.now().isoformat()
        }
        
        # Export or print report
        if output:
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
        else:
            click.echo(json.dumps(report, indent=2))
            
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.pass_context
def model_info(ctx, output: Optional[str]):
    """Display model information and statistics."""
    try:
        # Get model information
        info = {
            'classifier': {
                'version': ctx.obj.classifier.version,
                'last_updated': ctx.obj.classifier.last_updated,
                'model_type': ctx.obj.classifier.model_type,
                'feature_count': ctx.obj.classifier.feature_count
            },
            'analyzer': {
                'version': ctx.obj.analyzer.version,
                'patterns': len(ctx.obj.analyzer.patterns),
                'indicators': ctx.obj.analyzer.available_indicators
            },
            'performance': {
                'accuracy': ctx.obj.classifier.get_performance_metrics()['accuracy'],
                'precision': ctx.obj.classifier.get_performance_metrics()['precision'],
                'recall': ctx.obj.classifier.get_performance_metrics()['recall'],
                'f1_score': ctx.obj.classifier.get_performance_metrics()['f1_score']
            }
        }
        
        # Export or print info
        if output:
            with open(output, 'w') as f:
                json.dump(info, f, indent=2)
        else:
            click.echo(json.dumps(info, indent=2))
            
    except Exception as e:
        logger.error(f"Model info retrieval failed: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--threshold', '-t', type=float, default=0.7, help='Confidence threshold')
@click.pass_context
def extract_iocs(ctx, input_file: str, threshold: float):
    """Extract indicators of compromise from messages."""
    try:
        # Read input file
        messages = ctx.obj.extractor.read_messages(input_file)
        
        # Extract IOCs
        iocs = ctx.obj.analyzer.extract_iocs(messages, threshold)
        
        # Format results
        results = {
            'urls': iocs.get('urls', []),
            'phone_numbers': iocs.get('phone_numbers', []),
            'email_addresses': iocs.get('email_addresses', []),
            'domains': iocs.get('domains', []),
            'file_hashes': iocs.get('file_hashes', [])
        }
        
        # Print results
        click.echo(json.dumps(results, indent=2))
        
    except Exception as e:
        logger.error(f"IOC extraction failed: {str(e)}", exc_info=True)
        sys.exit(1)

def main():
    """Main entry point for the CLI."""
    try:
        cli(obj=None)
    except Exception as e:
        logger.error(f"CLI execution failed: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
