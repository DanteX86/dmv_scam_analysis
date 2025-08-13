#!/usr/bin/env python3
"""
Enhanced CLI Interface for DMV Scam Analysis System
Provides comprehensive command-line tools for threat analysis, model management, and system monitoring.
"""

import os
import sys
import json
import argparse
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add src to Python path
sys.path.insert(0, 'src')

# Import our modules
try:
    from src.dmv_scam_analysis.core.classifier import MLThreatClassifier
    from src.dmv_scam_analysis.core.model_manager import ModelManager
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules not available: {e}")
    MODULES_AVAILABLE = False


class EnhancedCLI:
    """Enhanced command-line interface for DMV scam analysis."""
    
    def __init__(self):
        """Initialize CLI interface."""
        self.classifier = None
        self.model_manager = None
        
        if MODULES_AVAILABLE:
            try:
                self.classifier = MLThreatClassifier()
                self.model_manager = ModelManager()
            except Exception as e:
                print(f"Warning: Failed to initialize components: {e}")
    
    def analyze_message(self, args) -> None:
        """Analyze a single message for threats."""
        if not self.classifier:
            print("❌ Error: Classifier not available")
            return
        
        message = args.message
        source = args.source or 'cli'
        
        try:
            print(f"🔍 Analyzing message from {source}...")
            print(f"Message: \"{message[:100]}{'...' if len(message) > 100 else ''}\"")
            print("-" * 50)
            
            start_time = time.time()
            
            # Get prediction
            prediction = self.classifier.predict([message])
            threat_score = float(prediction[0])
            
            # Determine classification
            if threat_score > 0.7:
                classification = "HIGH RISK"
                risk_emoji = "🚨"
                color_code = "\033[91m"  # Red
            elif threat_score > 0.3:
                classification = "MEDIUM RISK"
                risk_emoji = "⚠️"
                color_code = "\033[93m"  # Yellow
            else:
                classification = "LOW RISK"
                risk_emoji = "✅"
                color_code = "\033[92m"  # Green
            
            analysis_time = time.time() - start_time
            
            # Reset color
            reset_code = "\033[0m"
            
            # Display results
            print(f"\n{risk_emoji} {color_code}THREAT ASSESSMENT: {classification}{reset_code}")
            print(f"🎯 Threat Score: {threat_score:.3f}")
            print(f"📊 Confidence: {min(threat_score * 100, 100):.1f}%")
            print(f"⚡ Analysis Time: {analysis_time:.3f}s")
            
            # Additional analysis
            threat_indicators = self._extract_threat_indicators(message, threat_score)
            if threat_indicators:
                print(f"\n🔍 Threat Indicators Detected:")
                for indicator in threat_indicators:
                    print(f"  • {indicator}")
            
            # Recommendations
            print(f"\n💡 Recommendations:")
            if threat_score > 0.7:
                print("  • ❌ DO NOT respond to this message")
                print("  • 🚨 Report as potential scam")
                print("  • 🛡️ Block sender if possible")
            elif threat_score > 0.3:
                print("  • ⚠️ Exercise caution")
                print("  • 🔍 Verify sender independently")
                print("  • 📞 Contact official sources directly")
            else:
                print("  • ✅ Message appears legitimate")
                print("  • ℹ️ Always verify important information independently")
            
            if args.save:
                self._save_analysis_result({
                    'message': message,
                    'source': source,
                    'threat_score': threat_score,
                    'classification': classification.lower().replace(' ', '_'),
                    'indicators': threat_indicators,
                    'timestamp': datetime.now().isoformat(),
                    'analysis_time': analysis_time
                })
                print(f"\n💾 Analysis results saved to analysis_results.json")
        
        except Exception as e:
            print(f"❌ Error during analysis: {e}")
    
    def batch_analyze(self, args) -> None:
        """Analyze multiple messages from a file."""
        if not self.classifier:
            print("❌ Error: Classifier not available")
            return
        
        input_file = args.file
        if not os.path.exists(input_file):
            print(f"❌ Error: File {input_file} not found")
            return
        
        try:
            print(f"📄 Processing batch analysis from {input_file}...")
            
            # Load messages
            with open(input_file, 'r') as f:
                if input_file.endswith('.json'):
                    data = json.load(f)
                    if isinstance(data, list):
                        messages = [item['text'] if isinstance(item, dict) else str(item) for item in data]
                    else:
                        messages = [data['text']] if 'text' in data else [str(data)]
                else:
                    messages = [line.strip() for line in f.readlines() if line.strip()]
            
            print(f"📊 Found {len(messages)} messages to analyze")
            print("-" * 50)
            
            results = []
            high_risk_count = 0
            medium_risk_count = 0
            low_risk_count = 0
            
            for i, message in enumerate(messages):
                try:
                    prediction = self.classifier.predict([message])
                    threat_score = float(prediction[0])
                    
                    if threat_score > 0.7:
                        classification = "high_risk"
                        high_risk_count += 1
                        risk_emoji = "🚨"
                    elif threat_score > 0.3:
                        classification = "medium_risk"
                        medium_risk_count += 1
                        risk_emoji = "⚠️"
                    else:
                        classification = "low_risk"
                        low_risk_count += 1
                        risk_emoji = "✅"
                    
                    result = {
                        'id': i + 1,
                        'message': message[:100] + ('...' if len(message) > 100 else ''),
                        'threat_score': threat_score,
                        'classification': classification,
                        'timestamp': datetime.now().isoformat()
                    }
                    results.append(result)
                    
                    print(f"{risk_emoji} Message {i+1}: {classification.upper()} (Score: {threat_score:.3f})")
                    
                except Exception as e:
                    print(f"❌ Error analyzing message {i+1}: {e}")
            
            # Summary
            print("\n" + "=" * 50)
            print("📊 BATCH ANALYSIS SUMMARY")
            print("=" * 50)
            print(f"Total Messages: {len(messages)}")
            print(f"🚨 High Risk: {high_risk_count}")
            print(f"⚠️ Medium Risk: {medium_risk_count}")
            print(f"✅ Low Risk: {low_risk_count}")
            
            if high_risk_count > 0:
                print(f"\n🔥 ALERT: {high_risk_count} high-risk messages detected!")
            
            # Save results
            output_file = args.output or 'batch_analysis_results.json'
            with open(output_file, 'w') as f:
                json.dump({
                    'summary': {
                        'total_messages': len(messages),
                        'high_risk_count': high_risk_count,
                        'medium_risk_count': medium_risk_count,
                        'low_risk_count': low_risk_count
                    },
                    'results': results,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)
            
            print(f"💾 Results saved to {output_file}")
        
        except Exception as e:
            print(f"❌ Error during batch analysis: {e}")
    
    def model_status(self, args) -> None:
        """Display model status and information."""
        if not self.model_manager:
            print("❌ Error: Model manager not available")
            return
        
        try:
            print("🤖 MODEL STATUS")
            print("=" * 50)
            
            # List all models
            models = self.model_manager.list_models()
            print(f"📦 Total Models: {len(models)}")
            
            if models:
                print("\n📋 Available Models:")
                for model in models[:10]:  # Show first 10
                    status_emoji = "🟢" if model.get('status') == 'active' else "⚪"
                    print(f"  {status_emoji} {model['model_name']} v{model['version']}")
                    print(f"     Created: {model['created_at'][:19]}")
                    print(f"     Size: {model.get('file_size', 0) / 1024:.1f} KB")
                    if model.get('performance_metrics'):
                        metrics = model['performance_metrics']
                        print(f"     Accuracy: {metrics.get('accuracy', 'N/A')}")
                    print()
            
            # Active model
            try:
                _, model_info, model_id = self.model_manager.get_active_model()
                print(f"🎯 Active Model: {model_id}")
                print(f"   Status: 🟢 ACTIVE")
                print(f"   File: {model_info['file_path']}")
                if model_info.get('performance_metrics'):
                    metrics = model_info['performance_metrics']
                    print(f"   Performance: Accuracy {metrics.get('accuracy', 'N/A')}")
            except Exception:
                print("⚠️ No active model set")
            
            # System info
            print(f"\n💻 System Information:")
            print(f"   Models Directory: {self.model_manager.model_dir}")
            print(f"   Metadata File: {'✅ Found' if self.model_manager.metadata_file.exists() else '❌ Missing'}")
            
        except Exception as e:
            print(f"❌ Error retrieving model status: {e}")
    
    def system_info(self, args) -> None:
        """Display comprehensive system information."""
        print("🖥️ DMV SCAM ANALYSIS SYSTEM INFO")
        print("=" * 50)
        
        # System status
        print("🔧 Component Status:")
        print(f"   ML Classifier: {'✅ Available' if self.classifier else '❌ Unavailable'}")
        print(f"   Model Manager: {'✅ Available' if self.model_manager else '❌ Unavailable'}")
        
        # Directory structure
        print(f"\n📁 Directory Structure:")
        key_paths = ['src', 'models', 'data', 'logs', 'analysis_output', 'visualizations']
        for path in key_paths:
            exists = os.path.exists(path)
            emoji = "✅" if exists else "❌"
            print(f"   {path}/: {emoji} {'Found' if exists else 'Missing'}")
        
        # Configuration files
        print(f"\n⚙️ Configuration Files:")
        config_files = ['requirements.txt', 'Dockerfile', 'docker-compose.yml', 'pyproject.toml']
        for file in config_files:
            exists = os.path.exists(file)
            emoji = "✅" if exists else "❌"
            print(f"   {file}: {emoji} {'Found' if exists else 'Missing'}")
        
        # Performance test
        if self.classifier:
            print(f"\n⚡ Performance Test:")
            test_message = "Test message for performance measurement"
            start_time = time.time()
            try:
                prediction = self.classifier.predict([test_message])
                elapsed = time.time() - start_time
                print(f"   Prediction Time: {elapsed:.3f}s")
                print(f"   Performance: {'✅ Good' if elapsed < 1.0 else '⚠️ Slow' if elapsed < 2.0 else '❌ Critical'}")
            except Exception as e:
                print(f"   Performance Test: ❌ Failed ({e})")
        
        # Memory and disk info
        print(f"\n💾 Storage Information:")
        try:
            import shutil
            total, used, free = shutil.disk_usage(".")
            print(f"   Disk Space: {free // (2**30)} GB free of {total // (2**30)} GB total")
        except:
            print("   Disk Space: Unable to determine")
    
    def test_system(self, args) -> None:
        """Run comprehensive system tests."""
        print("🧪 DMV SCAM ANALYSIS SYSTEM TESTS")
        print("=" * 50)
        
        test_results = {'total': 0, 'passed': 0, 'failed': 0}
        
        # Test 1: Component Loading
        print("🔧 Test 1: Component Loading")
        test_results['total'] += 1
        if self.classifier and self.model_manager:
            print("   ✅ PASSED: All components loaded successfully")
            test_results['passed'] += 1
        else:
            print("   ❌ FAILED: Some components failed to load")
            test_results['failed'] += 1
        
        # Test 2: Basic Prediction
        if self.classifier:
            print("🎯 Test 2: Basic Prediction")
            test_results['total'] += 1
            try:
                test_messages = [
                    "Your DMV license expires soon. Click here to renew.",
                    "Thank you for visiting the DMV office."
                ]
                predictions = [self.classifier.predict([msg]) for msg in test_messages]
                print("   ✅ PASSED: Predictions generated successfully")
                print(f"   Scores: {[float(p[0]) for p in predictions]}")
                test_results['passed'] += 1
            except Exception as e:
                print(f"   ❌ FAILED: Prediction error - {e}")
                test_results['failed'] += 1
        
        # Test 3: Model Management
        if self.model_manager:
            print("📦 Test 3: Model Management")
            test_results['total'] += 1
            try:
                models = self.model_manager.list_models()
                print(f"   ✅ PASSED: Found {len(models)} models")
                test_results['passed'] += 1
            except Exception as e:
                print(f"   ❌ FAILED: Model management error - {e}")
                test_results['failed'] += 1
        
        # Test 4: File System Access
        print("📁 Test 4: File System Access")
        test_results['total'] += 1
        try:
            test_file = 'system_test.tmp'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print("   ✅ PASSED: File system read/write access")
            test_results['passed'] += 1
        except Exception as e:
            print(f"   ❌ FAILED: File system error - {e}")
            test_results['failed'] += 1
        
        # Results summary
        print("\n" + "=" * 50)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 50)
        print(f"Total Tests: {test_results['total']}")
        print(f"✅ Passed: {test_results['passed']}")
        print(f"❌ Failed: {test_results['failed']}")
        
        success_rate = (test_results['passed'] / test_results['total']) * 100
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 75:
            print("🎉 System Status: HEALTHY")
        elif success_rate >= 50:
            print("⚠️ System Status: NEEDS ATTENTION")
        else:
            print("🚨 System Status: CRITICAL")
    
    def interactive_mode(self, args) -> None:
        """Enter interactive analysis mode."""
        print("🎯 DMV SCAM ANALYSIS - INTERACTIVE MODE")
        print("=" * 50)
        print("Enter messages to analyze (type 'quit' to exit)")
        print("Commands: 'help', 'status', 'clear', 'quit'")
        print("-" * 50)
        
        session_results = []
        
        while True:
            try:
                user_input = input("\n📝 Enter message > ").strip()
                
                if user_input.lower() == 'quit':
                    break
                elif user_input.lower() == 'help':
                    print("\n💡 Available Commands:")
                    print("  - Type any message to analyze it")
                    print("  - 'status' - Show session statistics")
                    print("  - 'clear' - Clear session history")
                    print("  - 'quit' - Exit interactive mode")
                    continue
                elif user_input.lower() == 'status':
                    high_risk = sum(1 for r in session_results if r['threat_score'] > 0.7)
                    medium_risk = sum(1 for r in session_results if 0.3 < r['threat_score'] <= 0.7)
                    low_risk = sum(1 for r in session_results if r['threat_score'] <= 0.3)
                    
                    print(f"\n📊 Session Statistics:")
                    print(f"   Total Analyzed: {len(session_results)}")
                    print(f"   🚨 High Risk: {high_risk}")
                    print(f"   ⚠️ Medium Risk: {medium_risk}")
                    print(f"   ✅ Low Risk: {low_risk}")
                    continue
                elif user_input.lower() == 'clear':
                    session_results.clear()
                    print("🧹 Session history cleared")
                    continue
                elif not user_input:
                    continue
                
                if not self.classifier:
                    print("❌ Classifier not available")
                    continue
                
                # Analyze the message
                start_time = time.time()
                prediction = self.classifier.predict([user_input])
                threat_score = float(prediction[0])
                analysis_time = time.time() - start_time
                
                # Determine classification
                if threat_score > 0.7:
                    classification = "HIGH RISK"
                    risk_emoji = "🚨"
                elif threat_score > 0.3:
                    classification = "MEDIUM RISK"
                    risk_emoji = "⚠️"
                else:
                    classification = "LOW RISK"
                    risk_emoji = "✅"
                
                # Store result
                result = {
                    'message': user_input,
                    'threat_score': threat_score,
                    'classification': classification,
                    'analysis_time': analysis_time,
                    'timestamp': datetime.now().isoformat()
                }
                session_results.append(result)
                
                # Display result
                print(f"\n{risk_emoji} Result: {classification}")
                print(f"   Score: {threat_score:.3f} | Time: {analysis_time:.3f}s")
                
                # Quick recommendation
                if threat_score > 0.7:
                    print("   🚨 Recommendation: Treat as scam")
                elif threat_score > 0.3:
                    print("   ⚠️ Recommendation: Verify independently")
                else:
                    print("   ✅ Recommendation: Appears legitimate")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Error: {e}")
        
        # Save session
        if session_results:
            session_file = f"interactive_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(session_file, 'w') as f:
                json.dump(session_results, f, indent=2)
            print(f"\n💾 Session saved to {session_file}")
        
        print("\n👋 Exiting interactive mode")
    
    def _extract_threat_indicators(self, message: str, threat_score: float) -> List[str]:
        """Extract potential threat indicators from a message."""
        indicators = []
        
        # Convert to lowercase for analysis
        text_lower = message.lower()
        
        # Common threat indicators
        urgent_words = ['urgent', 'immediate', 'expires', 'suspend', 'deadline', 'act now']
        financial_words = ['payment', 'fee', 'fine', 'penalty', '$', 'cost', 'charge']
        action_words = ['click', 'link', 'verify', 'confirm', 'update', 'call now']
        government_words = ['dmv', 'license', 'registration', 'government', 'official']
        
        if any(word in text_lower for word in urgent_words):
            indicators.append("Urgency language detected")
        
        if any(word in text_lower for word in financial_words):
            indicators.append("Financial terms detected")
        
        if any(word in text_lower for word in action_words):
            indicators.append("Call-to-action language detected")
        
        if any(word in text_lower for word in government_words):
            indicators.append("Government/official impersonation")
        
        # URL detection
        if 'http' in text_lower or 'www.' in text_lower:
            indicators.append("External links present")
        
        # Phone number patterns
        import re
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        if re.search(phone_pattern, message):
            indicators.append("Phone number present")
        
        # High threat score
        if threat_score > 0.8:
            indicators.append("High ML confidence score")
        
        return indicators
    
    def _save_analysis_result(self, result: Dict[str, Any]) -> None:
        """Save analysis result to file."""
        results_file = 'analysis_results.json'
        
        # Load existing results
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                try:
                    results = json.load(f)
                    if not isinstance(results, list):
                        results = [results]
                except:
                    results = []
        else:
            results = []
        
        # Add new result
        results.append(result)
        
        # Keep only last 100 results
        if len(results) > 100:
            results = results[-100:]
        
        # Save
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='DMV Scam Analysis System - Enhanced CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze "Your DMV license expires soon. Click here to renew."
  %(prog)s batch-analyze messages.txt
  %(prog)s interactive
  %(prog)s status
  %(prog)s test-system
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single message')
    analyze_parser.add_argument('message', help='Message to analyze')
    analyze_parser.add_argument('-s', '--source', default='cli', help='Message source (default: cli)')
    analyze_parser.add_argument('--save', action='store_true', help='Save analysis results')
    
    # Batch analyze command
    batch_parser = subparsers.add_parser('batch-analyze', help='Analyze multiple messages from file')
    batch_parser.add_argument('file', help='Input file (text or JSON)')
    batch_parser.add_argument('-o', '--output', help='Output file for results')
    
    # Model status command
    subparsers.add_parser('model-status', help='Show model status and information')
    
    # System info command
    subparsers.add_parser('system-info', help='Show comprehensive system information')
    
    # Test system command
    subparsers.add_parser('test-system', help='Run system health tests')
    
    # Interactive mode command
    subparsers.add_parser('interactive', help='Enter interactive analysis mode')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = EnhancedCLI()
    
    # Route to appropriate command
    if args.command == 'analyze':
        cli.analyze_message(args)
    elif args.command == 'batch-analyze':
        cli.batch_analyze(args)
    elif args.command == 'model-status':
        cli.model_status(args)
    elif args.command == 'system-info':
        cli.system_info(args)
    elif args.command == 'test-system':
        cli.test_system(args)
    elif args.command == 'interactive':
        cli.interactive_mode(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
