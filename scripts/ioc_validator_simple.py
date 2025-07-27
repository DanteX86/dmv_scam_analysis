#!/usr/bin/env python3
"""
IOC Validator - Indicators of Compromise Verification Tool (Standalone Version)
Usage: python ioc_validator_simple.py [options] [input_data]

This script validates various types of indicators of compromise (IOCs) 
against known patterns from the DMV scam analysis.

Author: DMV Scam Analysis Team
Date: July 2025
"""

import re
import sys
import argparse
import json
import hashlib
from datetime import datetime
import socket

# IOC Patterns from the DMV scam analysis
IOC_PATTERNS = {
    'phone_numbers': {
        'patterns': [
            r'\+639\d{9}',  # Philippines Globe/Smart format
            r'\+63\d{10}',  # General Philippines format
        ],
        'description': 'Philippines-based phone numbers',
        'risk_level': 'HIGH'
    },
    'domains': {
        'patterns': [
            r'[a-z]+\.gov-[a-z]+\.vip',  # Government impersonation
            r'pa\.gov-[a-z]+\.vip',     # Pennsylvania specific
            r'gov-[a-z]+\.vip',         # Generic gov impersonation
            r'[a-z]+\.gov\.[a-z]{2,3}', # Fake .gov domains
        ],
        'description': 'Government impersonation domains',
        'risk_level': 'CRITICAL'
    },
    'content_patterns': {
        'patterns': [
            r'(?i)(dmv|department.*motor.*vehicles)',
            r'(?i)(license.*suspend|violation.*notice)',
            r'(?i)(payment.*required|pay.*immediately)',
            r'(?i)(urgent.*payment|overdue.*payment)',
            r'(?i)(government.*notice|official.*notice)',
            r'(?i)(penalty.*avoid|immediate.*action)',
            r'(?i)(fine.*notice|penalty.*fee)',
        ],
        'description': 'Scam message content patterns',
        'risk_level': 'MEDIUM'
    },
    'urls': {
        'patterns': [
            r'https?://[a-z]+\.gov-[a-z]+\.vip',
            r'https?://pa\.gov-[a-z]+\.vip',
            r'https?://.*\.vip/.*gov.*',
        ],
        'description': 'Fraudulent URLs',
        'risk_level': 'HIGH'
    },
    'ips': {
        'patterns': [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        ],
        'description': 'IP addresses',
        'risk_level': 'MEDIUM'
    }
}

# Known malicious indicators from the investigation
KNOWN_MALICIOUS = {
    'phone_numbers': [
        '+639127911810',  # Primary threat actor
    ],
    'domains': [
        'pa.gov-jad.vip',  # Primary fraudulent domain
    ],
    'ips': [
        # Add any identified malicious IPs here
    ]
}

class IOCValidator:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'total_checks': 0,
            'matches': [],
            'risk_score': 0
        }
    
    def validate_pattern(self, input_data, pattern_type):
        """Validate input against specific pattern type"""
        if pattern_type not in IOC_PATTERNS:
            return False, f"Unknown pattern type: {pattern_type}"
        
        pattern_info = IOC_PATTERNS[pattern_type]
        matches = []
        
        for pattern in pattern_info['patterns']:
            if re.search(pattern, input_data):
                matches.append({
                    'pattern': pattern,
                    'match': True,
                    'risk_level': pattern_info['risk_level'],
                    'description': pattern_info['description']
                })
        
        return len(matches) > 0, matches
    
    def validate_all_patterns(self, input_data):
        """Validate input against all pattern types"""
        all_matches = []
        
        for pattern_type in IOC_PATTERNS:
            is_match, matches = self.validate_pattern(input_data, pattern_type)
            if is_match:
                all_matches.extend(matches)
        
        return len(all_matches) > 0, all_matches
    
    def check_known_malicious(self, input_data):
        """Check if input matches known malicious indicators"""
        for category, indicators in KNOWN_MALICIOUS.items():
            if input_data in indicators:
                return True, category
        return False, None
    
    def calculate_risk_score(self, matches):
        """Calculate risk score based on matches"""
        score = 0
        risk_weights = {
            'CRITICAL': 50,
            'HIGH': 30,
            'MEDIUM': 20,
            'LOW': 10
        }
        
        for match in matches:
            score += risk_weights.get(match['risk_level'], 0)
        
        return min(score, 100)  # Cap at 100
    
    def validate_domain_dns(self, domain):
        """Validate domain via DNS lookup"""
        try:
            socket.gethostbyname(domain)
            return True, "Domain resolves"
        except socket.gaierror:
            return False, "Domain does not resolve"
    
    def generate_hash(self, input_data):
        """Generate hash for input data"""
        return {
            'md5': hashlib.md5(input_data.encode()).hexdigest(),
            'sha256': hashlib.sha256(input_data.encode()).hexdigest()
        }
    
    def validate_comprehensive(self, input_data):
        """Comprehensive validation with all checks"""
        result = {
            'input': input_data,
            'timestamp': datetime.now().isoformat(),
            'hashes': self.generate_hash(input_data),
            'pattern_matches': [],
            'known_malicious': False,
            'malicious_category': None,
            'risk_score': 0,
            'recommendations': []
        }
        
        # Check patterns
        is_match, matches = self.validate_all_patterns(input_data)
        if is_match:
            result['pattern_matches'] = matches
            result['risk_score'] = self.calculate_risk_score(matches)
        
        # Check known malicious
        is_malicious, category = self.check_known_malicious(input_data)
        result['known_malicious'] = is_malicious
        result['malicious_category'] = category
        
        # Additional checks based on input type
        if self.is_domain(input_data):
            dns_valid, dns_msg = self.validate_domain_dns(input_data)
            result['dns_resolution'] = {'valid': dns_valid, 'message': dns_msg}
        
        # Generate recommendations
        result['recommendations'] = self.generate_recommendations(result)
        
        return result
    
    def is_domain(self, input_data):
        """Check if input appears to be a domain"""
        return bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_data))
    
    def is_url(self, input_data):
        """Check if input appears to be a URL"""
        return bool(re.match(r'^https?://', input_data))
    
    def generate_recommendations(self, result):
        """Generate security recommendations based on results"""
        recommendations = []
        
        if result['known_malicious']:
            recommendations.append("CRITICAL: This indicator is confirmed malicious - block immediately")
        
        if result['risk_score'] > 70:
            recommendations.append("HIGH RISK: Multiple threat indicators detected")
        elif result['risk_score'] > 40:
            recommendations.append("MEDIUM RISK: Some threat indicators present")
        
        if result['pattern_matches']:
            recommendations.append("Monitor for additional related indicators")
        
        if 'dns_resolution' in result and result['dns_resolution']['valid']:
            recommendations.append("Domain is active - consider blocking at DNS level")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(
        description='IOC Validator - Verify indicators of compromise',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ioc_validator_simple.py "+639127911810"
  python ioc_validator_simple.py "pa.gov-jad.vip"
  python ioc_validator_simple.py "DMV license suspension notice"
  python ioc_validator_simple.py --pattern phone_numbers "+639127911810"
  python ioc_validator_simple.py --json "pa.gov-jad.vip"
        """
    )
    
    parser.add_argument('input_data', help='Data to validate against IOC patterns')
    parser.add_argument('--pattern', choices=list(IOC_PATTERNS.keys()), 
                       help='Specific pattern type to check')
    parser.add_argument('--json', action='store_true', 
                       help='Output results in JSON format')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose output')
    
    args = parser.parse_args()
    
    validator = IOCValidator()
    
    if args.pattern:
        # Single pattern validation
        is_match, matches = validator.validate_pattern(args.input_data, args.pattern)
        
        if args.json:
            result = {
                'input': args.input_data,
                'pattern_type': args.pattern,
                'match': is_match,
                'details': matches if is_match else None
            }
            print(json.dumps(result, indent=2))
        else:
            if is_match:
                print(f"✓ MATCH: '{args.input_data}' matches pattern '{args.pattern}'")
                if args.verbose:
                    for match in matches:
                        print(f"  - Pattern: {match['pattern']}")
                        print(f"  - Risk Level: {match['risk_level']}")
                        print(f"  - Description: {match['description']}")
            else:
                print(f"✗ NO MATCH: '{args.input_data}' does not match pattern '{args.pattern}'")
    else:
        # Comprehensive validation
        result = validator.validate_comprehensive(args.input_data)
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n=== IOC Validation Results ===")
            print(f"Input: {result['input']}")
            print(f"Timestamp: {result['timestamp']}")
            print(f"Risk Score: {result['risk_score']}/100")
            
            if result['known_malicious']:
                print(f"\n🚨 KNOWN MALICIOUS: {result['malicious_category']}")
            
            if result['pattern_matches']:
                print(f"\n📋 Pattern Matches:")
                for match in result['pattern_matches']:
                    print(f"  - {match['description']} ({match['risk_level']})")
            
            if result['recommendations']:
                print(f"\n💡 Recommendations:")
                for rec in result['recommendations']:
                    print(f"  - {rec}")
            
            if args.verbose:
                print(f"\n🔍 Additional Details:")
                print(f"  - MD5: {result['hashes']['md5']}")
                print(f"  - SHA256: {result['hashes']['sha256']}")
                
                if 'dns_resolution' in result:
                    print(f"  - DNS Resolution: {result['dns_resolution']['message']}")

if __name__ == "__main__":
    main()
