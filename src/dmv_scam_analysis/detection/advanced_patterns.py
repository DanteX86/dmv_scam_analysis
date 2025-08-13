"""
Enhanced Threat Detection Patterns
Advanced pattern matching for sophisticated scam detection.
"""

import re
from typing import Dict, List, Tuple, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AdvancedThreatPatterns:
    """Advanced threat detection patterns for sophisticated scam identification."""
    
    def __init__(self):
        """Initialize advanced threat detection patterns."""
        self.setup_patterns()
        
    def setup_patterns(self):
        """Setup comprehensive threat detection patterns."""
        
        # Government impersonation patterns
        self.government_patterns = {
            'dmv_specific': [
                r'\b(dmv|motor vehicle|drivers?\s*licen[sc]e|vehicle\s*registration)\b',
                r'\b(pennsylvania\s*dmv|pa\s*dmv|state\s*dmv)\b',
                r'\b(licen[sc]e\s*expir|registration\s*due|vehicle\s*tag)\b'
            ],
            'official_language': [
                r'\b(department\s*of|state\s*of|government|official|authority)\b',
                r'\b(notification|notice|alert|warning|violation)\b',
                r'\b(compliance|mandatory|required|regulation)\b'
            ]
        }
        
        # Urgency and pressure tactics
        self.urgency_patterns = {
            'time_pressure': [
                r'\b(urgent|immediate|asap|right\s*away|now|today)\b',
                r'\b(expir[ei]s?\s*(today|tomorrow|soon|in\s*\d+\s*days?))\b',
                r'\b(deadline|time\s*limit|last\s*chance|final\s*notice)\b',
                r'\b(act\s*now|respond\s*immediately|dont\s*delay)\b'
            ],
            'consequences': [
                r'\b(suspend|revok|cancel|terminat|forfeit)\b',
                r'\b(penalty|fine|fee|charge|arrest|legal\s*action)\b',
                r'\b(lose|loss|miss|avoid|prevent|stop)\b'
            ]
        }
        
        # Financial and action indicators
        self.financial_patterns = {
            'payment_requests': [
                r'\$\d+|\b\d+\s*dollars?\b|\bmoney\b|\bpay\b|\bfee\b|\bcost\b',
                r'\b(credit\s*card|debit\s*card|bank|account)\b',
                r'\b(payment|transaction|billing|invoice)\b'
            ],
            'action_requests': [
                r'\b(click|tap|visit|go\s*to|navigate)\b',
                r'\b(link|url|website|site|page)\b',
                r'\b(verify|confirm|update|provide|enter)\b',
                r'\b(call|phone|contact|reach\s*out)\b'
            ]
        }
        
        # Suspicious communication patterns
        self.suspicious_patterns = {
            'poor_grammar': [
                r'\b(recieve|seperate|occured|neccessary|buisness)\b',  # Common misspellings
                r'\b(thier|freind|wierd|definately|alot)\b',
                r'[.]{2,}|\s{3,}',  # Multiple periods or spaces
            ],
            'generic_language': [
                r'\b(dear\s*(customer|user|resident|citizen))\b',
                r'\b(account\s*holder|valued\s*(customer|member))\b',
                r'\b(this\s*is\s*to\s*inform|we\s*are\s*contacting)\b'
            ],
            'suspicious_domains': [
                r'bit\.ly|tinyurl|t\.co|goo\.gl|short\.link',
                r'[a-z0-9-]+\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs
                r'gov-[a-z]+\.(com|net|org|info)',  # Fake government domains
            ]
        }
        
        # Advanced evasion techniques
        self.evasion_patterns = {
            'character_substitution': [
                r'g0v[e3]rnm[e3]nt|[0o]fficial|d[m]v',  # Character substitutions
                r'[il1|]\s*[il1|]\s*c[e3]ns[e3]',  # Spaced out license
                r'p[a@4]y\s*m[e3]nt|f[e3][e3]',  # Payment with substitutions
            ],
            'unicode_tricks': [
                r'[\u200b-\u200d\ufeff]',  # Zero-width characters
                r'[а-я]',  # Cyrillic characters that look like Latin
            ]
        }
    
    def analyze_message(self, message: str) -> Dict[str, Any]:
        """
        Perform advanced threat analysis on a message.
        
        Args:
            message: The message text to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'threat_indicators': [],
            'risk_factors': {},
            'pattern_matches': {},
            'overall_score': 0.0,
            'confidence': 0.0
        }
        
        # Convert to lowercase for pattern matching
        text_lower = message.lower()
        
        # Analyze each pattern category
        results['pattern_matches']['government'] = self._check_patterns(
            text_lower, self.government_patterns
        )
        results['pattern_matches']['urgency'] = self._check_patterns(
            text_lower, self.urgency_patterns
        )
        results['pattern_matches']['financial'] = self._check_patterns(
            text_lower, self.financial_patterns
        )
        results['pattern_matches']['suspicious'] = self._check_patterns(
            text_lower, self.suspicious_patterns
        )
        results['pattern_matches']['evasion'] = self._check_patterns(
            text_lower, self.evasion_patterns
        )
        
        # Calculate risk factors
        results['risk_factors'] = self._calculate_risk_factors(results['pattern_matches'])
        
        # Extract specific threat indicators
        results['threat_indicators'] = self._extract_threat_indicators(
            message, results['pattern_matches']
        )
        
        # Calculate overall threat score
        results['overall_score'] = self._calculate_threat_score(results['risk_factors'])
        results['confidence'] = self._calculate_confidence(results['pattern_matches'])
        
        return results
    
    def _check_patterns(self, text: str, pattern_dict: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Check text against pattern dictionary."""
        matches = {}
        
        for category, patterns in pattern_dict.items():
            category_matches = []
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    category_matches.append(pattern)
            matches[category] = category_matches
            
        return matches
    
    def _calculate_risk_factors(self, pattern_matches: Dict) -> Dict[str, float]:
        """Calculate risk factor scores based on pattern matches."""
        risk_factors = {}
        
        # Government impersonation score
        gov_matches = sum(len(matches) for matches in pattern_matches.get('government', {}).values())
        risk_factors['government_impersonation'] = min(gov_matches * 0.3, 1.0)
        
        # Urgency pressure score
        urgency_matches = sum(len(matches) for matches in pattern_matches.get('urgency', {}).values())
        risk_factors['urgency_pressure'] = min(urgency_matches * 0.25, 1.0)
        
        # Financial request score
        financial_matches = sum(len(matches) for matches in pattern_matches.get('financial', {}).values())
        risk_factors['financial_request'] = min(financial_matches * 0.2, 1.0)
        
        # Suspicious indicators score
        suspicious_matches = sum(len(matches) for matches in pattern_matches.get('suspicious', {}).values())
        risk_factors['suspicious_indicators'] = min(suspicious_matches * 0.15, 1.0)
        
        # Evasion techniques score
        evasion_matches = sum(len(matches) for matches in pattern_matches.get('evasion', {}).values())
        risk_factors['evasion_techniques'] = min(evasion_matches * 0.4, 1.0)
        
        return risk_factors
    
    def _extract_threat_indicators(self, message: str, pattern_matches: Dict) -> List[str]:
        """Extract human-readable threat indicators."""
        indicators = []
        
        # Check for government impersonation
        if any(pattern_matches.get('government', {}).values()):
            indicators.append("🏛️ Government/DMV impersonation detected")
        
        # Check for urgency tactics
        if any(pattern_matches.get('urgency', {}).values()):
            indicators.append("⏰ High-pressure urgency tactics")
        
        # Check for financial requests
        if any(pattern_matches.get('financial', {}).values()):
            indicators.append("💰 Financial information or payment requested")
        
        # Check for suspicious elements
        if pattern_matches.get('suspicious', {}).get('poor_grammar'):
            indicators.append("📝 Poor grammar/spelling patterns")
        
        if pattern_matches.get('suspicious', {}).get('generic_language'):
            indicators.append("🎭 Generic/non-personalized language")
        
        if pattern_matches.get('suspicious', {}).get('suspicious_domains'):
            indicators.append("🔗 Suspicious links or domains")
        
        # Check for evasion techniques
        if any(pattern_matches.get('evasion', {}).values()):
            indicators.append("🎪 Advanced evasion techniques detected")
        
        # Check for specific URL patterns
        if re.search(r'http[s]?://[^\s]+', message, re.IGNORECASE):
            indicators.append("🔗 External links present")
        
        # Check for phone number patterns
        if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', message):
            indicators.append("📞 Phone number present")
        
        return indicators
    
    def _calculate_threat_score(self, risk_factors: Dict[str, float]) -> float:
        """Calculate overall threat score."""
        if not risk_factors:
            return 0.0
        
        # Weighted combination of risk factors
        weights = {
            'government_impersonation': 0.25,
            'urgency_pressure': 0.20,
            'financial_request': 0.20,
            'suspicious_indicators': 0.15,
            'evasion_techniques': 0.20
        }
        
        total_score = 0.0
        for factor, score in risk_factors.items():
            weight = weights.get(factor, 0.1)
            total_score += score * weight
        
        return min(total_score, 1.0)
    
    def _calculate_confidence(self, pattern_matches: Dict) -> float:
        """Calculate confidence in the threat assessment."""
        total_matches = 0
        for category_matches in pattern_matches.values():
            for matches in category_matches.values():
                total_matches += len(matches)
        
        # Base confidence on number of pattern matches
        confidence = min(total_matches * 0.1, 1.0)
        
        # Boost confidence if multiple categories match
        categories_with_matches = sum(1 for category in pattern_matches.values() 
                                    if any(matches for matches in category.values()))
        
        if categories_with_matches >= 3:
            confidence = min(confidence + 0.2, 1.0)
        
        return confidence
    
    def get_threat_summary(self, analysis_result: Dict[str, Any]) -> str:
        """Generate a human-readable threat summary."""
        score = analysis_result['overall_score']
        indicators = analysis_result['threat_indicators']
        confidence = analysis_result['confidence']
        
        if score >= 0.7:
            risk_level = "🚨 HIGH RISK"
            recommendation = "Do not respond. Report as scam."
        elif score >= 0.4:
            risk_level = "⚠️ MEDIUM RISK"
            recommendation = "Exercise caution. Verify independently."
        else:
            risk_level = "✅ LOW RISK"
            recommendation = "Appears legitimate, but always verify official communications."
        
        summary_parts = [
            f"Threat Level: {risk_level}",
            f"Confidence: {confidence:.1%}",
            f"Threat Score: {score:.3f}"
        ]
        
        if indicators:
            summary_parts.append(f"Indicators: {', '.join(indicators[:3])}")
        
        summary_parts.append(f"Recommendation: {recommendation}")
        
        return " | ".join(summary_parts)


def demo_advanced_detection():
    """Demonstrate the advanced threat detection capabilities."""
    detector = AdvancedThreatPatterns()
    
    test_messages = [
        "Your PA DMV license expires in 2 days. Pay $45 fee immediately to avoid suspension. Click: bit.ly/pa-gov-renew",
        "URGENT: Department of Motor Vehicles requires immediate verification. Call 555-0123 now!",
        "Reminder: Your vehicle registration renewal is due next month. Visit your local DMV office.",
        "Dear valued customer, your g0vernment account needs verification. Pay fee now!",
    ]
    
    print("🔍 Advanced Threat Detection Demo")
    print("=" * 50)
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n📧 Test Message {i}:")
        print(f"Text: {message}")
        
        result = detector.analyze_message(message)
        summary = detector.get_threat_summary(result)
        
        print(f"Analysis: {summary}")
        
        if result['threat_indicators']:
            print(f"Indicators: {', '.join(result['threat_indicators'])}")


if __name__ == "__main__":
    demo_advanced_detection()
