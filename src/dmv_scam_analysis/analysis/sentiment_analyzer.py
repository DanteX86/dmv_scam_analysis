"""
Sentiment Analyzer for DMV Scam Analysis
"""

import json
import logging
from datetime import datetime
from textblob import TextBlob
import numpy as np

logger = logging.getLogger(__name__)

class SentimentAnalyzer:
    """
    Analyzes sentiment of messages to detect emotional manipulation tactics
    """
    
    def __init__(self, config=None):
        """
        Initialize the sentiment analyzer
        
        Args:
            config: Configuration object with sentiment analysis settings
        """
        self.config = config
        self.threat_keywords = [
            'urgent', 'immediately', 'suspend', 'penalty', 'fine', 'arrest',
            'legal action', 'court', 'violation', 'expired', 'deadline'
        ]
        
    def analyze(self, text):
        """
        Analyze sentiment of a text message
        
        Args:
            text (str): Message text to analyze
            
        Returns:
            dict: Sentiment analysis results
        """
        if not text or not isinstance(text, str):
            return {
                'sentiment_score': 0.0,
                'sentiment_label': 'neutral',
                'confidence': 0.0,
                'threat_indicators': []
            }
        
        # Use TextBlob for sentiment analysis
        blob = TextBlob(text)
        sentiment_score = blob.sentiment.polarity
        
        # Determine sentiment label
        if sentiment_score > 0.1:
            sentiment_label = 'positive'
        elif sentiment_score < -0.1:
            sentiment_label = 'negative'
        else:
            sentiment_label = 'neutral'
            
        # Check for threat indicators
        threat_indicators = []
        text_lower = text.lower()
        
        for keyword in self.threat_keywords:
            if keyword in text_lower:
                threat_indicators.append(keyword)
        
        # Calculate confidence based on absolute sentiment score
        confidence = abs(sentiment_score)
        
        return {
            'sentiment_score': sentiment_score,
            'sentiment_label': sentiment_label,
            'confidence': confidence,
            'threat_indicators': threat_indicators,
            'analysis_timestamp': datetime.now().isoformat()
        }
