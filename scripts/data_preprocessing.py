#!/usr/bin/env python3
"""
Data preprocessing script for DMV scam analysis project.
Handles data cleaning, transformation, and feature engineering.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
from typing import Dict, List, Optional
import re
from datetime import datetime
import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataPreprocessor:
    """Class for preprocessing DMV scam message data."""
    
    def __init__(self, config_path: str = "config/preprocessing_config.yaml"):
        """Initialize the preprocessor with configuration."""
        self.config = self._load_config(config_path)
        
    def _load_config(self, config_path: str) -> dict:
        """Load preprocessing configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}

    def clean_text(self, text: str) -> str:
        """
        Clean text data by removing special characters and normalizing whitespace.
        
        Args:
            text: Input text to clean
            
        Returns:
            Cleaned text string
        """
        if not isinstance(text, str):
            return ""
            
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep basic punctuation
        text = re.sub(r'[^\w\s.,!?-]', '', text)
        
        # Normalize whitespace
        text = ' '.join(text.split())
        
        return text

    def remove_pii(self, text: str) -> str:
        """
        Remove personally identifiable information from text.
        
        Args:
            text: Input text to process
            
        Returns:
            Text with PII removed
        """
        if not isinstance(text, str):
            return ""
            
        # Remove potential phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)
        
        # Remove potential email addresses
        text = re.sub(r'\S+@\S+\.\S+', '[EMAIL]', text)
        
        # Remove potential SSN
        text = re.sub(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', '[SSN]', text)
        
        # Remove potential URLs
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                     '[URL]', text)
        
        return text

    def extract_features(self, text: str) -> Dict:
        """
        Extract features from message text.
        
        Args:
            text: Input text to analyze
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Message length
        features['length'] = len(text)
        
        # Word count
        features['word_count'] = len(text.split())
        
        # Contains URL
        features['has_url'] = 1 if '[URL]' in text else 0
        
        # Contains phone number
        features['has_phone'] = 1 if '[PHONE]' in text else 0
        
        # Contains email
        features['has_email'] = 1 if '[EMAIL]' in text else 0
        
        # Contains monetary amount
        features['has_money'] = 1 if bool(re.search(r'\$\d+', text)) else 0
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediately', 'asap', 'now', 'emergency']
        features['urgency_score'] = sum(1 for word in urgency_words if word in text.lower())
        
        return features

    def process(self, messages: List[Dict]) -> List[Dict]:
        """
        Process a list of messages through the preprocessing pipeline.
        
        Args:
            messages: List of message dictionaries
            
        Returns:
            List of processed message dictionaries
        """
        if not messages:
            raise ValueError("Messages list is empty")
        
        processed_messages = []
        
        for message in messages:
            if not isinstance(message, dict) or 'text' not in message:
                raise ValueError("Each message must be a dictionary with 'text' key")
            
            # Check for empty text
            if not message['text'] or not message['text'].strip():
                raise ValueError("Message text cannot be empty")
            
            # Create a copy of the message to avoid modifying the original
            processed_message = message.copy()
            
            # Clean the text
            cleaned_text = self.clean_text(message['text'])
            
            # Remove PII
            processed_text = self.remove_pii(cleaned_text)
            
            # Extract features
            features = self.extract_features(processed_text)
            
            # Add processed data to the message
            processed_message['cleaned_text'] = cleaned_text
            processed_message['processed_text'] = processed_text
            processed_message.update(features)
            
            processed_messages.append(processed_message)
        
        return processed_messages

    def process_dataset(self, input_path: str, output_path: str):
        """
        Process the entire dataset.
        
        Args:
            input_path: Path to input CSV file
            output_path: Path to save processed CSV file
        """
        try:
            # Read input data
            logger.info(f"Reading data from {input_path}")
            df = pd.read_csv(input_path)
            
            # Clean text
            logger.info("Cleaning message text")
            df['cleaned_text'] = df['message'].apply(self.clean_text)
            
            # Remove PII
            logger.info("Removing PII from messages")
            df['processed_text'] = df['cleaned_text'].apply(self.remove_pii)
            
            # Extract features
            logger.info("Extracting features from messages")
            features_df = pd.DataFrame(df['processed_text'].apply(self.extract_features).tolist())
            
            # Combine with original data
            processed_df = pd.concat([df, features_df], axis=1)
            
            # Save processed data
            logger.info(f"Saving processed data to {output_path}")
            processed_df.to_csv(output_path, index=False)
            
        except Exception as e:
            logger.error(f"Error processing dataset: {e}")
            raise

def main():
    """Main function to run data preprocessing."""
    preprocessor = DataPreprocessor()
    
    try:
        # Process raw data
        preprocessor.process_dataset(
            input_path="data/raw/messages.csv",
            output_path="data/processed/cleaned_messages.csv"
        )
        logger.info("Data preprocessing completed successfully")
        
    except Exception as e:
        logger.error(f"Preprocessing failed: {e}")
        raise

if __name__ == "__main__":
    main()
