#!/usr/bin/env python3
"""
Synthetic Data Generator for DMV Scam Analysis
Generates synthetic scam messages and handles class imbalance
"""

import json
import random
from faker import Faker
from typing import List, Dict, Any
import argparse
from pathlib import Path

fake = Faker()

class SyntheticDataGenerator:
    def __init__(self) -> None:
        self.fake = fake
        
        # Common scam patterns
        self.scam_patterns = [
            "Your DMV registration expires in {days} days. Renew now at {url}",
            "URGENT: Your vehicle registration is suspended. Click {url} to resolve",
            "DMV NOTICE: Your license will be revoked. Update info at {url}",
            "Action Required: Your car registration failed. Visit {url} immediately",
            "WARNING: Your driving record shows violations. Check {url} now",
            "Your DMV account has been locked. Verify identity at {url}",
            "FINAL NOTICE: Registration renewal required. Pay fees at {url}",
            "Your vehicle inspection is overdue. Schedule at {url}",
            "DMV Alert: Your license points will cause suspension. View {url}",
            "Registration payment declined. Update payment method at {url}"
        ]
        
        # Legitimate message patterns
        self.legitimate_patterns = [
            "Thank you for visiting the DMV. Your transaction number is {number}",
            "Appointment confirmation for {date} at {time}",
            "Your vehicle registration renewal is complete. Reference: {ref}",
            "DMV office hours: Monday-Friday 8AM-5PM",
            "Your driving test is scheduled for {date}",
            "Registration renewal notice - due date: {date}",
            "Your new license will arrive in 7-10 business days",
            "DMV customer service: Call 1-800-DMV-INFO for assistance",
            "Your vehicle passed inspection. Certificate valid until {date}",
            "Thank you for your payment. Receipt number: {receipt}"
        ]
        
        # Suspicious/scam indicators
        self.suspicious_words = [
            "URGENT", "FINAL NOTICE", "SUSPENDED", "EXPIRED", "CLICK NOW",
            "IMMEDIATE ACTION", "LOCKED", "VERIFY NOW", "LIMITED TIME"
        ]
        
    def generate_scam_message(self) -> Dict[str, Any]:
        """Generate a synthetic scam message"""
        pattern = random.choice(self.scam_patterns)
        
        # Generate fake data for placeholders
        days = random.randint(1, 30)
        url = f"dmv-{self.fake.word()}.{self.fake.domain_name()}"
        
        message = pattern.format(
            days=days,
            url=url,
            number=self.fake.random_number(digits=8),
            date=self.fake.date_between(start_date='-30d', end_date='+30d'),
            time=self.fake.time(),
            ref=self.fake.uuid4()[:8],
            receipt=self.fake.random_number(digits=10)
        )
        
        return {
            "id": self.fake.uuid4(),
            "message": message,
            "sender": self.fake.email(),
            "timestamp": self.fake.date_time_between(start_date='-1y', end_date='now').isoformat(),
            "label": "scam",
            "threat_score": random.uniform(0.7, 1.0),
            "suspicious_indicators": random.sample(self.suspicious_words, random.randint(1, 3))
        }
    
    def generate_legitimate_message(self) -> Dict[str, Any]:
        """Generate a synthetic legitimate message"""
        pattern = random.choice(self.legitimate_patterns)
        
        message = pattern.format(
            number=self.fake.random_number(digits=8),
            date=self.fake.date_between(start_date='-30d', end_date='+30d'),
            time=self.fake.time(),
            ref=self.fake.uuid4()[:8],
            receipt=self.fake.random_number(digits=10)
        )
        
        return {
            "id": self.fake.uuid4(),
            "message": message,
            "sender": "noreply@dmv.state.gov",
            "timestamp": self.fake.date_time_between(start_date='-1y', end_date='now').isoformat(),
            "label": "legitimate",
            "threat_score": random.uniform(0.0, 0.3),
            "suspicious_indicators": []
        }
    
    def generate_balanced_dataset(self, scam_count: int = 50, legitimate_count: int = 50) -> List[Dict[str, Any]]:
        """Generate a balanced dataset with specified counts"""
        dataset = []
        
        # Generate scam messages
        for _ in range(scam_count):
            dataset.append(self.generate_scam_message())
        
        # Generate legitimate messages
        for _ in range(legitimate_count):
            dataset.append(self.generate_legitimate_message())
        
        # Shuffle the dataset
        random.shuffle(dataset)
        
        return dataset
    
    def save_dataset(self, dataset: List[Dict[str, Any]], output_file: str) -> None:
        """Save dataset to JSON file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        print(f"Generated {len(dataset)} synthetic messages saved to {output_file}")
        
        # Print statistics
        scam_count = sum(1 for item in dataset if item['label'] == 'scam')
        legitimate_count = sum(1 for item in dataset if item['label'] == 'legitimate')
        
        print("Dataset statistics:")
        print(f"  - Scam messages: {scam_count}")
        print(f"  - Legitimate messages: {legitimate_count}")
        print(f"  - Total messages: {len(dataset)}")

def main() -> None:
    parser = argparse.ArgumentParser(description='Generate synthetic DMV scam data')
    parser.add_argument('--scam-count', type=int, default=50, help='Number of scam messages to generate')
    parser.add_argument('--legitimate-count', type=int, default=50, help='Number of legitimate messages to generate')
    parser.add_argument('--output', type=str, default='test_data/synthetic_messages.json', help='Output file path')
    
    args = parser.parse_args()
    
    generator = SyntheticDataGenerator()
    dataset = generator.generate_balanced_dataset(args.scam_count, args.legitimate_count)
    generator.save_dataset(dataset, args.output)

if __name__ == "__main__":
    main()
