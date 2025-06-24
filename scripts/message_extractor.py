#!/usr/bin/env python3
"""
iMessage Database Analysis Tool
DMV Scam Analysis Project

This script demonstrates digital forensics techniques for analyzing
iMessage communications to identify potential threats and scams.

Author: Cybersecurity Researcher
Purpose: Educational and threat detection demonstration
"""

import sqlite3
import pandas as pd
import re
from datetime import datetime, timedelta
import json
import argparse
import os

class iMessageAnalyzer:
    """
    Advanced iMessage database analyzer for threat detection and forensics
    """
    
    def __init__(self, db_path, output_dir="./analysis_output"):
        """
        Initialize the analyzer with database path and output directory
        
        Args:
            db_path (str): Path to chat.db file
            output_dir (str): Directory for analysis outputs
        """
        self.db_path = db_path
        self.output_dir = output_dir
        self.conn = None
        self.suspicious_patterns = self._load_threat_patterns()
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def _load_threat_patterns(self):
        """
        Load threat detection patterns for automated analysis
        
        Returns:
            dict: Categorized threat patterns
        """
        return {
            'government_impersonation': [
                r'(?i)(dmv|department.*motor.*vehicles)',
                r'(?i)(license.*suspend|violation.*notice)',
                r'(?i)(government.*notice|official.*notice)',
                r'(?i)(penalty.*avoid|immediate.*action)'
            ],
            'financial_threats': [
                r'(?i)(payment.*required|pay.*immediately)',
                r'(?i)(account.*suspend|freeze.*account)',
                r'(?i)(urgent.*payment|overdue.*payment)',
                r'(?i)(fine.*notice|penalty.*fee)'
            ],
            'suspicious_urls': [
                r'(?i)(\.vip|\.tk|\.ml|\.ga)',
                r'(?i)(gov-[a-z]+\.)',
                r'(?i)(secure-[a-z]+\.)',
                r'http[s]?://[^\s]+'
            ],
            'international_indicators': [
                r'\+63\d{10}',  # Philippines country code
                r'\+1\d{10}',   # Potential spoofed US numbers
                r'\+\d{1,3}\d{7,14}'  # International format
            ]
        }
    
    def connect_database(self):
        """
        Establish connection to the iMessage database
        
        Returns:
            bool: Success status
        """
        try:
            self.conn = sqlite3.connect(self.db_path)
            print(f"✓ Connected to database: {self.db_path}")
            return True
        except sqlite3.Error as e:
            print(f"✗ Database connection failed: {e}")
            return False
    
    def get_database_schema(self):
        """
        Analyze and document the database schema
        
        Returns:
            dict: Schema information
        """
        if not self.conn:
            return None
            
        cursor = self.conn.cursor()
        
        # Get table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        schema = {}
        for table in tables:
            cursor.execute(f"PRAGMA table_info({table});")
            columns = cursor.fetchall()
            schema[table] = {
                'columns': [col[1] for col in columns],
                'column_details': columns
            }
        
        return schema
    
    def extract_messages_by_contact(self, contact_identifier, limit=None):
        """
        Extract messages associated with a specific contact
        
        Args:
            contact_identifier (str): Phone number or email to search for
            limit (int): Maximum number of messages to retrieve
            
        Returns:
            pd.DataFrame: Message data
        """
        if not self.conn:
            print("✗ No database connection")
            return None
        
        query = """
        SELECT 
            m.ROWID,
            m.text,
            m.date,
            m.is_from_me,
            m.service,
            h.id as handle_id,
            c.chat_identifier,
            datetime(m.date/1000000000 + strftime('%s', '2001-01-01'), 'unixepoch', 'localtime') as readable_date
        FROM message m
        LEFT JOIN handle h ON m.handle_id = h.ROWID
        LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
        LEFT JOIN chat c ON cmj.chat_id = c.ROWID
        WHERE h.id LIKE ? OR c.chat_identifier LIKE ?
        ORDER BY m.date DESC
        """
        
        if limit:
            query += f" LIMIT {limit}"
        
        try:
            df = pd.read_sql_query(query, self.conn, params=[f"%{contact_identifier}%", f"%{contact_identifier}%"])
            print(f"✓ Extracted {len(df)} messages for contact: {contact_identifier}")
            return df
        except Exception as e:
            print(f"✗ Message extraction failed: {e}")
            return None
    
    def analyze_message_content(self, messages_df):
        """
        Perform automated threat analysis on message content
        
        Args:
            messages_df (pd.DataFrame): Message data to analyze
            
        Returns:
            dict: Analysis results
        """
        if messages_df is None or messages_df.empty:
            return None
        
        analysis_results = {
            'total_messages': len(messages_df),
            'threat_indicators': {},
            'suspicious_messages': [],
            'timeline_analysis': {},
            'risk_score': 0
        }
        
        # Analyze each message for threat patterns
        for index, message in messages_df.iterrows():
            if pd.isna(message['text']):
                continue
                
            message_text = str(message['text'])
            message_threats = []
            
            # Check against all threat patterns
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, message_text):
                        message_threats.append(category)
                        
                        if category not in analysis_results['threat_indicators']:
                            analysis_results['threat_indicators'][category] = 0
                        analysis_results['threat_indicators'][category] += 1
            
            # If threats found, add to suspicious messages
            if message_threats:
                analysis_results['suspicious_messages'].append({
                    'message_id': message['ROWID'],
                    'date': message['readable_date'],
                    'content_preview': message_text[:100] + "..." if len(message_text) > 100 else message_text,
                    'threat_categories': message_threats,
                    'is_from_me': message['is_from_me']
                })
        
        # Calculate risk score
        risk_factors = [
            len(analysis_results['threat_indicators']) * 10,  # Number of threat categories
            len(analysis_results['suspicious_messages']) * 5,  # Number of suspicious messages
            50 if 'government_impersonation' in analysis_results['threat_indicators'] else 0,
            30 if 'financial_threats' in analysis_results['threat_indicators'] else 0,
            20 if 'suspicious_urls' in analysis_results['threat_indicators'] else 0
        ]
        
        analysis_results['risk_score'] = min(100, sum(risk_factors))
        
        return analysis_results
    
    def generate_timeline_analysis(self, messages_df):
        """
        Generate timeline analysis of message patterns
        
        Args:
            messages_df (pd.DataFrame): Message data
            
        Returns:
            dict: Timeline analysis
        """
        if messages_df is None or messages_df.empty:
            return None
        
        # Convert dates for analysis
        messages_df['date_parsed'] = pd.to_datetime(messages_df['readable_date'])
        
        timeline = {
            'first_message': messages_df['date_parsed'].min().isoformat(),
            'last_message': messages_df['date_parsed'].max().isoformat(),
            'total_duration': str(messages_df['date_parsed'].max() - messages_df['date_parsed'].min()),
            'message_frequency': {},
            'suspicious_timing': []
        }
        
        # Analyze message frequency by day
        daily_counts = messages_df.groupby(messages_df['date_parsed'].dt.date).size()
        timeline['message_frequency'] = daily_counts.to_dict()
        
        return timeline
    
    def export_analysis_report(self, contact_identifier, analysis_results, timeline_results):
        """
        Export comprehensive analysis report
        
        Args:
            contact_identifier (str): Contact being analyzed
            analysis_results (dict): Threat analysis results
            timeline_results (dict): Timeline analysis results
        """
        report = {
            'analysis_metadata': {
                'contact_analyzed': contact_identifier,
                'analysis_timestamp': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'database_source': os.path.basename(self.db_path)
            },
            'threat_analysis': analysis_results,
            'timeline_analysis': timeline_results,
            'recommendations': self._generate_recommendations(analysis_results)
        }
        
        # Export as JSON
        output_file = os.path.join(self.output_dir, f"analysis_report_{contact_identifier.replace('+', '')}.json")
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"✓ Analysis report exported: {output_file}")
        
        # Generate human-readable summary
        self._generate_summary_report(report, contact_identifier)
    
    def _generate_recommendations(self, analysis_results):
        """
        Generate security recommendations based on analysis
        
        Args:
            analysis_results (dict): Analysis results
            
        Returns:
            list: Security recommendations
        """
        recommendations = []
        
        if analysis_results['risk_score'] > 70:
            recommendations.append("HIGH RISK: Immediate action required - block contact and report to authorities")
        elif analysis_results['risk_score'] > 40:
            recommendations.append("MEDIUM RISK: Monitor communications and avoid sharing personal information")
        
        if 'government_impersonation' in analysis_results['threat_indicators']:
            recommendations.append("Government impersonation detected - verify through official channels")
        
        if 'financial_threats' in analysis_results['threat_indicators']:
            recommendations.append("Financial threats identified - do not make payments without verification")
        
        if 'suspicious_urls' in analysis_results['threat_indicators']:
            recommendations.append("Suspicious URLs detected - do not click links from this contact")
        
        return recommendations
    
    def _generate_summary_report(self, report, contact_identifier):
        """
        Generate human-readable summary report
        
        Args:
            report (dict): Full analysis report
            contact_identifier (str): Contact identifier
        """
        summary_file = os.path.join(self.output_dir, f"summary_{contact_identifier.replace('+', '')}.txt")
        
        with open(summary_file, 'w') as f:
            f.write("iMessage Threat Analysis Summary\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Contact Analyzed: {contact_identifier}\n")
            f.write(f"Analysis Date: {report['analysis_metadata']['analysis_timestamp']}\n")
            f.write(f"Risk Score: {report['threat_analysis']['risk_score']}/100\n\n")
            
            f.write("Threat Indicators Found:\n")
            for category, count in report['threat_analysis']['threat_indicators'].items():
                f.write(f"  - {category.replace('_', ' ').title()}: {count} occurrences\n")
            
            f.write(f"\nSuspicious Messages: {len(report['threat_analysis']['suspicious_messages'])}\n\n")
            
            f.write("Recommendations:\n")
            for rec in report['recommendations']:
                f.write(f"  • {rec}\n")
        
        print(f"✓ Summary report generated: {summary_file}")
    
    def close_connection(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")

def main():
    """
    Main execution function for command-line usage
    """
    parser = argparse.ArgumentParser(description="iMessage Database Threat Analysis Tool")
    parser.add_argument("--db-path", required=True, help="Path to chat.db file")
    parser.add_argument("--contact", required=True, help="Contact identifier to analyze")
    parser.add_argument("--output-dir", default="./analysis_output", help="Output directory for reports")
    parser.add_argument("--limit", type=int, help="Limit number of messages to analyze")
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = iMessageAnalyzer(args.db_path, args.output_dir)
    
    try:
        # Connect to database
        if not analyzer.connect_database():
            return 1
        
        # Extract messages
        messages = analyzer.extract_messages_by_contact(args.contact, args.limit)
        if messages is None:
            return 1
        
        # Perform analysis
        analysis_results = analyzer.analyze_message_content(messages)
        timeline_results = analyzer.generate_timeline_analysis(messages)
        
        # Export reports
        analyzer.export_analysis_report(args.contact, analysis_results, timeline_results)
        
        print(f"\n✓ Analysis complete for contact: {args.contact}")
        print(f"✓ Risk Score: {analysis_results['risk_score']}/100")
        print(f"✓ Reports saved to: {args.output_dir}")
        
    except Exception as e:
        print(f"✗ Analysis failed: {e}")
        return 1
    
    finally:
        analyzer.close_connection()
    
    return 0

if __name__ == "__main__":
    exit(main())
