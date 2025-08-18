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
from datetime import datetime
import json
import argparse
import os
from typing import Any, Dict, List, Optional


class iMessageAnalyzer:
    """
    Advanced iMessage database analyzer for threat detection and forensics
    """

    def __init__(self, db_path: str, output_dir: str = "./analysis_output") -> None:
        """
        Initialize the analyzer with database path and output directory

        Args:
            db_path (str): Path to chat.db file
            output_dir (str): Directory for analysis outputs
        """
        self.db_path = db_path
        self.output_dir = output_dir
        self.conn: Optional[sqlite3.Connection] = None
        self.suspicious_patterns = self._load_threat_patterns()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

    def read_messages(self, input_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Read messages from input file or database.

        Supports JSON (.json), CSV (.csv), and plain text (.txt) files.
        - JSON: either a list of objects with at least a 'text' field, or an
          object containing a top-level key like 'messages' or 'data'.
        - CSV: attempts to detect a text column among common names
          (text, message, body, content). Other columns like id/timestamp are
          propagated when available.
        - TXT: each non-empty line becomes a message's 'text'.

        Args:
            input_file (str, optional): Path to input file containing messages

        Returns:
            list: A list of message dictionaries with at least the 'text' key
        """
        if input_file:
            try:
                ext = os.path.splitext(input_file)[1].lower()
                if ext == ".json":
                    with open(input_file, "r") as f:
                        data = json.load(f)
                    # Accept either list or object with messages
                    if isinstance(data, dict):
                        for key in ["messages", "data", "items", "rows"]:
                            if key in data and isinstance(data[key], list):
                                data = data[key]
                                break
                    if not isinstance(data, list):
                        raise ValueError(
                            "JSON must be a list of messages or contain a list under a known key"
                        )
                    messages = data
                elif ext == ".csv":
                    # Use pandas to read CSV and map to list of dicts
                    df = pd.read_csv(input_file)
                    # Detect text column
                    text_cols = [
                        "text",
                        "message",
                        "body",
                        "content",
                        "Text",
                        "Message",
                        "Body",
                        "Content",
                    ]
                    text_col = next((c for c in text_cols if c in df.columns), None)
                    if text_col is None:
                        # If no obvious text column, assume first column is text
                        if len(df.columns) == 1:
                            text_col = df.columns[0]
                        else:
                            raise ValueError("No text/message column found in CSV")
                    messages = []
                    for i, row in df.iterrows():
                        text_val = row.get(text_col)
                        if pd.isna(text_val):
                            continue
                        msg = {"text": str(text_val)}
                        # Optional fields
                        if "id" in df.columns:
                            msg["id"] = row.get("id")
                        else:
                            msg["id"] = f"msg_{i:03d}"
                        # Timestamp detection
                        ts_cols = ["timestamp", "date", "datetime", "time", "readable_date"]
                        ts_val = None
                        for c in ts_cols:
                            if c in df.columns:
                                ts_val = row.get(c)
                                break
                        if pd.isna(ts_val) if "pd" in globals() else ts_val is None:
                            ts_val = datetime.now().isoformat()
                        msg["timestamp"] = str(ts_val)
                        # Source if present
                        if "source" in df.columns:
                            msg["source"] = row.get("source")
                        messages.append(msg)
                else:
                    # Treat as plain text file: each non-empty line is a message
                    with open(input_file, "r") as f:
                        lines = [line.strip() for line in f.readlines()]
                    messages = []
                    for i, line in enumerate(lines):
                        if not line:
                            continue
                        messages.append(
                            {
                                "id": f"msg_{i:03d}",
                                "timestamp": datetime.now().isoformat(),
                                "text": line,
                                "source": os.path.basename(input_file),
                            }
                        )
                # Ensure required fields
                normalized = []
                for i, msg in enumerate(messages):
                    if not isinstance(msg, dict):
                        # If message is a simple string, wrap it
                        msg = {"text": str(msg)}
                    if "text" not in msg or msg["text"] is None or str(msg["text"]).strip() == "":
                        # Skip empty text entries
                        continue
                    msg.setdefault("id", f"msg_{i:03d}")
                    msg.setdefault("timestamp", datetime.now().isoformat())
                    normalized.append(msg)
                return normalized
            except Exception as e:
                print(f"Error reading messages from file: {e}")
                return []
        else:
            # Return sample messages for demonstration
            return [
                {
                    "id": "msg001",
                    "timestamp": "2025-06-27T10:00:00Z",
                    "text": "Sample message for testing",
                    "source": "demo",
                }
            ]

    def extract_all(self) -> List[Dict[str, Any]]:
        """
        Extract all messages for demonstration.
        Returns:
            list: A list of extracted message dictionaries
        """
        # This is a placeholder demonstrating extraction
        # Real implementation would call read_messages for files
        return self.read_messages()

    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """
        Load threat detection patterns for automated analysis

        Returns:
            dict: Categorized threat patterns
        """
        return {
            "government_impersonation": [
                r"(?i)(dmv|department.*motor.*vehicles)",
                r"(?i)(license.*suspend|violation.*notice)",
                r"(?i)(government.*notice|official.*notice)",
                r"(?i)(penalty.*avoid|immediate.*action)",
            ],
            "financial_threats": [
                r"(?i)(payment.*required|pay.*immediately)",
                r"(?i)(account.*suspend|freeze.*account)",
                r"(?i)(urgent.*payment|overdue.*payment)",
                r"(?i)(fine.*notice|penalty.*fee)",
            ],
            "suspicious_urls": [
                r"(?i)(\.vip|\.tk|\.ml|\.ga)",
                r"(?i)(gov-[a-z]+\.)",
                r"(?i)(secure-[a-z]+\.)",
                r"http[s]?://[^\s]+",
            ],
            "international_indicators": [
                r"\+63\d{10}",  # Philippines country code
                r"\+1\d{10}",  # Potential spoofed US numbers
                r"\+\d{1,3}\d{7,14}",  # International format
            ],
        }

    def connect_database(self) -> bool:
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

    def get_database_schema(self) -> Optional[Dict[str, Any]]:
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
            schema[table] = {"columns": [col[1] for col in columns], "column_details": columns}

        return schema

    def extract_messages_by_contact(self, contact_identifier: str, limit: Optional[int] = None) -> Optional[pd.DataFrame]:
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
            datetime(m.date/1000000000 + strftime('%s', '2001-01-01'),
                     'unixepoch', 'localtime') as readable_date
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
            df = pd.read_sql_query(
                query, self.conn, params=[f"%{contact_identifier}%", f"%{contact_identifier}%"]
            )
            print(f"✓ Extracted {len(df)} messages for contact: {contact_identifier}")
            return df
        except Exception as e:
            print(f"✗ Message extraction failed: {e}")
            return None

    def analyze_message_content(self, messages_df: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """
        Perform automated threat analysis on message content

        Args:
            messages_df (pd.DataFrame): Message data to analyze

        Returns:
            dict: Analysis results
        """
        if messages_df is None or messages_df.empty:
            return None

        # Typed containers for analysis aggregation
        threat_indicators: Dict[str, int] = {}
        suspicious_messages: List[Dict[str, Any]] = []

        analysis_results: Dict[str, Any] = {
            "total_messages": len(messages_df),
            "threat_indicators": threat_indicators,
            "suspicious_messages": suspicious_messages,
            "timeline_analysis": {},
            "risk_score": 0,
        }

        # Analyze each message for threat patterns
        for index, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            message_text = str(message["text"])
            message_threats = []

            # Check against all threat patterns
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, message_text):
                        message_threats.append(category)

                        if category not in threat_indicators:
                            threat_indicators[category] = 0
                        threat_indicators[category] += 1

            # If threats found, add to suspicious messages
            if message_threats:
                suspicious_messages.append(
                    {
                        "message_id": message["ROWID"],
                        "date": message["readable_date"],
                        "content_preview": (
                            message_text[:100] + "..." if len(message_text) > 100 else message_text
                        ),
                        "threat_categories": message_threats,
                        "is_from_me": message["is_from_me"],
                    }
                )

        # Calculate risk score
        risk_factors = [
            len(threat_indicators) * 10,  # Number of threat categories
            len(suspicious_messages) * 5,  # Number of suspicious messages
            50 if "government_impersonation" in threat_indicators else 0,
            30 if "financial_threats" in threat_indicators else 0,
            20 if "suspicious_urls" in threat_indicators else 0,
        ]

        analysis_results["risk_score"] = min(100, sum(risk_factors))

        return analysis_results

    def generate_timeline_analysis(self, messages_df: pd.DataFrame) -> Optional[Dict[str, Any]]:
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
        messages_df["date_parsed"] = pd.to_datetime(messages_df["readable_date"])

        timeline = {
            "first_message": messages_df["date_parsed"].min().isoformat(),
            "last_message": messages_df["date_parsed"].max().isoformat(),
            "total_duration": str(
                messages_df["date_parsed"].max() - messages_df["date_parsed"].min()
            ),
            "message_frequency": {},
            "suspicious_timing": [],
        }

        # Analyze message frequency by day
        daily_counts = messages_df.groupby(messages_df["date_parsed"].dt.date).size()
        timeline["message_frequency"] = daily_counts.to_dict()

        return timeline

    def export_messages_csv(self, df: pd.DataFrame, output_path: str) -> bool:
        """
        Export extracted messages DataFrame to CSV file.

        Args:
            df: DataFrame containing extracted messages
            output_path: Full path to output CSV file

        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            # Export to CSV with UTF-8 encoding
            df.to_csv(output_path, index=False, encoding="utf-8")
            print(f"✓ Exported {len(df)} messages to: {output_path}")
            return True
        except Exception as e:
            print(f"✗ CSV export failed: {e}")
            return False

    def export_analysis_report(self, contact_identifier: str, analysis_results: Dict[str, Any], timeline_results: Dict[str, Any]) -> None:
        """
        Export comprehensive analysis report

        Args:
            contact_identifier (str): Contact being analyzed
            analysis_results (dict): Threat analysis results
            timeline_results (dict): Timeline analysis results
        """
        report = {
            "analysis_metadata": {
                "contact_analyzed": contact_identifier,
                "analysis_timestamp": datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "database_source": os.path.basename(self.db_path),
            },
            "threat_analysis": analysis_results,
            "timeline_analysis": timeline_results,
            "recommendations": self._generate_recommendations(analysis_results),
        }

        # Export as JSON
        output_file = os.path.join(
            self.output_dir, f"analysis_report_{contact_identifier.replace('+', '')}.json"
        )
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"✓ Analysis report exported: {output_file}")

        # Generate human-readable summary
        self._generate_summary_report(report, contact_identifier)

    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on analysis

        Args:
            analysis_results (dict): Analysis results

        Returns:
            list: Security recommendations
        """
        recommendations = []

        if analysis_results["risk_score"] > 70:
            recommendations.append(
                "HIGH RISK: Immediate action required - block contact and report to authorities"
            )
        elif analysis_results["risk_score"] > 40:
            recommendations.append(
                "MEDIUM RISK: Monitor communications and avoid sharing personal information"
            )

        if "government_impersonation" in analysis_results["threat_indicators"]:
            recommendations.append(
                "Government impersonation detected - verify through official channels"
            )

        if "financial_threats" in analysis_results["threat_indicators"]:
            recommendations.append(
                "Financial threats identified - do not make payments without verification"
            )

        if "suspicious_urls" in analysis_results["threat_indicators"]:
            recommendations.append(
                "Suspicious URLs detected - do not click links from this contact"
            )

        return recommendations

    def _generate_summary_report(self, report: Dict[str, Any], contact_identifier: str) -> None:
        """
        Generate human-readable summary report

        Args:
            report (dict): Full analysis report
            contact_identifier (str): Contact identifier
        """
        summary_file = os.path.join(
            self.output_dir, f"summary_{contact_identifier.replace('+', '')}.txt"
        )

        with open(summary_file, "w") as f:
            f.write("iMessage Threat Analysis Summary\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Contact Analyzed: {contact_identifier}\n")
            f.write(f"Analysis Date: {report['analysis_metadata']['analysis_timestamp']}\n")
            f.write(f"Risk Score: {report['threat_analysis']['risk_score']}/100\n\n")

            f.write("Threat Indicators Found:\n")
            for category, count in report["threat_analysis"]["threat_indicators"].items():
                f.write(f"  - {category.replace('_', ' ').title()}: {count} occurrences\n")

            suspicious_count = len(report["threat_analysis"]["suspicious_messages"])
            f.write(f"\nSuspicious Messages: {suspicious_count}\n\n")

            f.write("Recommendations:\n")
            for rec in report["recommendations"]:
                f.write(f"  • {rec}\n")

        print(f"✓ Summary report generated: {summary_file}")

    def close_connection(self) -> None:
        """Close database connection if open."""
        if self.conn:
            try:
                self.conn.close()
                self.conn = None
                print("✓ Database connection closed")
            except Exception as e:
                print(f"✗ Error closing connection: {e}")


def main() -> int:
    """
    Main execution function for command-line usage
    """
    parser = argparse.ArgumentParser(description="iMessage Database Threat Analysis Tool")
    parser.add_argument("--db-path", required=True, help="Path to chat.db file")
    parser.add_argument("--contact", required=True, help="Contact identifier to analyze")
    parser.add_argument(
        "--output-dir", default="./analysis_output", help="Output directory for reports"
    )
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

        # Ensure we have results before exporting
        if analysis_results is None or timeline_results is None:
            return 1

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


# Alias for backward compatibility
MessageExtractor = iMessageAnalyzer

if __name__ == "__main__":
    exit(main())
