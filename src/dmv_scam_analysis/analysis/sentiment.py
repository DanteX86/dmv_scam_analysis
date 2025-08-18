#!/usr/bin/env python3
"""
Natural Language Processing Analysis Module
DMV Scam Analysis Project

Advanced NLP techniques for semantic analysis, entity extraction, and sentiment analysis
of threat communications. Demonstrates sophisticated text analysis capabilities.

Author: Cybersecurity Researcher
Purpose: Portfolio demonstration and advanced threat analysis
"""

import pandas as pd
import numpy as np
import re
import json
from datetime import datetime
from textblob import TextBlob
import nltk
from collections import Counter, defaultdict
import warnings
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
from nltk.tree import Tree
from typing import Any, Dict, List, Optional, Tuple, Union

warnings.filterwarnings("ignore")

# Download required NLTK data (only needed first time)
try:
    nltk.data.find("tokenizers/punkt")
except LookupError:
    nltk.download("punkt", quiet=True)

try:
    nltk.data.find("corpora/stopwords")
except LookupError:
    nltk.download("stopwords", quiet=True)

try:
    nltk.data.find("taggers/averaged_perceptron_tagger")
except LookupError:
    nltk.download("averaged_perceptron_tagger", quiet=True)


class AdvancedNLPAnalyzer:
    """
    Advanced NLP analysis for threat communication analysis
    """

    def __init__(self, output_dir: str = "./analysis_output") -> None:
        """
        Initialize NLP analyzer

        Args:
            output_dir (str): Directory for analysis outputs
        """
        self.output_dir = output_dir
        self.stop_words = set(stopwords.words("english"))

        # Define threat-specific vocabularies
        self.threat_vocabularies = {
            "urgency": [
                "urgent",
                "immediately",
                "asap",
                "now",
                "today",
                "deadline",
                "expire",
                "suspend",
                "cancel",
                "terminate",
                "final",
                "last",
            ],
            "authority": [
                "dmv",
                "department",
                "government",
                "official",
                "agency",
                "bureau",
                "administration",
                "authority",
                "office",
                "court",
                "legal",
            ],
            "financial": [
                "payment",
                "fee",
                "fine",
                "penalty",
                "cost",
                "charge",
                "bill",
                "amount",
                "money",
                "pay",
                "owe",
                "debt",
                "credit",
                "account",
            ],
            "fear_appeals": [
                "penalty",
                "violation",
                "illegal",
                "arrest",
                "jail",
                "prison",
                "criminal",
                "felony",
                "misdemeanor",
                "prosecute",
                "sue",
                "lawsuit",
            ],
            "action_words": [
                "click",
                "visit",
                "call",
                "contact",
                "respond",
                "reply",
                "confirm",
                "verify",
                "update",
                "provide",
                "submit",
                "send",
                "download",
            ],
        }

        # Entity patterns for extraction
        self.entity_patterns = {
            "phone_numbers": r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            "urls": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            "domains": r"[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.(?:com|org|net|gov|edu|vip|tk|ml|ga|cf)",
            "email_addresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "amounts": r"\$[\d,]+(?:\.\d{2})?",
            "reference_numbers": r"(?:ref|reference|case|ticket|citation)[\s#:]*([a-zA-Z0-9]{6,})",
            "dates": r"\b(?:(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}(?:,\s*\d{4})?|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b",
        }

    def extract_features(self, messages_df: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Extract features from message data for NLP analysis

        Args:
            messages_df (pd.DataFrame or np.array): Message data

        Returns:
            np.ndarray: Feature matrix where each row is a sample and each column is a feature
        """
        # Handle numpy array vs DataFrame input
        if isinstance(messages_df, np.ndarray):
            # It's a numpy array of text messages
            if messages_df.ndim != 1:
                return np.array([])
            text_messages = messages_df
        elif isinstance(messages_df, pd.DataFrame):
            # It's a DataFrame
            if messages_df.empty or "text" not in messages_df.columns:
                return np.array([])
            text_messages = messages_df.dropna(subset=["text"])["text"]
        else:
            return np.array([])

        # Define fixed feature order for consistent output
        feature_names: List[str] = []

        # Add threat vocabulary features
        for vocab in sorted(self.threat_vocabularies.keys()):
            feature_names.append(vocab + "_matches")

        # Add entity pattern features
        for entity in sorted(self.entity_patterns.keys()):
            feature_names.append(entity + "_matches")

        # Additional basic features
        feature_names.extend(
            [
                "message_length",
                "word_count",
                "sentence_count",
                "exclamation_count",
                "question_count",
                "caps_ratio",
            ]
        )

        # Initialize feature matrix
        feature_matrix: List[List[float]] = []

        # Extract features for each message
        for text in text_messages:
            feature_vector: List[float]
            if pd.isna(text):
                # Fill with zeros for missing text
                feature_vector = [0.0] * len(feature_names)
            else:
                text_str = str(text)
                words = word_tokenize(text_str.lower())
                filtered_words = [
                    word for word in words if word.isalpha() and word not in self.stop_words
                ]

                feature_vector = []

                # Threat vocabulary features
                for vocab in sorted(self.threat_vocabularies.keys()):
                    count = sum(
                        1 for word in filtered_words if word in self.threat_vocabularies[vocab]
                    )
                    feature_vector.append(float(count))

                # Entity pattern features
                for entity in sorted(self.entity_patterns.keys()):
                    pattern = self.entity_patterns[entity]
                    count = len(re.findall(pattern, text_str))
                    feature_vector.append(float(count))

                # Basic text features
                feature_vector.extend(
                    [
                        float(len(text_str)),  # message_length
                        float(len(words)),  # word_count
                        float(len(sent_tokenize(text_str))),  # sentence_count
                        float(text_str.count("!")),  # exclamation_count
                        float(text_str.count("?")),  # question_count
                        (
                            float(sum(1 for c in text_str if c.isupper())) / float(len(text_str))
                            if text_str
                            else 0.0
                        ),  # caps_ratio
                    ]
                )

            feature_matrix.append(feature_vector)

        return np.array(feature_matrix)

    def get_feature_importance(self, features: np.ndarray, labels: np.ndarray) -> np.ndarray:
        """
        Calculate feature importance based on correlation with labels

        Args:
            features (np.ndarray): Feature matrix
            labels (np.ndarray): Target labels

        Returns:
            np.ndarray: Feature importance scores
        """
        if len(features) == 0 or len(labels) == 0:
            return np.array([])

        # Calculate correlation between each feature and the labels
        importance_scores = []

        for feature_idx in range(features.shape[1]):
            feature_values = features[:, feature_idx]

            # Calculate correlation coefficient
            if np.std(feature_values) == 0:
                # No variance in feature values
                importance_scores.append(0.0)
            else:
                correlation = np.corrcoef(feature_values, labels)[0, 1]
                # Use absolute correlation as importance score
                importance_scores.append(abs(correlation) if not np.isnan(correlation) else 0.0)

        return np.array(importance_scores)

    def analyze(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a list of messages and return NLP analysis results

        Args:
            messages (List[Dict]): List of message dictionaries

        Returns:
            dict: NLP analysis results with entities and sentiment
        """
        if not messages:
            raise ValueError("Messages list is empty")

        # Convert to DataFrame for analysis
        df = pd.DataFrame(messages)

        # Ensure we have text column
        if "text" not in df.columns:
            raise ValueError("Messages must contain 'text' field")

        # Run comprehensive analysis
        analysis_results = self.analyze_message_content(df)

        if analysis_results is None or "error" in analysis_results:
            error_msg = (
                analysis_results.get("error", "Unable to analyze messages")
                if analysis_results
                else "Unable to analyze messages"
            )
            raise ValueError(f"Unable to analyze messages: {error_msg}")

        # Extract entities and sentiment for the test
        entities = analysis_results.get("entity_extraction", {})
        sentiment = analysis_results.get("sentiment_analysis", {})

        return {"entities": entities, "sentiment": sentiment, "full_analysis": analysis_results}

    def analyze_message_content(self, messages_df: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """
        Perform comprehensive NLP analysis on message content

        Args:
            messages_df (pd.DataFrame): Message data with text content

        Returns:
            dict: Comprehensive NLP analysis results
        """
        if messages_df is None or messages_df.empty or "text" not in messages_df.columns:
            return None

        # Filter out messages without text
        text_messages = messages_df.dropna(subset=["text"])
        text_messages = text_messages[text_messages["text"].str.strip() != ""]

        if len(text_messages) == 0:
            return {"error": "no_text_content"}

        nlp_analysis = {
            "sentiment_analysis": self._analyze_sentiment(text_messages),
            "entity_extraction": self._extract_entities(text_messages),
            "vocabulary_analysis": self._analyze_vocabulary(text_messages),
            "linguistic_patterns": self._analyze_linguistic_patterns(text_messages),
            "deception_indicators": self._detect_deception_indicators(text_messages),
            "urgency_analysis": self._analyze_urgency_patterns(text_messages),
            "semantic_topics": self._extract_semantic_topics(text_messages),
        }

        return nlp_analysis

    def _analyze_sentiment(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze sentiment patterns in messages"""
        sentiments = []

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"])
            blob = TextBlob(text)

            sentiment_data = {
                "message_id": message.get("ROWID", 0),
                "text_preview": text[:50] + "..." if len(text) > 50 else text,
                "polarity": blob.sentiment.polarity,  # -1 (negative) to 1 (positive)
                "subjectivity": blob.sentiment.subjectivity,  # 0 (objective) to 1 (subjective)
                "is_from_me": message.get("is_from_me", 0),
                "timestamp": message.get("readable_date", ""),
            }

            # Categorize sentiment
            if sentiment_data["polarity"] >= 0.1:
                sentiment_data["sentiment_category"] = "positive"
            elif sentiment_data["polarity"] <= -0.1:
                sentiment_data["sentiment_category"] = "negative"
            else:
                sentiment_data["sentiment_category"] = "neutral"

            if sentiment_data["sentiment_category"] == "negative" and "urgent" in text.lower():
                sentiment_data["threat_indicator"] = "potential threat"
            else:
                sentiment_data["threat_indicator"] = "normal"

            sentiments.append(sentiment_data)

        # Calculate aggregate statistics
        if sentiments:
            polarities = [s["polarity"] for s in sentiments]
            subjectivities = [s["subjectivity"] for s in sentiments]

            # Separate by sender
            sent_messages = [s for s in sentiments if s["is_from_me"] == 1]
            received_messages = [s for s in sentiments if s["is_from_me"] == 0]

            aggregate_stats = {
                "overall_polarity_mean": np.mean(polarities),
                "overall_polarity_std": np.std(polarities),
                "overall_subjectivity_mean": np.mean(subjectivities),
                "sentiment_distribution": {
                    "positive": len(
                        [s for s in sentiments if s["sentiment_category"] == "positive"]
                    ),
                    "negative": len(
                        [s for s in sentiments if s["sentiment_category"] == "negative"]
                    ),
                    "neutral": len([s for s in sentiments if s["sentiment_category"] == "neutral"]),
                },
                "sent_vs_received": {
                    "sent_polarity_mean": (
                        np.mean([s["polarity"] for s in sent_messages]) if sent_messages else 0
                    ),
                    "received_polarity_mean": (
                        np.mean([s["polarity"] for s in received_messages])
                        if received_messages
                        else 0
                    ),
                    "sentiment_asymmetry": self._calculate_sentiment_asymmetry(
                        sent_messages, received_messages
                    ),
                },
            }
        else:
            aggregate_stats = {}

        return {
            "message_sentiments": sentiments,
            "aggregate_statistics": aggregate_stats,
            "sentiment_timeline": self._create_sentiment_timeline(sentiments),
        }

    def _calculate_sentiment_asymmetry(self, sent_messages: List[Dict[str, Any]], received_messages: List[Dict[str, Any]]) -> float:
        """Calculate asymmetry between sent and received message sentiment"""
        if not sent_messages or not received_messages:
            return 0

        sent_polarity = np.mean([s["polarity"] for s in sent_messages])
        received_polarity = np.mean([s["polarity"] for s in received_messages])

        return float(abs(float(sent_polarity) - float(received_polarity)))

    def _create_sentiment_timeline(self, sentiments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create sentiment evolution timeline"""
        if not sentiments:
            return []

        # Sort by timestamp and create timeline
        timeline = []
        for sentiment in sorted(sentiments, key=lambda x: x.get("timestamp", "")):
            timeline.append(
                {
                    "timestamp": sentiment["timestamp"],
                    "polarity": sentiment["polarity"],
                    "sentiment_category": sentiment["sentiment_category"],
                    "is_from_me": sentiment["is_from_me"],
                }
            )

        return timeline

    def _extract_entities(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Extract entities from message content"""
        all_entities: Dict[str, List[Dict[str, Any]]] = {
            "phone_numbers": [],
            "urls": [],
            "domains": [],
            "email_addresses": [],
            "amounts": [],
            "reference_numbers": [],
            "dates": [],
            "named_entities": [],
        }

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"])
            message_id = message.get("ROWID", 0)

            # Extract using regex patterns
            for entity_type, pattern in self.entity_patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    all_entities[entity_type].append(
                        {
                            "value": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

            # Extract named entities using NLTK
            named_entities = self._extract_named_entities(text)
            for entity in named_entities:
                all_entities["named_entities"].append(
                    {
                        "entity": entity["entity"],
                        "label": entity["label"],
                        "message_id": message_id,
                        "context": entity["context"],
                    }
                )

        # Generate entity statistics
        entity_stats = {}
        for entity_type, entities in all_entities.items():
            if entities:
                entity_stats[entity_type] = {
                    "count": len(entities),
                    "unique_count": len(
                        set(e["value"] if "value" in e else e["entity"] for e in entities)
                    ),
                    "most_common": self._get_most_common_entities(entities, entity_type),
                }
            else:
                entity_stats[entity_type] = {"count": 0, "unique_count": 0, "most_common": []}

        return {
            "extracted_entities": all_entities,
            "entity_statistics": entity_stats,
            "suspicious_entities": self._identify_suspicious_entities(all_entities),
        }

    def _get_entity_context(self, text: str, entity: str, window: int = 20) -> str:
        """Get context around an extracted entity"""
        entity_pos = text.lower().find(str(entity).lower())
        if entity_pos == -1:
            return text[:50]

        start = max(0, entity_pos - window)
        end = min(len(text), entity_pos + len(str(entity)) + window)

        return text[start:end]

    def _extract_named_entities(self, text: str) -> List[Dict[str, str]]:
        """Extract named entities using NLTK"""
        entities = []

        try:
            tokens = word_tokenize(text)
            pos_tags = pos_tag(tokens)
            chunks = ne_chunk(pos_tags)

            for chunk in chunks:
                if isinstance(chunk, Tree):
                    entity_name = " ".join([token for token, pos in chunk.leaves()])
                    entity_label = chunk.label()
                    entities.append(
                        {
                            "entity": entity_name,
                            "label": entity_label,
                            "context": self._get_entity_context(text, entity_name),
                        }
                    )
        except Exception:
            # If NLTK processing fails, continue without named entities
            pass

        return entities

    def _get_most_common_entities(self, entities: List[Dict[str, Any]], entity_type: str) -> List[Tuple[str, int]]:
        """Get most common entities of a specific type"""
        if entity_type == "named_entities":
            entity_values = [e["entity"] for e in entities]
        else:
            entity_values = [e["value"] for e in entities]

        counter = Counter(entity_values)
        return counter.most_common(5)

    def _identify_suspicious_entities(self, all_entities: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Identify potentially suspicious entities"""
        suspicious: Dict[str, List[Dict[str, Any]]] = {
            "suspicious_domains": [],
            "suspicious_phone_numbers": [],
            "suspicious_amounts": [],
            "red_flag_entities": [],
        }

        # Check for suspicious domains
        for domain_info in all_entities.get("domains", []):
            domain = domain_info["value"]
            if any(tld in domain.lower() for tld in [".vip", ".tk", ".ml", ".ga", ".cf"]):
                suspicious["suspicious_domains"].append(domain_info)
            elif "gov" in domain.lower() and not domain.lower().endswith(".gov"):
                suspicious["suspicious_domains"].append(domain_info)

        # Check for international phone numbers
        for phone_info in all_entities.get("phone_numbers", []):
            phone = phone_info["value"]
            if phone.startswith("+63") or phone.startswith("+1"):
                suspicious["suspicious_phone_numbers"].append(phone_info)

        # Check for large amounts
        for amount_info in all_entities.get("amounts", []):
            amount_str = amount_info["value"].replace("$", "").replace(",", "")
            try:
                amount = float(amount_str)
                if amount > 500:  # Suspicious if over $500
                    suspicious["suspicious_amounts"].append(amount_info)
            except ValueError:
                pass

        return suspicious

    def _analyze_vocabulary(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze vocabulary usage and threat-specific terminology"""
        all_words = []
        threat_vocabulary_usage = defaultdict(list)

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"]).lower()
            words = word_tokenize(text)

            # Filter out stopwords and punctuation
            words = [word for word in words if word.isalpha() and word not in self.stop_words]
            all_words.extend(words)

            # Check for threat vocabulary usage
            for category, vocab_list in self.threat_vocabularies.items():
                for word in vocab_list:
                    if word.lower() in text:
                        threat_vocabulary_usage[category].append(
                            {
                                "word": word,
                                "message_id": message.get("ROWID", 0),
                                "context": self._get_entity_context(text, word),
                            }
                        )

        # Calculate vocabulary statistics
        word_freq = Counter(all_words)
        vocab_stats = {
            "total_words": len(all_words),
            "unique_words": len(set(all_words)),
            "vocabulary_richness": len(set(all_words)) / len(all_words) if all_words else 0,
            "most_common_words": word_freq.most_common(20),
            "threat_vocabulary_usage": dict(threat_vocabulary_usage),
            "threat_score": self._calculate_threat_vocabulary_score(threat_vocabulary_usage),
        }

        return vocab_stats

    def _calculate_threat_vocabulary_score(self, threat_usage: Dict[str, List[Dict[str, Any]]]) -> int:
        """Calculate score based on threat vocabulary usage"""
        score = 0
        weights = {
            "urgency": 15,
            "authority": 20,
            "financial": 25,
            "fear_appeals": 30,
            "action_words": 10,
        }

        for category, occurrences in threat_usage.items():
            if occurrences:
                category_score = len(occurrences) * weights.get(category, 10)
                score += min(category_score, weights.get(category, 10) * 3)  # Cap per category

        return min(score, 100)  # Cap total score at 100

    def _analyze_linguistic_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze linguistic patterns and writing style"""
        message_lengths: List[Dict[str, int]] = []
        sentence_structures: List[Dict[str, Any]] = []
        punctuation_usage: Dict[str, int] = {}
        capitalization_patterns: Dict[str, int] = {}
        grammatical_errors: List[Dict[str, str]] = []

        patterns: Dict[str, Any] = {
            "message_lengths": message_lengths,
            "sentence_structures": sentence_structures,
            "punctuation_usage": punctuation_usage,
            "capitalization_patterns": capitalization_patterns,
            "grammatical_errors": grammatical_errors,
        }

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"])

            # Message length analysis
            patterns["message_lengths"].append(
                {
                    "message_id": message.get("ROWID", 0),
                    "character_count": len(text),
                    "word_count": len(text.split()),
                    "sentence_count": len(sent_tokenize(text)),
                }
            )

            # Punctuation analysis
            punctuation_chars = "!?.,;:"
            for char in punctuation_chars:
                if char not in patterns["punctuation_usage"]:
                    patterns["punctuation_usage"][char] = 0
                patterns["punctuation_usage"][char] += text.count(char)

            # Capitalization analysis
            patterns["capitalization_patterns"]["all_caps_words"] = patterns[
                "capitalization_patterns"
            ].get("all_caps_words", 0)
            patterns["capitalization_patterns"]["all_caps_words"] += len(
                [word for word in text.split() if word.isupper() and len(word) > 1]
            )

            # Grammar check using TextBlob
            try:
                blob = TextBlob(text)
                corrected = blob.correct()
                if str(blob) != str(corrected):
                    patterns["grammatical_errors"].append(
                        {
                            "message_id": message.get("ROWID", 0),
                            "original": str(blob),
                            "corrected": str(corrected),
                        }
                    )
            except Exception:
                pass

        # Calculate aggregate statistics
        if patterns["message_lengths"]:
            char_counts = [m["character_count"] for m in patterns["message_lengths"]]
            word_counts = [m["word_count"] for m in patterns["message_lengths"]]

            patterns["aggregate_stats"] = {
                "avg_message_length_chars": np.mean(char_counts),
                "avg_message_length_words": np.mean(word_counts),
                "message_length_variance": np.var(char_counts),
                "total_grammatical_errors": len(patterns["grammatical_errors"]),
                "error_rate": len(patterns["grammatical_errors"])
                / len(patterns["message_lengths"]),
            }

        return patterns

    def _detect_deception_indicators(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Detect linguistic indicators of deception"""
        deception_indicators: Dict[str, Any] = {
            "hedging_language": [],
            "excessive_details": [],
            "inconsistencies": [],
            "emotional_manipulation": [],
            "credibility_appeals": [],
        }

        # Define deception patterns
        hedging_patterns = [
            r"\b(maybe|perhaps|possibly|might|could|seem|appear|sort of|kind of)\b",
            r"\b(i think|i believe|i guess|i suppose)\b",
        ]

        credibility_patterns = [
            r"\b(official|legitimate|authorized|certified|verified|secure)\b",
            r"\b(trust|reliable|guaranteed|assured)\b",
        ]

        emotional_patterns = [
            r"\b(urgent|emergency|critical|immediate|deadline)\b",
            r"\b(worried|concerned|afraid|anxious|scared)\b",
        ]

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"]).lower()
            message_id = message.get("ROWID", 0)

            # Check for hedging language
            for pattern in hedging_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    deception_indicators["hedging_language"].append(
                        {
                            "match": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

            # Check for credibility appeals
            for pattern in credibility_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    deception_indicators["credibility_appeals"].append(
                        {
                            "match": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

            # Check for emotional manipulation
            for pattern in emotional_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    deception_indicators["emotional_manipulation"].append(
                        {
                            "match": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

            # Check for excessive details (very long messages)
            if len(text) > 500:  # Arbitrary threshold
                deception_indicators["excessive_details"].append(
                    {"message_id": message_id, "length": len(text), "preview": text[:100] + "..."}
                )

        # Calculate deception score
        deception_score = self._calculate_deception_score(deception_indicators)
        deception_indicators["deception_score"] = deception_score

        return deception_indicators

    def _calculate_deception_score(self, indicators: Dict[str, Any]) -> int:
        """Calculate overall deception likelihood score"""
        score = 0
        weights = {
            "hedging_language": 5,
            "excessive_details": 10,
            "emotional_manipulation": 15,
            "credibility_appeals": 20,
        }

        for indicator_type, occurrences in indicators.items():
            if indicator_type in weights and isinstance(occurrences, list):
                score += len(occurrences) * weights[indicator_type]

        return min(score, 100)

    def _analyze_urgency_patterns(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze urgency and pressure tactics in messages"""
        urgency_indicators: Dict[str, Any] = {
            "time_pressure": [],
            "consequence_threats": [],
            "action_demands": [],
            "urgency_score": 0,
        }

        time_patterns = [
            r"\b(today|now|immediately|asap|urgent|deadline|expire|expires)\b",
            r"\b(within \d+ (hours?|days?|minutes?))\b",
            r"\b(before \w+day)\b",
        ]

        consequence_patterns = [
            r"\b(suspend|cancel|terminate|close|block|freeze)\b",
            r"\b(penalty|fine|fee|charge|arrest|prosecution)\b",
            r"\b(lose|forfeit|denied|rejected)\b",
        ]

        action_patterns = [
            r"\b(click|call|visit|contact|respond|reply|confirm)\b",
            r"\b(must|need to|have to|required to)\b",
            r"\b(act now|respond now|call now)\b",
        ]

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"]).lower()
            message_id = message.get("ROWID", 0)

            # Check for time pressure
            for pattern in time_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    urgency_indicators["time_pressure"].append(
                        {
                            "match": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

            # Check for consequence threats
            for pattern in consequence_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    urgency_indicators["consequence_threats"].append(
                        {
                            "match": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

            # Check for action demands
            for pattern in action_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    urgency_indicators["action_demands"].append(
                        {
                            "match": match,
                            "message_id": message_id,
                            "context": self._get_entity_context(text, match),
                        }
                    )

        # Calculate urgency score
        urgency_score = (
            len(urgency_indicators["time_pressure"]) * 15
            + len(urgency_indicators["consequence_threats"]) * 20
            + len(urgency_indicators["action_demands"]) * 10
        )
        urgency_indicators["urgency_score"] = min(urgency_score, 100)

        return urgency_indicators

    def _extract_semantic_topics(self, messages_df: pd.DataFrame) -> Dict[str, Any]:
        """Extract semantic topics and themes from messages"""
        # Simple topic extraction using keyword clustering
        topics: Dict[str, List[Dict[str, Any]]] = {
            "government_services": [],
            "financial_transactions": [],
            "legal_threats": [],
            "identity_verification": [],
            "technical_support": [],
        }

        topic_keywords = {
            "government_services": [
                "dmv",
                "license",
                "registration",
                "renewal",
                "government",
                "department",
            ],
            "financial_transactions": [
                "payment",
                "fee",
                "cost",
                "money",
                "credit",
                "debit",
                "bank",
            ],
            "legal_threats": ["violation", "penalty", "court", "legal", "arrest", "prosecution"],
            "identity_verification": [
                "verify",
                "confirm",
                "identity",
                "ssn",
                "personal",
                "information",
            ],
            "technical_support": [
                "system",
                "update",
                "technical",
                "error",
                "maintenance",
                "server",
            ],
        }

        for _, message in messages_df.iterrows():
            if pd.isna(message["text"]):
                continue

            text = str(message["text"]).lower()
            message_id = message.get("ROWID", 0)

            for topic, keywords in topic_keywords.items():
                topic_score = sum(1 for keyword in keywords if keyword in text)
                if topic_score > 0:
                    topics[topic].append(
                        {
                            "message_id": message_id,
                            "topic_score": topic_score,
                            "matched_keywords": [kw for kw in keywords if kw in text],
                            "text_preview": text[:100] + "..." if len(text) > 100 else text,
                        }
                    )

        # Calculate topic prevalence
        topic_stats = {}
        for topic, messages in topics.items():
            topic_stats[topic] = {
                "message_count": len(messages),
                "avg_score": np.mean([m["topic_score"] for m in messages]) if messages else 0,
                "prevalence": len(messages) / len(messages_df) if len(messages_df) > 0 else 0,
            }

        return {
            "topic_assignments": topics,
            "topic_statistics": topic_stats,
            "dominant_topics": sorted(
                topic_stats.items(), key=lambda x: x[1]["prevalence"], reverse=True
            )[:3],
        }

    def generate_nlp_report(self, contact_identifier: str, nlp_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive NLP analysis report

        Args:
            contact_identifier (str): Contact being analyzed
            nlp_analysis (dict): NLP analysis results
        """
        report = {
            "analysis_metadata": {
                "contact_analyzed": contact_identifier,
                "analysis_timestamp": datetime.now().isoformat(),
                "analysis_type": "natural_language_processing",
            },
            "nlp_analysis": nlp_analysis,
            "risk_assessment": self._assess_nlp_risk(nlp_analysis),
            "recommendations": self._generate_nlp_recommendations(nlp_analysis),
        }

        # Save detailed report
        output_file = f"{self.output_dir}/nlp_analysis_{contact_identifier.replace('+', '')}.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"✓ NLP analysis report saved: {output_file}")

        # Generate summary
        self._generate_nlp_summary(report, contact_identifier)

        return report

    def _assess_nlp_risk(self, nlp_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk based on NLP analysis results"""
        risk_factors = []
        risk_score = 0

        # Sentiment risk factors
        sentiment_analysis = nlp_analysis.get("sentiment_analysis", {})
        aggregate_stats = sentiment_analysis.get("aggregate_statistics", {})

        if aggregate_stats.get("overall_polarity_mean", 0) < -0.3:
            risk_factors.append("Predominantly negative sentiment detected")
            risk_score += 15

        # Entity risk factors
        entity_analysis = nlp_analysis.get("entity_extraction", {})
        suspicious_entities = entity_analysis.get("suspicious_entities", {})

        if suspicious_entities.get("suspicious_domains"):
            risk_factors.append(
                f"Suspicious domains detected: {len(suspicious_entities['suspicious_domains'])}"
            )
            risk_score += 25

        if suspicious_entities.get("suspicious_phone_numbers"):
            risk_factors.append(
                f"International phone numbers detected: {len(suspicious_entities['suspicious_phone_numbers'])}"
            )
            risk_score += 20

        # Vocabulary risk factors
        vocab_analysis = nlp_analysis.get("vocabulary_analysis", {})
        threat_score = vocab_analysis.get("threat_score", 0)

        if threat_score > 50:
            risk_factors.append(f"High threat vocabulary usage (score: {threat_score})")
            risk_score += threat_score * 0.3

        # Deception risk factors
        deception_analysis = nlp_analysis.get("deception_indicators", {})
        deception_score = deception_analysis.get("deception_score", 0)

        if deception_score > 30:
            risk_factors.append(f"Deception indicators present (score: {deception_score})")
            risk_score += deception_score * 0.4

        # Urgency risk factors
        urgency_analysis = nlp_analysis.get("urgency_analysis", {})
        urgency_score = urgency_analysis.get("urgency_score", 0)

        if urgency_score > 40:
            risk_factors.append(f"High urgency/pressure tactics (score: {urgency_score})")
            risk_score += urgency_score * 0.3

        return {
            "nlp_risk_score": min(100, int(risk_score)),
            "risk_factors": risk_factors,
            "risk_level": self._categorize_risk_level(risk_score),
        }

    def _categorize_risk_level(self, score: float) -> str:
        """Categorize risk level based on score"""
        if score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_nlp_recommendations(self, nlp_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations based on NLP analysis"""
        recommendations = []

        # Entity-based recommendations
        entity_analysis = nlp_analysis.get("entity_extraction", {})
        suspicious_entities = entity_analysis.get("suspicious_entities", {})

        if suspicious_entities.get("suspicious_domains"):
            recommendations.append(
                {
                    "priority": "HIGH",
                    "recommendation": "Block and investigate suspicious domains",
                    "rationale": "Non-standard TLD domains detected that may be used for phishing",
                }
            )

        # Deception-based recommendations
        deception_analysis = nlp_analysis.get("deception_indicators", {})
        if deception_analysis.get("deception_score", 0) > 50:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "recommendation": "High likelihood of deceptive communication",
                    "rationale": "Multiple deception indicators detected in message content",
                }
            )

        # Urgency-based recommendations
        urgency_analysis = nlp_analysis.get("urgency_analysis", {})
        if urgency_analysis.get("urgency_score", 0) > 50:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "recommendation": "Social engineering attempt likely",
                    "rationale": "High pressure tactics and urgency indicators present",
                }
            )

        # Vocabulary-based recommendations
        vocab_analysis = nlp_analysis.get("vocabulary_analysis", {})
        if vocab_analysis.get("threat_score", 0) > 40:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "recommendation": "Monitor for government impersonation",
                    "rationale": "Threat-specific vocabulary patterns detected",
                }
            )

        return recommendations

    def _generate_nlp_summary(self, report: Dict[str, Any], contact_identifier: str) -> None:
        """Generate human-readable NLP summary"""
        summary_file = f"{self.output_dir}/nlp_summary_{contact_identifier.replace('+', '')}.txt"

        with open(summary_file, "w") as f:
            f.write("Natural Language Processing Analysis Summary\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Contact: {contact_identifier}\n")
            f.write(f"Analysis Date: {report['analysis_metadata']['analysis_timestamp']}\n\n")

            # Risk assessment
            risk_assessment = report.get("risk_assessment", {})
            f.write(f"NLP Risk Score: {risk_assessment.get('nlp_risk_score', 0)}/100\n")
            f.write(f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}\n\n")

            # Key findings
            nlp_analysis = report.get("nlp_analysis", {})

            # Sentiment summary
            sentiment = nlp_analysis.get("sentiment_analysis", {})
            if sentiment:
                aggregate = sentiment.get("aggregate_statistics", {})
                f.write(
                    f"Overall Sentiment: {aggregate.get('overall_polarity_mean', 0):.2f} (polarity)\n"
                )

            # Entity summary
            entities = nlp_analysis.get("entity_extraction", {})
            if entities:
                entity_stats = entities.get("entity_statistics", {})
                f.write(
                    f"Extracted Entities: {sum(stats.get('count', 0) for stats in entity_stats.values())}\n"
                )

            # Threat vocabulary
            vocab = nlp_analysis.get("vocabulary_analysis", {})
            if vocab:
                f.write(f"Threat Vocabulary Score: {vocab.get('threat_score', 0)}/100\n")

            f.write("\nKey Risk Factors:\n")
            for factor in risk_assessment.get("risk_factors", []):
                f.write(f"  • {factor}\n")

            f.write("\nRecommendations:\n")
            for rec in report.get("recommendations", []):
                f.write(f"  [{rec['priority']}] {rec['recommendation']}\n")
                f.write(f"      Rationale: {rec['rationale']}\n")

        print(f"✓ NLP summary saved: {summary_file}")


def main() -> int:
    """
    Main execution function for standalone NLP analysis
    """
    import argparse

    parser = argparse.ArgumentParser(description="Advanced NLP Analysis Tool")
    parser.add_argument("--input-file", required=True, help="Path to message data (JSON or CSV)")
    parser.add_argument("--contact", required=True, help="Contact identifier")
    parser.add_argument("--output-dir", default="./analysis_output", help="Output directory")

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = AdvancedNLPAnalyzer(output_dir=args.output_dir)

    try:
        # Load data
        if args.input_file.endswith(".json"):
            with open(args.input_file, "r") as f:
                data = json.load(f)
                messages_df = pd.DataFrame(data)
        else:
            messages_df = pd.read_csv(args.input_file)

        # Perform NLP analysis
        nlp_analysis = analyzer.analyze_message_content(messages_df)

        if nlp_analysis and "error" not in nlp_analysis:
            # Generate report
            report = analyzer.generate_nlp_report(args.contact, nlp_analysis)

            print(f"\n✓ NLP analysis complete for: {args.contact}")
            print(f"✓ Risk Score: {report['risk_assessment']['nlp_risk_score']}/100")

            # Print key findings
            vocab_score = nlp_analysis.get("vocabulary_analysis", {}).get("threat_score", 0)
            urgency_score = nlp_analysis.get("urgency_analysis", {}).get("urgency_score", 0)
            deception_score = nlp_analysis.get("deception_indicators", {}).get("deception_score", 0)

            print(f"✓ Threat Vocabulary Score: {vocab_score}/100")
            print(f"✓ Urgency Score: {urgency_score}/100")
            print(f"✓ Deception Score: {deception_score}/100")
        else:
            print("❌ No text content available for analysis")
            return 1

    except Exception as e:
        print(f"❌ NLP analysis failed: {e}")
        return 1

    return 0


# Class aliases for backward compatibility
NLPAnalyzer = AdvancedNLPAnalyzer

if __name__ == "__main__":
    exit(main())
