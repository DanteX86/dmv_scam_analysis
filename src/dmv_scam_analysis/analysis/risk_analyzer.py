"""
Risk Analysis Module
Assesses behavioral risk patterns and generates recommendations.
"""

import json
from datetime import datetime
from typing import Any, Dict, List


class RiskAnalyzer:
    """Analyzes risk based on behavioral patterns and automation indicators"""

    def __init__(self, output_dir: str = "./analysis_output") -> None:
        """
        Initialize risk analyzer

        Args:
            output_dir (str): Directory for analysis outputs
        """
        self.output_dir = output_dir

    def analyze_risk(
        self,
        contact_identifier: str,
        temporal_analysis: Dict[str, Any],
        automation_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate comprehensive risk analysis report

        Args:
            contact_identifier (str): Contact being analyzed
            temporal_analysis (dict): Temporal pattern analysis results
            automation_analysis (dict): Automation detection results

        Returns:
            dict: Risk analysis report
        """
        report = {
            "analysis_metadata": {
                "contact_analyzed": contact_identifier,
                "analysis_timestamp": datetime.now().isoformat(),
                "analysis_type": "behavioral_patterns",
            },
            "temporal_patterns": temporal_analysis,
            "automation_indicators": automation_analysis,
            "risk_assessment": self._assess_behavioral_risk(
                temporal_analysis, automation_analysis
            ),
            "recommendations": self._generate_recommendations(
                temporal_analysis, automation_analysis
            ),
        }

        # Save detailed report
        output_file = f"{self.output_dir}/behavioral_analysis_{contact_identifier.replace('+', '')}.json"
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"✓ Behavioral analysis report saved: {output_file}")

        # Generate summary
        self._generate_summary(report, contact_identifier)

        return report

    def _assess_behavioral_risk(
        self, temporal_analysis: Dict[str, Any], automation_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess risk based on behavioral patterns"""
        risk_factors = []
        risk_score = 0

        # Temporal risk factors
        if temporal_analysis and temporal_analysis.get("burst_detection"):
            burst_count = temporal_analysis["burst_detection"].get("total_bursts", 0)
            if burst_count > 3:
                risk_factors.append("High frequency message bursts detected")
                risk_score += 20

        if temporal_analysis and temporal_analysis.get("anomalous_timing"):
            anomaly_score = temporal_analysis["anomalous_timing"].get(
                "anomaly_score", 0
            )
            if anomaly_score > 0.3:
                risk_factors.append("Anomalous timing patterns detected")
                risk_score += 15

        # Automation risk factors
        if automation_analysis:
            automation_score = automation_analysis.get("overall_automation_score", 0)
            if automation_score > 0.7:
                risk_factors.append("High likelihood of automated messaging")
                risk_score += 25
            elif automation_score > 0.5:
                risk_factors.append("Moderate automation indicators present")
                risk_score += 15

        # Off-hours activity
        if temporal_analysis and temporal_analysis.get("hourly_distribution"):
            night_hours = [0, 1, 2, 3, 4, 5]
            hourly_dist = temporal_analysis["hourly_distribution"].get(
                "distribution", {}
            )
            night_activity = sum(hourly_dist.get(str(hour), 0) for hour in night_hours)
            total_activity = sum(hourly_dist.values()) if hourly_dist.values() else 1

            if night_activity / total_activity > 0.3:
                risk_factors.append("Significant activity during unusual hours")
                risk_score += 10

        return {
            "behavioral_risk_score": min(100, risk_score),
            "risk_factors": risk_factors,
            "risk_level": self._categorize_risk_level(risk_score),
        }

    def _categorize_risk_level(self, score: int) -> str:
        """Categorize risk level based on score"""
        if score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(
        self, temporal_analysis: Dict[str, Any], automation_analysis: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate recommendations based on analysis results"""
        recommendations = []

        # Content-based triggers (if provided by upstream pipeline)
        content = (
            automation_analysis.get("content_indicators", {})
            if automation_analysis
            else {}
        )
        keyword_hits = int(content.get("keyword_hits", 0))
        url_count = int(content.get("url_count", 0))
        payment_signals = int(content.get("payment_signals", 0))
        urgency_signals = int(content.get("urgency_signals", 0))
        if payment_signals >= 2 or urgency_signals >= 2:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "recommendation": "Escalate due to coercive/payment language",
                    "rationale": f"Detected {payment_signals} payment and {urgency_signals} urgency cues in content",
                }
            )
        elif keyword_hits >= 3 or url_count >= 2:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "recommendation": "Flag messages for manual review (scam indicators present)",
                    "rationale": f"Found {keyword_hits} scam keywords and {url_count} URLs/domains",
                }
            )

        if (
            automation_analysis
            and automation_analysis.get("overall_automation_score", 0) > 0.4
        ):
            recommendations.append(
                {
                    "priority": "HIGH",
                    "recommendation": "Investigate potential bot/automated messaging system",
                    "rationale": "High automation indicators suggest non-human communication patterns",
                }
            )

        if (
            temporal_analysis
            and temporal_analysis.get("burst_detection", {}).get("total_bursts", 0) > 1
        ):
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "recommendation": "Monitor for coordinated campaign activity",
                    "rationale": "Message burst patterns may indicate coordinated threat activity",
                }
            )

        if temporal_analysis and temporal_analysis.get("response_patterns", {}).get(
            "rapid_responses"
        ):
            rapid_count = len(temporal_analysis["response_patterns"]["rapid_responses"])
            if rapid_count > 1:
                recommendations.append(
                    {
                        "priority": "MEDIUM",
                        "recommendation": "Verify human vs automated responses",
                        "rationale": f"{rapid_count} rapid responses detected, possibly automated",
                    }
                )

        return recommendations

    def _generate_summary(
        self, report: Dict[str, Any], contact_identifier: str
    ) -> None:
        """Generate human-readable summary report"""
        summary_file = f"{self.output_dir}/behavioral_summary_{contact_identifier.replace('+', '')}.txt"

        with open(summary_file, "w") as f:
            f.write("Behavioral Analysis Summary\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Contact: {contact_identifier}\n")
            f.write(
                f"Analysis Date: {report['analysis_metadata']['analysis_timestamp']}\n\n"
            )

            # Risk assessment
            risk_assessment = report.get("risk_assessment", {})
            f.write(
                f"Behavioral Risk Score: {risk_assessment.get('behavioral_risk_score', 0)}/100\n"
            )
            f.write(f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}\n\n")

            # Automation analysis
            automation = report.get("automation_indicators", {})
            automation_score = automation.get("overall_automation_score", 0)
            f.write(
                f"Automation Likelihood: {automation_score:.2f} ({automation_score * 100:.1f}%)\n\n"
            )

            # Key findings
            f.write("Key Behavioral Findings:\n")
            for factor in risk_assessment.get("risk_factors", []):
                f.write(f"  • {factor}\n")

            f.write("\nRecommendations:\n")
            for rec in report.get("recommendations", []):
                f.write(f"  [{rec['priority']}] {rec['recommendation']}\n")
                f.write(f"      Rationale: {rec['rationale']}\n")

        print(f"✓ Behavioral summary saved: {summary_file}")
