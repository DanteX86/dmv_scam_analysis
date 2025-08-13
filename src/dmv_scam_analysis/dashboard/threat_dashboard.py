"""
Real-time threat monitoring dashboard for DMV Scam Analysis system.
Provides live visualization of threats, system performance, and analytics.
"""

import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

# Dashboard dependencies
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import pandas as pd
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("Plotly not available. Dashboard will use basic visualization.")

logger = logging.getLogger(__name__)


class ThreatDashboard:
    """Real-time threat monitoring dashboard."""
    
    def __init__(self, data_dir: str = "dashboard_data"):
        """
        Initialize threat dashboard.
        
        Args:
            data_dir: Directory to store dashboard data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Data storage files
        self.threats_file = self.data_dir / "threats.json"
        self.metrics_file = self.data_dir / "metrics.json"
        self.alerts_file = self.data_dir / "alerts.json"
        
        # Initialize data stores
        self.threats_data = self._load_data(self.threats_file, [])
        self.metrics_data = self._load_data(self.metrics_file, {})
        self.alerts_data = self._load_data(self.alerts_file, [])
        
        # Dashboard configuration
        self.alert_thresholds = {
            'high_risk_percentage': 20.0,  # Alert if >20% of messages are high risk
            'response_time': 2.0,          # Alert if response time >2s
            'error_rate': 5.0,             # Alert if error rate >5%
            'threat_spike': 50             # Alert if threats spike by 50%
        }
    
    def record_threat_analysis(self, analysis_result: Dict[str, Any]) -> None:
        """
        Record a new threat analysis result.
        
        Args:
            analysis_result: Result from threat analysis
        """
        threat_record = {
            'timestamp': datetime.now().isoformat(),
            'threat_score': analysis_result.get('threat_score', 0.0),
            'classification': analysis_result.get('classification', 'unknown'),
            'confidence': analysis_result.get('confidence', 0.0),
            'source': analysis_result.get('source', 'unknown'),
            'analysis_id': analysis_result.get('analysis_id', 'unknown'),
            'indicators': analysis_result.get('indicators', [])
        }
        
        self.threats_data.append(threat_record)
        
        # Keep only last 1000 records for performance
        if len(self.threats_data) > 1000:
            self.threats_data = self.threats_data[-1000:]
        
        self._save_data(self.threats_file, self.threats_data)
        
        # Check for alerts
        self._check_threat_alerts(threat_record)
        
        logger.info(f"Recorded threat analysis: {analysis_result.get('classification', 'unknown')}")
    
    def record_system_metric(self, metric_name: str, value: float, metadata: Dict = None) -> None:
        """
        Record a system performance metric.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            metadata: Additional metadata
        """
        timestamp = datetime.now().isoformat()
        
        if metric_name not in self.metrics_data:
            self.metrics_data[metric_name] = []
        
        metric_record = {
            'timestamp': timestamp,
            'value': value,
            'metadata': metadata or {}
        }
        
        self.metrics_data[metric_name].append(metric_record)
        
        # Keep only last 500 records per metric
        if len(self.metrics_data[metric_name]) > 500:
            self.metrics_data[metric_name] = self.metrics_data[metric_name][-500:]
        
        self._save_data(self.metrics_file, self.metrics_data)
        
        # Check for performance alerts
        self._check_performance_alerts(metric_name, value)
    
    def generate_dashboard_html(self, output_file: str = "threat_dashboard.html") -> str:
        """
        Generate an HTML dashboard file.
        
        Args:
            output_file: Output filename for the dashboard
            
        Returns:
            Path to the generated HTML file
        """
        if not PLOTLY_AVAILABLE:
            return self._generate_basic_html_dashboard(output_file)
        
        # Create dashboard with multiple visualizations
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=(
                'Threat Classification Distribution',
                'Threat Scores Over Time',
                'Response Time Metrics',
                'System Alert Status',
                'Daily Threat Summary',
                'Performance Overview'
            ),
            specs=[
                [{"type": "pie"}, {"type": "scatter"}],
                [{"type": "scatter"}, {"type": "indicator"}],
                [{"type": "bar"}, {"type": "table"}]
            ]
        )
        
        # 1. Threat Classification Pie Chart
        if self.threats_data:
            classifications = [t['classification'] for t in self.threats_data[-100:]]  # Last 100
            classification_counts = pd.Series(classifications).value_counts()
            
            fig.add_trace(
                go.Pie(
                    labels=classification_counts.index.tolist(),
                    values=classification_counts.values.tolist(),
                    name="Classifications"
                ),
                row=1, col=1
            )
        
        # 2. Threat Scores Timeline
        if self.threats_data:
            df_threats = pd.DataFrame(self.threats_data[-200:])  # Last 200
            df_threats['timestamp'] = pd.to_datetime(df_threats['timestamp'])
            
            fig.add_trace(
                go.Scatter(
                    x=df_threats['timestamp'],
                    y=df_threats['threat_score'],
                    mode='lines+markers',
                    name='Threat Score',
                    line=dict(color='red', width=2)
                ),
                row=1, col=2
            )
        
        # 3. Response Time Metrics
        if 'response_time' in self.metrics_data:
            df_response = pd.DataFrame(self.metrics_data['response_time'][-100:])
            df_response['timestamp'] = pd.to_datetime(df_response['timestamp'])
            
            fig.add_trace(
                go.Scatter(
                    x=df_response['timestamp'],
                    y=df_response['value'],
                    mode='lines',
                    name='Response Time (s)',
                    line=dict(color='blue', width=2)
                ),
                row=2, col=1
            )
        
        # 4. Alert Status Indicator
        active_alerts = len([a for a in self.alerts_data if not a.get('resolved', False)][-10:])\n        alert_color = \"red\" if active_alerts > 0 else \"green\"\n        alert_status = f\"{active_alerts} Active Alerts\" if active_alerts > 0 else \"All Clear\"\n        \n        fig.add_trace(\n            go.Indicator(\n                mode=\"gauge+number+delta\",\n                value=active_alerts,\n                domain={'x': [0, 1], 'y': [0, 1]},\n                title={'text': \"Active Alerts\"},\n                gauge={\n                    'axis': {'range': [None, 10]},\n                    'bar': {'color': alert_color},\n                    'steps': [\n                        {'range': [0, 3], 'color': \"lightgray\"},\n                        {'range': [3, 7], 'color': \"yellow\"},\n                        {'range': [7, 10], 'color': \"red\"}\n                    ],\n                    'threshold': {\n                        'line': {'color': \"red\", 'width': 4},\n                        'thickness': 0.75,\n                        'value': 5\n                    }\n                }\n            ),\n            row=2, col=2\n        )\n        \n        # 5. Daily Threat Summary (Bar Chart)\n        if self.threats_data:\n            # Get last 7 days of data\n            now = datetime.now()\n            daily_data = {}\n            \n            for threat in self.threats_data:\n                threat_date = datetime.fromisoformat(threat['timestamp']).date()\n                if (now.date() - threat_date).days <= 7:\n                    date_str = threat_date.strftime('%Y-%m-%d')\n                    if date_str not in daily_data:\n                        daily_data[date_str] = {'high': 0, 'medium': 0, 'low': 0}\n                    \n                    if threat['classification'] == 'high_risk':\n                        daily_data[date_str]['high'] += 1\n                    elif threat['classification'] == 'medium_risk':\n                        daily_data[date_str]['medium'] += 1\n                    else:\n                        daily_data[date_str]['low'] += 1\n            \n            dates = sorted(daily_data.keys())\n            high_counts = [daily_data[d]['high'] for d in dates]\n            medium_counts = [daily_data[d]['medium'] for d in dates]\n            low_counts = [daily_data[d]['low'] for d in dates]\n            \n            fig.add_trace(go.Bar(x=dates, y=high_counts, name='High Risk', marker_color='red'), row=3, col=1)\n            fig.add_trace(go.Bar(x=dates, y=medium_counts, name='Medium Risk', marker_color='orange'), row=3, col=1)\n            fig.add_trace(go.Bar(x=dates, y=low_counts, name='Low Risk', marker_color='green'), row=3, col=1)\n        \n        # 6. Performance Overview Table\n        performance_data = self._calculate_performance_summary()\n        \n        fig.add_trace(\n            go.Table(\n                header=dict(values=['Metric', 'Current Value', 'Status'],\n                           fill_color='paleturquoise',\n                           align='left'),\n                cells=dict(values=[\n                    list(performance_data.keys()),\n                    [str(v['value']) for v in performance_data.values()],\n                    [v['status'] for v in performance_data.values()]\n                ],\n                fill_color='lavender',\n                align='left')\n            ),\n            row=3, col=2\n        )\n        \n        # Update layout\n        fig.update_layout(\n            height=1200,\n            showlegend=True,\n            title_text=f\"DMV Scam Analysis - Real-time Threat Dashboard (Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\",\n            title_x=0.5\n        )\n        \n        # Save dashboard\n        output_path = self.data_dir / output_file\n        fig.write_html(str(output_path))\n        \n        logger.info(f\"Dashboard generated: {output_path}\")\n        return str(output_path)\n    \n    def _generate_basic_html_dashboard(self, output_file: str) -> str:\n        \"\"\"Generate a basic HTML dashboard without Plotly.\"\"\"\n        \n        # Calculate basic statistics\n        total_threats = len(self.threats_data)\n        recent_threats = [t for t in self.threats_data if \n                         datetime.now() - datetime.fromisoformat(t['timestamp']) < timedelta(hours=24)]\n        \n        high_risk_count = len([t for t in recent_threats if t['classification'] == 'high_risk'])\n        medium_risk_count = len([t for t in recent_threats if t['classification'] == 'medium_risk'])\n        low_risk_count = len([t for t in recent_threats if t['classification'] == 'low_risk'])\n        \n        active_alerts = len([a for a in self.alerts_data if not a.get('resolved', False)])\n        \n        # Generate HTML\n        html_content = f\"\"\"\n<!DOCTYPE html>\n<html>\n<head>\n    <title>DMV Scam Analysis - Threat Dashboard</title>\n    <meta http-equiv=\"refresh\" content=\"30\">\n    <style>\n        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}\n        .dashboard {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}\n        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}\n        .metric {{ font-size: 2em; font-weight: bold; color: #333; }}\n        .label {{ font-size: 0.9em; color: #666; margin-top: 5px; }}\n        .alert {{ background: #ffebee; border-left: 4px solid #f44336; }}\n        .success {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}\n        .warning {{ background: #fff3e0; border-left: 4px solid #ff9800; }}\n        h1 {{ text-align: center; color: #333; }}\n        .status-indicator {{ width: 20px; height: 20px; border-radius: 50%; display: inline-block; margin-right: 10px; }}\n        .status-green {{ background-color: #4caf50; }}\n        .status-red {{ background-color: #f44336; }}\n        .status-orange {{ background-color: #ff9800; }}\n    </style>\n</head>\n<body>\n    <h1>🛡️ DMV Scam Analysis - Threat Dashboard</h1>\n    <p style=\"text-align: center; color: #666;\">Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n    \n    <div class=\"dashboard\">\n        <div class=\"card\">\n            <div class=\"metric\">{total_threats}</div>\n            <div class=\"label\">Total Threats Analyzed</div>\n        </div>\n        \n        <div class=\"card\">\n            <div class=\"metric\">{len(recent_threats)}</div>\n            <div class=\"label\">Threats (Last 24 Hours)</div>\n        </div>\n        \n        <div class=\"card alert\" style=\"{'display: block' if high_risk_count > 0 else 'display: none'}\">\n            <div class=\"metric\" style=\"color: #f44336;\">{high_risk_count}</div>\n            <div class=\"label\">High Risk Threats</div>\n        </div>\n        \n        <div class=\"card warning\" style=\"{'display: block' if medium_risk_count > 0 else 'display: none'}\">\n            <div class=\"metric\" style=\"color: #ff9800;\">{medium_risk_count}</div>\n            <div class=\"label\">Medium Risk Threats</div>\n        </div>\n        \n        <div class=\"card success\">\n            <div class=\"metric\" style=\"color: #4caf50;\">{low_risk_count}</div>\n            <div class=\"label\">Low Risk Messages</div>\n        </div>\n        \n        <div class=\"card {'alert' if active_alerts > 0 else 'success'}\">\n            <span class=\"status-indicator {'status-red' if active_alerts > 0 else 'status-green'}\"></span>\n            <div class=\"metric\" style=\"color: {'#f44336' if active_alerts > 0 else '#4caf50'};\">{active_alerts}</div>\n            <div class=\"label\">Active Alerts</div>\n        </div>\n    </div>\n    \n    <div style=\"margin-top: 20px;\">\n        <div class=\"card\">\n            <h3>Recent High-Risk Threats</h3>\n            <ul>\n        \"\"\"\n        \n        # Add recent high-risk threats\n        recent_high_risk = [t for t in recent_threats if t['classification'] == 'high_risk'][-5:]\n        if recent_high_risk:\n            for threat in recent_high_risk:\n                timestamp = datetime.fromisoformat(threat['timestamp']).strftime('%H:%M:%S')\n                html_content += f\"\"\"<li>[{timestamp}] Score: {threat['threat_score']:.2f} - Source: {threat['source']}</li>\"\"\"\n        else:\n            html_content += \"<li>No high-risk threats in the last 24 hours ✅</li>\"\n        \n        html_content += \"\"\"\n            </ul>\n        </div>\n    </div>\n    \n    <div style=\"margin-top: 20px;\">\n        <div class=\"card\">\n            <h3>System Status</h3>\n            <p><span class=\"status-indicator status-green\"></span>ML Classifier: Operational</p>\n            <p><span class=\"status-indicator status-green\"></span>Model Manager: Operational</p>\n            <p><span class=\"status-indicator status-green\"></span>Data Pipeline: Operational</p>\n        </div>\n    </div>\n</body>\n</html>\n        \"\"\"\n        \n        # Save HTML file\n        output_path = self.data_dir / output_file\n        with open(output_path, 'w') as f:\n            f.write(html_content)\n        \n        logger.info(f\"Basic dashboard generated: {output_path}\")\n        return str(output_path)\n    \n    def _check_threat_alerts(self, threat_record: Dict[str, Any]) -> None:\n        \"\"\"Check if threat record triggers any alerts.\"\"\"\n        \n        # High threat score alert\n        if threat_record['threat_score'] > 0.8:\n            self._create_alert(\n                'high_threat_detected',\n                f\"High threat detected with score {threat_record['threat_score']:.2f}\",\n                'high',\n                {'threat_record': threat_record}\n            )\n        \n        # Check threat spike (compare to recent average)\n        recent_scores = [t['threat_score'] for t in self.threats_data[-20:]]  # Last 20\n        if len(recent_scores) >= 10:\n            avg_score = sum(recent_scores[:-1]) / len(recent_scores[:-1])\n            current_score = recent_scores[-1]\n            \n            if current_score > avg_score * 1.5:  # 50% spike\n                self._create_alert(\n                    'threat_spike',\n                    f\"Threat spike detected: {current_score:.2f} vs avg {avg_score:.2f}\",\n                    'medium',\n                    {'current_score': current_score, 'average_score': avg_score}\n                )\n    \n    def _check_performance_alerts(self, metric_name: str, value: float) -> None:\n        \"\"\"Check if performance metric triggers alerts.\"\"\"\n        \n        if metric_name == 'response_time' and value > self.alert_thresholds['response_time']:\n            self._create_alert(\n                'slow_response',\n                f\"Slow response time detected: {value:.2f}s\",\n                'medium',\n                {'metric': metric_name, 'value': value}\n            )\n        \n        elif metric_name == 'error_rate' and value > self.alert_thresholds['error_rate']:\n            self._create_alert(\n                'high_error_rate',\n                f\"High error rate detected: {value:.1f}%\",\n                'high',\n                {'metric': metric_name, 'value': value}\n            )\n    \n    def _create_alert(self, alert_type: str, message: str, severity: str, metadata: Dict = None) -> None:\n        \"\"\"Create a new alert.\"\"\"\n        \n        alert = {\n            'id': f\"{alert_type}_{int(time.time())}\",\n            'type': alert_type,\n            'message': message,\n            'severity': severity,\n            'timestamp': datetime.now().isoformat(),\n            'resolved': False,\n            'metadata': metadata or {}\n        }\n        \n        self.alerts_data.append(alert)\n        \n        # Keep only last 100 alerts\n        if len(self.alerts_data) > 100:\n            self.alerts_data = self.alerts_data[-100:]\n        \n        self._save_data(self.alerts_file, self.alerts_data)\n        \n        logger.warning(f\"Alert created: {alert['type']} - {alert['message']}\")\n    \n    def _calculate_performance_summary(self) -> Dict[str, Dict[str, Any]]:\n        \"\"\"Calculate performance summary statistics.\"\"\"\n        \n        summary = {}\n        \n        # Response time summary\n        if 'response_time' in self.metrics_data and self.metrics_data['response_time']:\n            recent_response_times = [m['value'] for m in self.metrics_data['response_time'][-10:]]\n            avg_response_time = sum(recent_response_times) / len(recent_response_times)\n            summary['Avg Response Time'] = {\n                'value': f\"{avg_response_time:.3f}s\",\n                'status': '✅ Good' if avg_response_time < 1.0 else '⚠️ Slow' if avg_response_time < 2.0 else '❌ Critical'\n            }\n        \n        # Threat detection rate\n        if self.threats_data:\n            recent_threats = [t for t in self.threats_data if \n                            datetime.now() - datetime.fromisoformat(t['timestamp']) < timedelta(hours=1)]\n            threat_rate = len(recent_threats)\n            summary['Threats/Hour'] = {\n                'value': str(threat_rate),\n                'status': '✅ Normal' if threat_rate < 10 else '⚠️ Elevated' if threat_rate < 20 else '❌ High'\n            }\n        \n        # Active alerts\n        active_alerts = len([a for a in self.alerts_data if not a.get('resolved', False)])\n        summary['Active Alerts'] = {\n            'value': str(active_alerts),\n            'status': '✅ Clear' if active_alerts == 0 else '⚠️ Some' if active_alerts < 3 else '❌ Many'\n        }\n        \n        return summary\n    \n    def get_dashboard_data(self) -> Dict[str, Any]:\n        \"\"\"Get current dashboard data for API consumption.\"\"\"\n        \n        return {\n            'timestamp': datetime.now().isoformat(),\n            'summary': {\n                'total_threats': len(self.threats_data),\n                'recent_threats': len([t for t in self.threats_data if \n                                     datetime.now() - datetime.fromisoformat(t['timestamp']) < timedelta(hours=24)]),\n                'active_alerts': len([a for a in self.alerts_data if not a.get('resolved', False)]),\n                'high_risk_count': len([t for t in self.threats_data[-100:] if t['classification'] == 'high_risk'])\n            },\n            'recent_threats': self.threats_data[-10:] if self.threats_data else [],\n            'active_alerts': [a for a in self.alerts_data if not a.get('resolved', False)][-5:],\n            'performance_summary': self._calculate_performance_summary()\n        }\n    \n    def _load_data(self, file_path: Path, default_value: Any) -> Any:\n        \"\"\"Load data from JSON file.\"\"\"\n        if file_path.exists():\n            try:\n                with open(file_path, 'r') as f:\n                    return json.load(f)\n            except Exception as e:\n                logger.error(f\"Failed to load data from {file_path}: {e}\")\n                return default_value\n        return default_value\n    \n    def _save_data(self, file_path: Path, data: Any) -> None:\n        \"\"\"Save data to JSON file.\"\"\"\n        try:\n            with open(file_path, 'w') as f:\n                json.dump(data, f, indent=2)\n        except Exception as e:\n            logger.error(f\"Failed to save data to {file_path}: {e}\")\n\n\ndef demo_dashboard():\n    \"\"\"Create a demo dashboard with sample data.\"\"\"\n    \n    dashboard = ThreatDashboard()\n    \n    # Add sample threat data\n    sample_threats = [\n        {'threat_score': 0.9, 'classification': 'high_risk', 'confidence': 0.85, 'source': 'sms', 'analysis_id': 'demo_1'},\n        {'threat_score': 0.3, 'classification': 'low_risk', 'confidence': 0.92, 'source': 'email', 'analysis_id': 'demo_2'},\n        {'threat_score': 0.7, 'classification': 'medium_risk', 'confidence': 0.78, 'source': 'sms', 'analysis_id': 'demo_3'},\n        {'threat_score': 0.95, 'classification': 'high_risk', 'confidence': 0.88, 'source': 'sms', 'analysis_id': 'demo_4'},\n        {'threat_score': 0.2, 'classification': 'low_risk', 'confidence': 0.95, 'source': 'email', 'analysis_id': 'demo_5'}\n    ]\n    \n    for threat in sample_threats:\n        dashboard.record_threat_analysis(threat)\n        time.sleep(0.1)  # Small delay to create time separation\n    \n    # Add sample performance metrics\n    dashboard.record_system_metric('response_time', 0.245)\n    dashboard.record_system_metric('response_time', 0.189)\n    dashboard.record_system_metric('response_time', 0.356)\n    dashboard.record_system_metric('response_time', 0.298)\n    \n    dashboard.record_system_metric('error_rate', 2.1)\n    dashboard.record_system_metric('error_rate', 1.8)\n    dashboard.record_system_metric('error_rate', 2.3)\n    \n    # Generate dashboard\n    dashboard_path = dashboard.generate_dashboard_html(\"demo_threat_dashboard.html\")\n    print(f\"Demo dashboard created: {dashboard_path}\")\n    \n    # Print dashboard data\n    data = dashboard.get_dashboard_data()\n    print(\"\\nDashboard Data:\")\n    print(json.dumps(data, indent=2))\n    \n    return dashboard_path\n\n\nif __name__ == \"__main__\":\n    demo_dashboard()"
