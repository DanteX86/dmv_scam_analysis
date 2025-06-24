#!/usr/bin/env python3
"""
Threat Analysis Visualization Tool
DMV Scam Analysis Project

This script creates comprehensive visualizations for cybersecurity threat analysis,
demonstrating data science skills and threat intelligence presentation capabilities.

Author: Cybersecurity Researcher
Purpose: Portfolio demonstration and threat analysis visualization
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.offline as pyo
import json
import argparse
import os

# Set style for professional visualizations
sns.set_style("whitegrid")
sns.set_palette("husl")

class ThreatVisualizationSuite:
    """
    Comprehensive threat analysis visualization toolkit
    """
    
    def __init__(self, output_dir="./visualizations"):
        """
        Initialize visualization suite
        
        Args:
            output_dir (str): Directory for saving visualizations
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Sample data for demonstration (sanitized)
        self.threat_data = self._generate_sample_data()
        
    def _generate_sample_data(self):
        """
        Generate sanitized sample data for visualization demonstration
        
        Returns:
            dict: Sample threat analysis data
        """
        # Timeline data
        dates = pd.date_range(start='2024-11-15', end='2024-11-22', freq='H')
        message_counts = np.random.poisson(lam=2, size=len(dates))
        message_counts[50:70] = np.random.poisson(lam=8, size=20)  # Spike during campaign
        
        # Risk scoring data
        risk_categories = ['Government Impersonation', 'Financial Threats', 
                          'Suspicious URLs', 'International Indicators']
        risk_scores = [85, 70, 60, 45]
        
        # Geographic data
        geographic_data = {
            'Pennsylvania': 45,
            'New Jersey': 8,
            'New York': 12,
            'Maryland': 6,
            'Ohio': 4,
            'Other': 25
        }
        
        # IOC detection timeline
        ioc_timeline = {
            'Phone Number Detection': datetime(2024, 11, 16, 14, 30),
            'Domain Analysis': datetime(2024, 11, 16, 18, 45),
            'Content Pattern ID': datetime(2024, 11, 17, 9, 15),
            'Attribution Complete': datetime(2024, 11, 17, 16, 20),
            'Domain Takedown': datetime(2024, 11, 18, 11, 30)
        }
        
        # Threat actor capabilities
        capabilities = {
            'Social Engineering': 9,
            'Technical Infrastructure': 7,
            'Geographic Targeting': 8,
            'Payment Processing': 6,
            'OPSEC': 3,
            'Language Quality': 8
        }
        
        return {
            'timeline_dates': dates,
            'message_counts': message_counts,
            'risk_categories': risk_categories,
            'risk_scores': risk_scores,
            'geographic_data': geographic_data,
            'ioc_timeline': ioc_timeline,
            'capabilities': capabilities
        }
    
    def create_threat_timeline(self):
        """
        Create comprehensive threat timeline visualization
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
        
        # Message frequency timeline
        ax1.plot(self.threat_data['timeline_dates'], 
                self.threat_data['message_counts'], 
                linewidth=2, color='#d62728', alpha=0.8)
        ax1.fill_between(self.threat_data['timeline_dates'], 
                        self.threat_data['message_counts'], 
                        alpha=0.3, color='#d62728')
        ax1.set_title('DMV Scam Campaign: Message Activity Timeline', 
                     fontsize=16, fontweight='bold', pad=20)
        ax1.set_xlabel('Date/Time', fontsize=12)
        ax1.set_ylabel('Messages per Hour', fontsize=12)
        ax1.grid(True, alpha=0.3)
        
        # Add campaign phases
        campaign_start = self.threat_data['timeline_dates'][50]
        campaign_end = self.threat_data['timeline_dates'][70]
        ax1.axvspan(campaign_start, campaign_end, alpha=0.2, color='red', 
                   label='Active Campaign Phase')
        ax1.legend()
        
        # IOC discovery timeline
        ioc_events = list(self.threat_data['ioc_timeline'].keys())
        ioc_times = list(self.threat_data['ioc_timeline'].values())
        
        # Convert to numerical values for plotting
        ioc_y_positions = range(len(ioc_events))
        
        ax2.scatter([t.hour + t.minute/60 for t in ioc_times], ioc_y_positions, 
                   s=100, c=['#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#17becf'], 
                   alpha=0.8)
        
        for i, (event, time) in enumerate(self.threat_data['ioc_timeline'].items()):
            ax2.annotate(f'{event}\n{time.strftime("%m/%d %H:%M")}', 
                        (time.hour + time.minute/60, i),
                        xytext=(10, 0), textcoords='offset points',
                        fontsize=10, ha='left')
        
        ax2.set_yticks(ioc_y_positions)
        ax2.set_yticklabels(ioc_events)
        ax2.set_title('Threat Intelligence Discovery Timeline', 
                     fontsize=16, fontweight='bold', pad=20)
        ax2.set_xlabel('Hours (24h format)', fontsize=12)
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/threat_timeline.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✓ Threat timeline saved: {self.output_dir}/threat_timeline.png")
    
    def create_risk_assessment_dashboard(self):
        """
        Create comprehensive risk assessment dashboard
        """
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Risk Category Scores', 'Geographic Distribution', 
                           'Threat Actor Capabilities', 'Risk Score Trend'],
            specs=[[{"type": "bar"}, {"type": "pie"}],
                   [{"type": "scatterpolar"}, {"type": "scatter"}]]
        )
        
        # Risk category bar chart
        fig.add_trace(
            go.Bar(x=self.threat_data['risk_categories'], 
                   y=self.threat_data['risk_scores'],
                   marker_color=['#d62728', '#ff7f0e', '#2ca02c', '#9467bd'],
                   name='Risk Scores'),
            row=1, col=1
        )
        
        # Geographic distribution pie chart
        fig.add_trace(
            go.Pie(labels=list(self.threat_data['geographic_data'].keys()),
                   values=list(self.threat_data['geographic_data'].values()),
                   name='Geographic Distribution'),
            row=1, col=2
        )
        
        # Threat actor capabilities radar chart
        capabilities = list(self.threat_data['capabilities'].keys())
        capability_scores = list(self.threat_data['capabilities'].values())
        
        fig.add_trace(
            go.Scatterpolar(r=capability_scores,
                           theta=capabilities,
                           fill='toself',
                           name='Threat Actor Profile'),
            row=2, col=1
        )
        
        # Risk trend over time (simulated)
        trend_dates = pd.date_range(start='2024-11-16', periods=7, freq='D')
        risk_trend = [25, 45, 70, 85, 90, 75, 60]  # Escalation then mitigation
        
        fig.add_trace(
            go.Scatter(x=trend_dates, y=risk_trend,
                      mode='lines+markers',
                      line=dict(color='#d62728', width=3),
                      name='Risk Level'),
            row=2, col=2
        )
        
        # Update layout
        fig.update_layout(
            title_text="DMV Scam Campaign: Comprehensive Risk Assessment Dashboard",
            title_x=0.5,
            height=800,
            showlegend=False
        )
        
        # Update y-axis for risk scores
        fig.update_yaxes(title_text="Risk Score (0-100)", row=1, col=1)
        fig.update_yaxes(title_text="Risk Level", range=[0, 100], row=2, col=2)
        
        # Save as HTML
        pyo.plot(fig, filename=f'{self.output_dir}/risk_dashboard.html', auto_open=False)
        
        print(f"✓ Risk dashboard saved: {self.output_dir}/risk_dashboard.html")
    
    def create_threat_intelligence_network(self):
        """
        Create network diagram showing threat infrastructure relationships
        """
        fig = go.Figure()
        
        # Define nodes (threat infrastructure components)
        nodes = {
            'Philippines Criminal Org': (0, 0),
            '+639127911810': (2, 1),
            'Globe Telecom': (4, 1),
            'pa.gov-jad.vip': (2, -1),
            'Premium Domain (.vip)': (4, -1),
            'Pennsylvania Targets': (-2, 0),
            'SMS Campaign': (0, 2),
            'Web Redirection': (0, -2)
        }
        
        # Define edges (relationships)
        edges = [
            ('Philippines Criminal Org', '+639127911810'),
            ('+639127911810', 'Globe Telecom'),
            ('Philippines Criminal Org', 'pa.gov-jad.vip'),
            ('pa.gov-jad.vip', 'Premium Domain (.vip)'),
            ('Philippines Criminal Org', 'SMS Campaign'),
            ('SMS Campaign', '+639127911810'),
            ('SMS Campaign', 'Pennsylvania Targets'),
            ('pa.gov-jad.vip', 'Web Redirection'),
            ('Web Redirection', 'Pennsylvania Targets')
        ]
        
        # Plot edges
        for edge in edges:
            x0, y0 = nodes[edge[0]]
            x1, y1 = nodes[edge[1]]
            fig.add_trace(go.Scatter(x=[x0, x1, None], y=[y0, y1, None],
                                   mode='lines',
                                   line=dict(color='gray', width=2),
                                   showlegend=False))
        
        # Plot nodes
        node_colors = {
            'Philippines Criminal Org': '#d62728',  # Red for threat actor
            '+639127911810': '#ff7f0e',             # Orange for phone
            'Globe Telecom': '#ffbb78',             # Light orange for carrier
            'pa.gov-jad.vip': '#d62728',            # Red for malicious domain
            'Premium Domain (.vip)': '#ffbb78',     # Light orange for infrastructure
            'Pennsylvania Targets': '#2ca02c',      # Green for victims
            'SMS Campaign': '#9467bd',              # Purple for attack vector
            'Web Redirection': '#9467bd'            # Purple for attack vector
        }
        
        for node, (x, y) in nodes.items():
            fig.add_trace(go.Scatter(x=[x], y=[y],
                                   mode='markers+text',
                                   marker=dict(size=20, color=node_colors[node]),
                                   text=node,
                                   textposition="middle center",
                                   textfont=dict(size=10, color='white'),
                                   name=node))
        
        fig.update_layout(
            title="DMV Scam Campaign: Threat Infrastructure Network",
            title_x=0.5,
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white',
            width=800,
            height=600
        )
        
        pyo.plot(fig, filename=f'{self.output_dir}/threat_network.html', auto_open=False)
        
        print(f"✓ Threat network diagram saved: {self.output_dir}/threat_network.html")
    
    def create_detection_analytics(self):
        """
        Create analytics showing detection effectiveness and patterns
        """
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # Detection accuracy metrics
        detection_methods = ['Phone Pattern', 'Domain Pattern', 'Content Analysis', 'Geographic Filter']
        true_positives = [95, 88, 92, 78]
        false_positives = [2, 8, 5, 12]
        
        x = np.arange(len(detection_methods))
        width = 0.35
        
        ax1.bar(x - width/2, true_positives, width, label='True Positives', color='#2ca02c', alpha=0.8)
        ax1.bar(x + width/2, false_positives, width, label='False Positives', color='#d62728', alpha=0.8)
        ax1.set_title('Detection Method Effectiveness', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Detection Method')
        ax1.set_ylabel('Percentage')
        ax1.set_xticks(x)
        ax1.set_xticklabels(detection_methods, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Pattern confidence scores
        patterns = ['DMV Keywords', 'Payment Urgency', 'Suspicious URLs', 'Int\'l Numbers']
        confidence_scores = [0.95, 0.87, 0.82, 0.91]
        
        colors = ['#d62728' if score < 0.85 else '#2ca02c' for score in confidence_scores]
        bars = ax2.bar(patterns, confidence_scores, color=colors, alpha=0.8)
        ax2.set_title('Pattern Confidence Scores', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Confidence Score')
        ax2.set_ylim(0, 1)
        ax2.tick_params(axis='x', rotation=45)
        
        # Add confidence threshold line
        ax2.axhline(y=0.85, color='orange', linestyle='--', alpha=0.7, label='Threshold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        # Analysis timeline efficiency
        analysis_stages = ['Data Collection', 'Pattern Analysis', 'Attribution', 'Reporting']
        time_taken = [0.5, 2.0, 1.5, 1.0]  # Hours
        automated_time = [0.1, 0.3, 0.8, 0.2]  # Hours with automation
        
        x = np.arange(len(analysis_stages))
        ax3.bar(x - width/2, time_taken, width, label='Manual Process', color='#ff7f0e', alpha=0.8)
        ax3.bar(x + width/2, automated_time, width, label='Automated Process', color='#2ca02c', alpha=0.8)
        ax3.set_title('Analysis Efficiency Comparison', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Analysis Stage')
        ax3.set_ylabel('Time (Hours)')
        ax3.set_xticks(x)
        ax3.set_xticklabels(analysis_stages, rotation=45, ha='right')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Risk score evolution
        hours = range(0, 48, 2)
        risk_evolution = [10, 15, 25, 35, 50, 65, 75, 85, 90, 85, 80, 75, 
                         70, 65, 60, 55, 50, 45, 40, 35, 30, 25, 20, 15]
        
        ax4.plot(hours, risk_evolution, linewidth=3, color='#d62728', marker='o', markersize=4)
        ax4.fill_between(hours, risk_evolution, alpha=0.3, color='#d62728')
        ax4.set_title('Risk Score Evolution During Investigation', fontsize=14, fontweight='bold')
        ax4.set_xlabel('Hours Since Detection')
        ax4.set_ylabel('Risk Score')
        ax4.grid(True, alpha=0.3)
        
        # Add risk level zones
        ax4.axhspan(0, 30, alpha=0.2, color='green', label='Low Risk')
        ax4.axhspan(30, 70, alpha=0.2, color='orange', label='Medium Risk')
        ax4.axhspan(70, 100, alpha=0.2, color='red', label='High Risk')
        ax4.legend(loc='upper right')
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/detection_analytics.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✓ Detection analytics saved: {self.output_dir}/detection_analytics.png")
    
    def create_executive_summary_visual(self):
        """
        Create executive-level visual summary
        """
        fig = make_subplots(
            rows=2, cols=3,
            subplot_titles=['Campaign Impact', 'Response Timeline', 'Threat Level',
                           'Geographic Reach', 'Detection Success', 'Mitigation Status'],
            specs=[[{"type": "indicator"}, {"type": "scatter"}, {"type": "indicator"}],
                   [{"type": "bar"}, {"type": "indicator"}, {"type": "indicator"}]]
        )
        
        # Campaign impact indicator
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=85,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Overall Risk Score"},
                delta={'reference': 50},
                gauge={'axis': {'range': [None, 100]},
                       'bar': {'color': "darkred"},
                       'steps': [{'range': [0, 50], 'color': "lightgray"},
                                {'range': [50, 80], 'color': "yellow"},
                                {'range': [80, 100], 'color': "red"}],
                       'threshold': {'line': {'color': "red", 'width': 4},
                                    'thickness': 0.75, 'value': 90}}
            ),
            row=1, col=1
        )
        
        # Response timeline
        response_dates = pd.date_range(start='2024-11-16', periods=5, freq='D')
        response_progress = [20, 45, 70, 90, 95]
        
        fig.add_trace(
            go.Scatter(x=response_dates, y=response_progress,
                      mode='lines+markers',
                      line=dict(color='blue', width=3),
                      name='Response Progress'),
            row=1, col=2
        )
        
        # Threat level indicator
        fig.add_trace(
            go.Indicator(
                mode="number+delta",
                value=75,
                title={"text": "Current Threat Level"},
                delta={'reference': 85, 'valueformat': '.0f'},
                number={'suffix': "%"}
            ),
            row=1, col=3
        )
        
        # Geographic reach
        states = ['PA', 'NJ', 'NY', 'MD', 'OH']
        affected = [45, 8, 12, 6, 4]
        
        fig.add_trace(
            go.Bar(x=states, y=affected,
                   marker_color='orange',
                   name='Affected Population %'),
            row=2, col=1
        )
        
        # Detection success rate
        fig.add_trace(
            go.Indicator(
                mode="gauge+number",
                value=92,
                title={'text': "Detection Accuracy"},
                gauge={'axis': {'range': [None, 100]},
                       'bar': {'color': "green"},
                       'steps': [{'range': [0, 70], 'color': "lightgray"},
                                {'range': [70, 90], 'color': "yellow"},
                                {'range': [90, 100], 'color': "green"}]}
            ),
            row=2, col=2
        )
        
        # Mitigation status
        fig.add_trace(
            go.Indicator(
                mode="number+delta",
                value=95,
                title={"text": "Mitigation Complete"},
                delta={'reference': 0, 'valueformat': '.0f'},
                number={'suffix': "%", 'valueformat': '.0f'}
            ),
            row=2, col=3
        )
        
        fig.update_layout(
            title_text="DMV Scam Campaign: Executive Dashboard",
            title_x=0.5,
            height=600
        )
        
        pyo.plot(fig, filename=f'{self.output_dir}/executive_dashboard.html', auto_open=False)
        
        print(f"✓ Executive dashboard saved: {self.output_dir}/executive_dashboard.html")
    
    def generate_all_visualizations(self):
        """
        Generate complete visualization suite
        """
        print("🎨 Generating comprehensive threat analysis visualizations...")
        print("=" * 60)
        
        self.create_threat_timeline()
        self.create_risk_assessment_dashboard()
        self.create_threat_intelligence_network()
        self.create_detection_analytics()
        self.create_executive_summary_visual()
        
        # Create visualization index
        self.create_visualization_index()
        
        print("=" * 60)
        print(f"✅ All visualizations generated successfully!")
        print(f"📁 Output directory: {self.output_dir}/")
        print(f"🌐 Open visualization_index.html to view all charts")
    
    def create_visualization_index(self):
        """
        Create HTML index page for all visualizations
        """
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>DMV Scam Analysis - Visualization Suite</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
                h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
                .viz-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
                .viz-card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; background: #fafafa; }
                .viz-card h3 { margin-top: 0; color: #2980b9; }
                .viz-card img { max-width: 100%; height: auto; border-radius: 5px; margin: 10px 0; }
                .button { background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px; }
                .button:hover { background-color: #2980b9; }
                .skills { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .skills h3 { margin-top: 0; }
                .skill-tag { background-color: #3498db; color: white; padding: 5px 10px; border-radius: 3px; margin: 2px; display: inline-block; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 DMV Scam Analysis: Comprehensive Visualization Suite</h1>
                
                <div class="skills">
                    <h3>📊 Technical Skills Demonstrated</h3>
                    <span class="skill-tag">Data Visualization</span>
                    <span class="skill-tag">Python Analytics</span>
                    <span class="skill-tag">Threat Intelligence</span>
                    <span class="skill-tag">Risk Assessment</span>
                    <span class="skill-tag">Interactive Dashboards</span>
                    <span class="skill-tag">Network Analysis</span>
                    <span class="skill-tag">Timeline Analysis</span>
                    <span class="skill-tag">Executive Reporting</span>
                </div>
                
                <h2>📈 Interactive Dashboards</h2>
                <div class="viz-grid">
                    <div class="viz-card">
                        <h3>Risk Assessment Dashboard</h3>
                        <p>Comprehensive multi-panel dashboard showing risk scores, geographic distribution, and threat actor capabilities.</p>
                        <a href="risk_dashboard.html" class="button">View Interactive Dashboard</a>
                    </div>
                    
                    <div class="viz-card">
                        <h3>Threat Network Diagram</h3>
                        <p>Interactive network visualization showing relationships between threat infrastructure components.</p>
                        <a href="threat_network.html" class="button">View Network Diagram</a>
                    </div>
                    
                    <div class="viz-card">
                        <h3>Executive Summary Dashboard</h3>
                        <p>High-level executive dashboard with key metrics, indicators, and status updates.</p>
                        <a href="executive_dashboard.html" class="button">View Executive Dashboard</a>
                    </div>
                </div>
                
                <h2>📊 Static Analysis Charts</h2>
                <div class="viz-grid">
                    <div class="viz-card">
                        <h3>Threat Timeline Analysis</h3>
                        <p>Message activity timeline and IOC discovery sequence showing campaign progression.</p>
                        <img src="threat_timeline.png" alt="Threat Timeline">
                        <br><a href="threat_timeline.png" class="button">View Full Size</a>
                    </div>
                    
                    <div class="viz-card">
                        <h3>Detection Analytics</h3>
                        <p>Comprehensive analysis of detection effectiveness, pattern confidence, and automation benefits.</p>
                        <img src="detection_analytics.png" alt="Detection Analytics">
                        <br><a href="detection_analytics.png" class="button">View Full Size</a>
                    </div>
                </div>
                
                <h2>🎯 Portfolio Value</h2>
                <p>This visualization suite demonstrates advanced cybersecurity data analysis capabilities including:</p>
                <ul>
                    <li><strong>Interactive Dashboards</strong> - Plotly-based dynamic visualizations</li>
                    <li><strong>Statistical Analysis</strong> - Risk scoring and pattern analysis</li>
                    <li><strong>Network Visualization</strong> - Threat infrastructure mapping</li>
                    <li><strong>Executive Reporting</strong> - Multi-audience data presentation</li>
                    <li><strong>Automation Metrics</strong> - Efficiency and accuracy measurements</li>
                </ul>
                
                <h2>🔧 Technical Implementation</h2>
                <p>Built using professional data science and cybersecurity tools:</p>
                <ul>
                    <li><strong>Python Libraries</strong>: Matplotlib, Seaborn, Plotly, Pandas, NumPy</li>
                    <li><strong>Visualization Types</strong>: Time series, network graphs, risk matrices, dashboards</li>
                    <li><strong>Export Formats</strong>: PNG (high-res), HTML (interactive), responsive design</li>
                    <li><strong>Data Sources</strong>: Sanitized threat intelligence, synthetic benchmarks</li>
                </ul>
                
                <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <p><em>Generated as part of cybersecurity portfolio demonstration</em></p>
                    <p><strong>GitHub Repository:</strong> <a href="https://github.com/DanteX86/dmv_scam_analysis">dmv_scam_analysis</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(f'{self.output_dir}/visualization_index.html', 'w') as f:
            f.write(html_content)
        
        print(f"✓ Visualization index saved: {self.output_dir}/visualization_index.html")

def main():
    """
    Main execution function
    """
    parser = argparse.ArgumentParser(description="Threat Analysis Visualization Suite")
    parser.add_argument("--output-dir", default="./visualizations", 
                       help="Output directory for visualizations")
    
    args = parser.parse_args()
    
    # Create visualization suite
    viz_suite = ThreatVisualizationSuite(output_dir=args.output_dir)
    
    try:
        viz_suite.generate_all_visualizations()
        
        print("\n🎯 Portfolio Enhancement Complete!")
        print("Visualizations demonstrate:")
        print("  • Advanced Python data analysis skills")
        print("  • Interactive dashboard development")
        print("  • Professional threat intelligence presentation")
        print("  • Multi-audience reporting capabilities")
        
    except Exception as e:
        print(f"❌ Visualization generation failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
