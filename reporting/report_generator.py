import json
from datetime import datetime
from jinja2 import Template
import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
from typing import Dict, List
import base64

class ReportGenerator:
    """Generate vulnerability scan reports in various formats"""
    
    def __init__(self):
        self.html_template = self._load_html_template()
        self.markdown_template = self._load_markdown_template()
    
    def generate_html(self, scan_results: Dict) -> str:
        """Generate HTML report with charts"""
        
        # Create severity chart
        severity_chart = self._create_severity_chart(scan_results['severity_summary'])
        
        # Create vulnerability table
        vuln_table = self._create_vulnerability_table(scan_results['cve_list'])
        
        # Render template
        template = Template(self.html_template)
        html_report = template.render(
            scan_results=scan_results,
            severity_chart=severity_chart,
            vuln_table=vuln_table,
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        return html_report
    
    def generate_markdown(self, scan_results: Dict) -> str:
        """Generate Markdown report"""
        template = Template(self.markdown_template)
        
        # Create vulnerability summary
        vuln_summary = self._create_vulnerability_summary(scan_results)
        
        return template.render(
            scan_results=scan_results,
            vuln_summary=vuln_summary,
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    def generate_pdf(self, scan_results: Dict, output_path: str):
        """Generate PDF report"""
        import pdfkit
        
        html_report = self.generate_html(scan_results)
        pdfkit.from_string(html_report, output_path)
    
    def _create_severity_chart(self, severity_summary: Dict) -> str:
        """Create severity distribution chart"""
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(severity_summary.keys()),
                y=list(severity_summary.values()),
                marker_color=['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']
            )
        ])
        
        fig.update_layout(
            title='Vulnerability Severity Distribution',
            xaxis_title='Severity',
            yaxis_title='Count',
            showlegend=False
        )
        
        return pio.to_html(fig, include_plotlyjs='cdn', div_id="severity-chart")
    
    def _create_vulnerability_table(self, cve_list: List[Dict]) -> str:
        """Create HTML table of vulnerabilities"""
        
        if not cve_list:
            return "<p>No vulnerabilities found</p>"
        
        df = pd.DataFrame(cve_list)
        
        # Style the dataframe
        def severity_color(val):
            colors = {
                'CRITICAL': 'background-color: #dc3545; color: white;',
                'HIGH': 'background-color: #fd7e14; color: white;',
                'MEDIUM': 'background-color: #ffc107;',
                'LOW': 'background-color: #28a745; color: white;',
                'UNKNOWN': 'background-color: #6c757d; color: white;'
            }
            return colors.get(val, '')
        
        styled_df = df.style.applymap(
            severity_color, 
            subset=['severity']
        )
        
        return styled_df.to_html(index=False, escape=False)
    
    def _create_vulnerability_summary(self, scan_results: Dict) -> str:
        """Create text summary of vulnerabilities"""
        
        summary = []
        summary.append(f"**Total Vulnerabilities:** {scan_results['total_vulnerabilities']}")
        summary.append("\n**Severity Breakdown:**")
        
        for severity, count in scan_results['severity_summary'].items():
            emoji = self._get_severity_emoji(severity)
            summary.append(f"- {emoji} {severity}: {count}")
        
        if scan_results['cve_list']:
            summary.append("\n**Top 5 Critical/High Vulnerabilities:**")
            critical_high = [v for v in scan_results['cve_list'] 
                           if v['severity'] in ['CRITICAL', 'HIGH']][:5]
            
            for vuln in critical_high:
                summary.append(f"- **{vuln['id']}** in {vuln['package']} "
                             f"(Severity: {vuln['severity']})")
        
        return '\n'.join(summary)
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }
        return emojis.get(severity, '⚪')
    
    def _load_html_template(self) -> str:
        """Load HTML report template"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <h1>Container Vulnerability Scan Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Image:</strong> {{ scan_results.image }}</p>
        <p><strong>Scan Date:</strong> {{ scan_date }}</p>
        <p><strong>Total Vulnerabilities:</strong> {{ scan_results.total_vulnerabilities }}</p>
    </div>
    
    <div id="severity-chart">
        {{ severity_chart|safe }}
    </div>
    
    <h2>Vulnerability Details</h2>
    {{ vuln_table|safe }}
    
    <footer>
        <p>Generated by Container Vulnerability Scanner</p>
    </footer>
</body>
</html>
        '''
    
    def _load_markdown_template(self) -> str:
        """Load Markdown report template"""
        return '''
# Container Vulnerability Scan Report

## Scan Information
- **Image:** {{ scan_results.image }}
- **Scan Date:** {{ scan_date }}
- **Scanner:** {{ scan_results.scanner }}

## Summary
{{ vuln_summary }}

## Recommendations
{% if scan_results.severity_summary.CRITICAL > 0 %}
⚠️ **Critical vulnerabilities detected!** Immediate action required.
{% endif %}

{% if scan_results.severity_summary.HIGH > 5 %}
⚠️ **High number of HIGH severity vulnerabilities.** Please review and patch.
{% endif %}

---
*Generated by Container Vulnerability Scanner*
        '''