# src/notifications/slack_notifier.py

import json
from typing import Dict, List
from slack_sdk.webhook import WebhookClient
from slack_sdk.errors import SlackApiError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SlackNotifier:
    """Send vulnerability scan notifications to Slack"""
    
    def __init__(self, webhook_url: str):
        self.webhook_client = WebhookClient(webhook_url)
    
    def send_scan_summary(self, scan_results: Dict, threshold_results: Dict = None):
        """Send scan summary to Slack"""
        
        blocks = self._create_summary_blocks(scan_results, threshold_results)
        
        try:
            response = self.webhook_client.send(
                text="Vulnerability Scan Completed",
                blocks=blocks
            )
            logger.info(f"Slack notification sent: {response.status_code}")
            return response
        except SlackApiError as e:
            logger.error(f"Error sending Slack notification: {e}")
            raise
    
    def send_critical_alert(self, scan_results: Dict, critical_vulns: List[Dict]):
        """Send critical vulnerability alert"""
        
        blocks = self._create_critical_alert_blocks(scan_results, critical_vulns)
        
        try:
            response = self.webhook_client.send(
                text="🚨 Critical Vulnerabilities Detected!",
                blocks=blocks
            )
            logger.info(f"Critical alert sent: {response.status_code}")
            return response
        except SlackApiError as e:
            logger.error(f"Error sending critical alert: {e}")
            raise
    
    def _create_summary_blocks(self, scan_results: Dict, threshold_results: Dict) -> List[Dict]:
        """Create Slack blocks for scan summary"""
        
        # Determine overall status
        if scan_results['severity_summary'].get('CRITICAL', 0) > 0:
            status_emoji = "🔴"
            status_text = "Critical Issues Found"
        elif scan_results['severity_summary'].get('HIGH', 0) > 0:
            status_emoji = "🟠"
            status_text = "High Issues Found"
        elif scan_results['total_vulnerabilities'] > 0:
            status_emoji = "🟡"
            status_text = "Issues Found"
        else:
            status_emoji = "✅"
            status_text = "No Issues Found"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Vulnerability Scan Report"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Image:*\n`{scan_results['image']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status_text}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Vulnerabilities:*\n{scan_results['total_vulnerabilities']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Scan Time:*\n{scan_results['scan_timestamp']}"
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Severity Breakdown:*"
                }
            }
        ]
        
        # Add severity counts
        severity_text = []
        for severity, count in scan_results['severity_summary'].items():
            emoji = self._get_severity_emoji(severity)
            severity_text.append(f"{emoji} {severity}: {count}")
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(severity_text)
            }
        })
        
        # Add threshold check results if available
        if threshold_results:
            if not threshold_results['passed']:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "⚠️ *Threshold Violations:*"
                    }
                })
                
                for violation in threshold_results['violations']:
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"• {violation['severity']}: {violation['count']} "
                                   f"(max: {violation['max_allowed']})"
                        }
                    })
        
        # Add action buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View in Grafana"
                    },
                    "url": "http://13.233.130.69:3000/dashboards"
                }
            ]
        })
        
        return blocks
    
    def _create_critical_alert_blocks(self, scan_results: Dict, critical_vulns: List[Dict]) -> List[Dict]:
        """Create Slack blocks for critical alerts"""
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Critical Security Alert"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Critical vulnerabilities detected in:*\n`{scan_results['image']}`"
                }
            },
            {
                "type": "divider"
            }
        ]
        
        # Add top critical vulnerabilities
        for vuln in critical_vulns[:5]:  # Show top 5
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*CVE:*\n{vuln['id']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Package:*\n{vuln['package']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{vuln['severity']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Fixed Version:*\n{vuln['fixed_version']}"
                    }
                ]
            })
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "⚠️ *Immediate action required!* Please review and patch these vulnerabilities."
            }
        })
        
        return blocks
    
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