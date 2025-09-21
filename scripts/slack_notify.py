import argparse
import json
import os
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from notifications.slack_notifier import SlackNotifier

def main():
    parser = argparse.ArgumentParser(description='Send Slack notification')
    parser.add_argument('--scan-results', required=True, help='Scan results file')
    parser.add_argument('--webhook-url', required=True, help='Slack webhook URL')
    parser.add_argument('--threshold-results', help='Threshold check results file')
    parser.add_argument('--status', default='success', help='Build status')
    
    args = parser.parse_args()
    
    # Load scan results
    with open(args.scan_results, 'r') as f:
        scan_results = json.load(f)
    
    # Load threshold results if available
    threshold_results = None
    if args.threshold_results and os.path.exists(args.threshold_results):
        with open(args.threshold_results, 'r') as f:
            threshold_results = json.load(f)
    
    # Send notification
    notifier = SlackNotifier(args.webhook_url)
    
    # Send summary
    notifier.send_scan_summary(scan_results, threshold_results)
    
    # Send critical alert if needed
    critical_vulns = [v for v in scan_results.get('cve_list', []) 
                     if v['severity'] == 'CRITICAL']
    
    if critical_vulns:
        notifier.send_critical_alert(scan_results, critical_vulns)
    
    print("✅ Slack notification sent successfully")

if __name__ == '__main__':
    main()