import argparse
import json
from pathlib import Path
import sys
from datetime import datetime, timezone
import uuid
import re

sys.path.append(str(Path(__file__).parent.parent))

from metrics.prometheus_exporter import PrometheusExporter

def sanitize_label_value(value):
    """Sanitize label values for Prometheus compatibility"""
    # Replace invalid characters with underscores
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', str(value))

def main():
    parser = argparse.ArgumentParser(description='Push metrics to Prometheus')
    parser.add_argument('--scan-results', required=True, help='Scan results file')
    parser.add_argument('--pushgateway', required=True, help='Prometheus Pushgateway URL')
    parser.add_argument('--scan-duration', type=float, help='Scan duration in seconds')
    parser.add_argument('--job', default='container_scan', help='Job name for metrics')
    parser.add_argument('--instance', default='github_actions', help='Instance name')
    parser.add_argument('--run-id', help='Unique run identifier (e.g., GitHub run ID)')
    
    args = parser.parse_args()
    
    # Load scan results
    with open(args.scan_results, 'r') as f:
        scan_results = json.load(f)
    
    # Create unique scan ID - use timezone-aware datetime
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    # Generate a unique scan_id (sanitized for Prometheus)
    if args.run_id:
        scan_id = sanitize_label_value(f"{args.run_id}_{timestamp}")
    else:
        scan_id = f"{timestamp}_{uuid.uuid4().hex[:8]}"
    
    # Add scan_id to results
    scan_results['scan_id'] = scan_id
    
    # Use run_id if provided for instance name (sanitized)
    if args.run_id:
        unique_instance = sanitize_label_value(f"{args.instance}_{args.run_id}")
    else:
        unique_instance = f"{args.instance}_{timestamp}"
    
    # Export metrics
    exporter = PrometheusExporter(args.pushgateway)
    exporter.export_scan_metrics(
        scan_results, 
        args.scan_duration,
        job=sanitize_label_value(args.job),
        instance=unique_instance
    )
    
    print(f"✅ Metrics pushed to Prometheus successfully")
    print(f"   Instance: {unique_instance}")
    print(f"   Scan ID: {scan_id}")

if __name__ == '__main__':
    main()