import argparse
import json
from pathlib import Path
import sys
from datetime import datetime
import hashlib

sys.path.append(str(Path(__file__).parent.parent))

from metrics.prometheus_exporter import PrometheusExporter

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
    
    # Create unique instance identifier
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    # Use run_id if provided (e.g., from GitHub Actions), otherwise use timestamp
    if args.run_id:
        unique_instance = f"{args.instance}_{args.run_id}"
    else:
        unique_instance = f"{args.instance}_{timestamp}"
    
    # Export metrics with unique instance
    exporter = PrometheusExporter(args.pushgateway)
    
    # You'll need to modify your exporter to accept job and instance parameters
    exporter.export_scan_metrics(
        scan_results, 
        args.scan_duration,
        job=args.job,
        instance=unique_instance
    )
    
    print(f"✅ Metrics pushed to Prometheus successfully (instance: {unique_instance})")

if __name__ == '__main__':
    main()