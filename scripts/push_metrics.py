import argparse
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

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
    
    # Create a simple, unique instance name
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    
    if args.run_id:
        # Use GitHub run ID if available
        instance_name = f"gh_{args.run_id}"
    else:
        # Use timestamp as fallback
        instance_name = f"scan_{timestamp}"
    
    # Export metrics
    exporter = PrometheusExporter(args.pushgateway)
    exporter.export_scan_metrics(
        scan_results, 
        args.scan_duration,
        job=args.job,
        instance=instance_name
    )
    
    
    print(f"✅ Metrics pushed to Prometheus successfully")
    print(f"   Instance: {instance_name}")

if __name__ == '__main__':
    main()