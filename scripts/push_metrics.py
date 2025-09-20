import argparse
import json
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from metrics.prometheus_exporter import PrometheusExporter

def main():
    parser = argparse.ArgumentParser(description='Push metrics to Prometheus')
    parser.add_argument('--scan-results', required=True, help='Scan results file')
    parser.add_argument('--pushgateway', required=True, help='Prometheus Pushgateway URL')
    parser.add_argument('--scan-duration', type=float, help='Scan duration in seconds')
    
    args = parser.parse_args()
    
    # Load scan results
    with open(args.scan_results, 'r') as f:
        scan_results = json.load(f)
    
    # Export metrics
    exporter = PrometheusExporter(args.pushgateway)
    exporter.export_scan_metrics(scan_results, args.scan_duration)
    
    print("✅ Metrics pushed to Prometheus successfully")

if __name__ == '__main__':
    main()