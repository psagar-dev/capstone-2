# src/metrics/prometheus_exporter.py

from prometheus_client import Counter, Gauge, Histogram, push_to_gateway, CollectorRegistry, REGISTRY
from typing import Dict
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PrometheusExporter:
    """Export vulnerability scan metrics to Prometheus"""
    
    def __init__(self, pushgateway_url: str = None):
        self.pushgateway_url = pushgateway_url
    
    def export_scan_metrics(self, scan_results, scan_duration=None, job='container_scan', instance='github_actions'):
        # Create a new registry for this push
        registry = CollectorRegistry()
        
        # Extract image info from scan results
        image = scan_results.get('image', 'unknown')
        tag = scan_results.get('tag', 'latest')
        scan_id = scan_results.get('scan_id', str(int(time.time())))
        
        # --- Match the dashboard metric names ---
        
        # Total scans counter (cumulative)
        vulnerability_scans_total = Gauge(
            'vulnerability_scans_total',
            'Total number of vulnerability scans performed',
            ['image', 'status', 'instance', 'scan_id'],
            registry=registry
        )
        
        # Vulnerabilities by severity (what dashboard expects)
        vulnerabilities_by_severity = Gauge(
            'vulnerabilities_by_severity',
            'Number of vulnerabilities by severity',
            ['image', 'severity', 'instance', 'scan_id'],
            registry=registry
        )
        
        # Total vulnerabilities
        total_vulnerabilities = Gauge(
            'total_vulnerabilities',
            'Total number of vulnerabilities in image',
            ['image', 'instance', 'scan_id'],
            registry=registry
        )
        
        # Critical vulnerabilities (for gauge panel)
        critical_vulnerabilities_total = Gauge(
            'critical_vulnerabilities_total',
            'Total number of critical vulnerabilities',
            ['image', 'instance', 'scan_id'],
            registry=registry
        )
        
        # High vulnerabilities
        high_vulnerabilities_total = Gauge(
            'high_vulnerabilities_total',
            'Total number of high severity vulnerabilities',
            ['image', 'instance', 'scan_id'],
            registry=registry
        )
        
        # Scan duration
        vulnerability_scan_duration_seconds = Gauge(
            'vulnerability_scan_duration_seconds',
            'Duration of vulnerability scan in seconds',
            ['image', 'instance', 'scan_id'],
            registry=registry
        )
        
        # Scan timestamp
        container_scan_timestamp = Gauge(
            'container_scan_timestamp',
            'Timestamp of the container scan',
            ['image', 'tag', 'instance', 'scan_id'],
            registry=registry
        )
        
        # Set scan total (always 1 for each scan)
        vulnerability_scans_total.labels(
            image=f"{image}:{tag}",
            status='completed',
            instance=instance,
            scan_id=scan_id
        ).set(1)
        
        # Set vulnerabilities by severity
        total_count = 0
        for severity in ['critical', 'high', 'medium', 'low']:
            count = scan_results.get(f'{severity}_count', 0)
            vulnerabilities_by_severity.labels(
                image=f"{image}:{tag}",
                severity=severity,
                instance=instance,
                scan_id=scan_id
            ).set(count)
            total_count += count
        
        # Set total vulnerabilities
        total_vulnerabilities.labels(
            image=f"{image}:{tag}",
            instance=instance,
            scan_id=scan_id
        ).set(total_count)
        
        # Set critical and high counts specifically
        critical_vulnerabilities_total.labels(
            image=f"{image}:{tag}",
            instance=instance,
            scan_id=scan_id
        ).set(scan_results.get('critical_count', 0))
        
        high_vulnerabilities_total.labels(
            image=f"{image}:{tag}",
            instance=instance,
            scan_id=scan_id
        ).set(scan_results.get('high_count', 0))
        
        # Set scan duration if provided
        if scan_duration:
            vulnerability_scan_duration_seconds.labels(
                image=f"{image}:{tag}",
                instance=instance,
                scan_id=scan_id
            ).set(scan_duration)
        
        # Set timestamp
        container_scan_timestamp.labels(
            image=image,
            tag=tag,
            instance=instance,
            scan_id=scan_id
        ).set(time.time())
        
        # Push to gateway - use scan_id in grouping to prevent overwriting
        try:
            push_to_gateway(
                self.pushgateway_url,
                job=job,
                registry=registry,
                grouping_key={
                    'instance': instance,
                    'scan_id': scan_id  # This ensures each scan is unique
                }
            )
            logger.info(f"Metrics pushed successfully for {image}:{tag} (scan_id: {scan_id})")
        except Exception as e:
            logger.error(f"Error pushing metrics: {str(e)}")
            raise