# src/metrics/prometheus_exporter.py

from prometheus_client import Counter, Gauge, Histogram, push_to_gateway, CollectorRegistry
from typing import Dict
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PrometheusExporter:
    """Export vulnerability scan metrics to Prometheus"""
    
    def __init__(self, pushgateway_url: str = None):
        self.pushgateway_url = pushgateway_url
        self.registry = CollectorRegistry()
        
        # Define metrics
        self.scan_total = Counter(
            'vulnerability_scans_total',
            'Total number of vulnerability scans performed',
            ['image', 'status'],
            registry=self.registry
        )
        
        self.vulnerabilities_by_severity = Gauge(
            'vulnerabilities_by_severity',
            'Number of vulnerabilities by severity',
            ['image', 'severity'],
            registry=self.registry
        )
        
        self.total_vulnerabilities = Gauge(
            'total_vulnerabilities',
            'Total number of vulnerabilities in image',
            ['image'],
            registry=self.registry
        )
        
        self.scan_duration = Histogram(
            'vulnerability_scan_duration_seconds',
            'Duration of vulnerability scan in seconds',
            ['image'],
            registry=self.registry
        )
        
        self.critical_vulnerabilities = Gauge(
            'critical_vulnerabilities_total',
            'Total number of critical vulnerabilities',
            ['image'],
            registry=self.registry
        )
        
        self.high_vulnerabilities = Gauge(
            'high_vulnerabilities_total',
            'Total number of high severity vulnerabilities',
            ['image'],
            registry=self.registry
        )
    
    def export_scan_metrics(self, scan_results, scan_duration=None, job='container_scan', instance='github_actions'):
        # Create a new registry for this push
        registry = CollectorRegistry()
        
        # Create metrics with additional labels
        scan_timestamp = Gauge(
            'container_scan_timestamp',
            'Timestamp of the container scan',
            ['job', 'instance', 'image', 'tag'],
            registry=registry
        )
        
        vulnerabilities_total = Gauge(
            'container_vulnerabilities_total',
            'Total number of vulnerabilities found',
            ['job', 'instance', 'image', 'tag', 'severity'],
            registry=registry
        )
        
        scan_duration_metric = Gauge(
            'container_scan_duration_seconds',
            'Duration of the container scan in seconds',
            ['job', 'instance', 'image', 'tag'],
            registry=registry
        )
        
        # Extract image info from scan results
        image = scan_results.get('image', 'unknown')
        tag = scan_results.get('tag', 'latest')
        
        # Set timestamp
        scan_timestamp.labels(
            job=job,
            instance=instance,
            image=image,
            tag=tag
        ).set(time.time())
        
        # Set vulnerability metrics
        for severity in ['critical', 'high', 'medium', 'low']:
            count = scan_results.get(f'{severity}_count', 0)
            vulnerabilities_total.labels(
                job=job,
                instance=instance,
                image=image,
                tag=tag,
                severity=severity
            ).set(count)
        
        # Set scan duration if provided
        if scan_duration:
            scan_duration_metric.labels(
                job=job,
                instance=instance,
                image=image,
                tag=tag
            ).set(scan_duration)
        
        # Push to gateway with grouping keys
        push_to_gateway(
            self.pushgateway_url,
            job=job,
            registry=registry,
            grouping_key={'instance': instance}
        )
    
    def push_metrics(self):
        """Push metrics to Prometheus Pushgateway"""
        
        try:
            push_to_gateway(
                self.pushgateway_url,
                job='vulnerability_scanner',
                registry=self.registry
            )
            logger.info("Metrics pushed to Prometheus Pushgateway")
        except Exception as e:
            logger.error(f"Error pushing metrics: {str(e)}")
            raise