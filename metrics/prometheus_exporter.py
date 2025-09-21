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
    
    def export_scan_metrics(self, scan_results: Dict, scan_duration: float = None):
        """Export scan metrics to Prometheus"""
        
        image = scan_results['image']
        
        # Update scan counter
        self.scan_total.labels(
            image=image,
            status=scan_results.get('scan_status', 'completed')
        ).inc()
        
        # Update vulnerability counts by severity
        for severity, count in scan_results['severity_summary'].items():
            self.vulnerabilities_by_severity.labels(
                image=image,
                severity=severity
            ).set(count)
        
        # Update total vulnerabilities
        self.total_vulnerabilities.labels(image=image).set(
            scan_results['total_vulnerabilities']
        )
        
        # Update critical and high severity metrics
        self.critical_vulnerabilities.labels(image=image).set(
            scan_results['severity_summary'].get('CRITICAL', 0)
        )
        
        self.high_vulnerabilities.labels(image=image).set(
            scan_results['severity_summary'].get('HIGH', 0)
        )
        
        # Update scan duration if provided
        if scan_duration:
            self.scan_duration.labels(image=image).observe(scan_duration)
        
        # Push to gateway if configured
        if self.pushgateway_url:
            self.push_metrics()
        
        logger.info(f"Metrics exported for {image}")
    
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