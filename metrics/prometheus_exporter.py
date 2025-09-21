# src/metrics/prometheus_exporter.py

from prometheus_client import Counter, Gauge, Histogram, push_to_gateway, CollectorRegistry
from prometheus_client.exposition import basic_auth_handler
from typing import Dict
import time
import logging
import re
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sanitize_label_value(value):
    """Sanitize label values for Prometheus compatibility"""
    if value is None:
        return "unknown"
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(value))
    # Ensure it doesn't start with a number
    if sanitized and sanitized[0].isdigit():
        sanitized = f"v_{sanitized}"
    return sanitized or "unknown"

class PrometheusExporter:
    """Export vulnerability scan metrics to Prometheus"""
    
    def __init__(self, pushgateway_url: str = None):
        self.pushgateway_url = pushgateway_url
    
    def export_scan_metrics(self, scan_results, scan_duration=None, job='container_scan', instance='github_actions'):
        # Create a new registry for this push
        registry = CollectorRegistry()
        
        # Extract and sanitize image info from scan results
        image = sanitize_label_value(scan_results.get('image', 'unknown'))
        tag = sanitize_label_value(scan_results.get('tag', 'latest'))
        scan_id = sanitize_label_value(scan_results.get('scan_id', str(int(time.time()))))
        
        # Ensure job and instance are sanitized
        job = sanitize_label_value(job)
        instance = sanitize_label_value(instance)
        
        # Combined image name for labels
        image_full = f"{image}_{tag}"  # Use underscore instead of colon
        
        # --- Define metrics with proper names ---
        
        # Total scans counter
        vulnerability_scans_total = Gauge(
            'vulnerability_scans_total',
            'Total number of vulnerability scans performed',
            ['image', 'status'],
            registry=registry
        )
        
        # Vulnerabilities by severity
        vulnerabilities_by_severity = Gauge(
            'vulnerabilities_by_severity',
            'Number of vulnerabilities by severity',
            ['image', 'severity'],
            registry=registry
        )
        
        # Total vulnerabilities
        total_vulnerabilities = Gauge(
            'total_vulnerabilities',
            'Total number of vulnerabilities in image',
            ['image'],
            registry=registry
        )
        
        # Critical vulnerabilities
        critical_vulnerabilities_total = Gauge(
            'critical_vulnerabilities_total',
            'Total number of critical vulnerabilities',
            ['image'],
            registry=registry
        )
        
        # High vulnerabilities
        high_vulnerabilities_total = Gauge(
            'high_vulnerabilities_total',
            'Total number of high severity vulnerabilities',
            ['image'],
            registry=registry
        )
        
        # Scan duration
        vulnerability_scan_duration_seconds = Gauge(
            'vulnerability_scan_duration_seconds',
            'Duration of vulnerability scan in seconds',
            ['image'],
            registry=registry
        )
        
        # Scan timestamp
        container_scan_timestamp = Gauge(
            'container_scan_timestamp',
            'Timestamp of the container scan',
            ['image', 'tag'],
            registry=registry
        )
        
        # Set metrics values
        
        # Set scan total
        vulnerability_scans_total.labels(
            image=image_full,
            status='completed'
        ).set(1)
        
        # Set vulnerabilities by severity and calculate total
        total_count = 0
        for severity in ['critical', 'high', 'medium', 'low']:
            count = scan_results.get(f'{severity}_count', 0)
            vulnerabilities_by_severity.labels(
                image=image_full,
                severity=severity
            ).set(count)
            total_count += count
        
        # Set total vulnerabilities
        total_vulnerabilities.labels(
            image=image_full
        ).set(total_count)
        
        # Set critical and high counts
        critical_vulnerabilities_total.labels(
            image=image_full
        ).set(scan_results.get('critical_count', 0))
        
        high_vulnerabilities_total.labels(
            image=image_full
        ).set(scan_results.get('high_count', 0))
        
        # Set scan duration if provided
        if scan_duration is not None:
            vulnerability_scan_duration_seconds.labels(
                image=image_full
            ).set(scan_duration)
        
        # Set timestamp
        container_scan_timestamp.labels(
            image=image,
            tag=tag
        ).set(time.time())
        
        # Push to gateway
        try:
            # Create grouping key with sanitized values
            grouping_key = {
                'instance': instance,
                'scan_id': scan_id
            }
            
            logger.info(f"Pushing metrics with job={job}, grouping_key={grouping_key}")
            
            push_to_gateway(
                self.pushgateway_url,
                job=job,
                registry=registry,
                grouping_key=grouping_key
            )
            
            logger.info(f"Metrics pushed successfully for {image}:{tag} (scan_id: {scan_id})")
        except Exception as e:
            logger.error(f"Error pushing metrics: {str(e)}")
            # Log more details for debugging
            logger.error(f"Pushgateway URL: {self.pushgateway_url}")
            logger.error(f"Job: {job}")
            logger.error(f"Grouping key: {grouping_key}")
            raise