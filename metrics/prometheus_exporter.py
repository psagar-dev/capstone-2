# src/metrics/prometheus_exporter.py

from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
from typing import Dict
import time
import logging
import re
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PrometheusExporter:
    """Export vulnerability scan metrics to Prometheus"""
    
    def __init__(self, pushgateway_url: str = None):
        # Clean up the URL - ensure it doesn't have trailing slashes or paths
        if pushgateway_url:
            # Remove any trailing slashes
            self.pushgateway_url = pushgateway_url.rstrip('/')
            # If it includes /metrics, remove it
            if self.pushgateway_url.endswith('/metrics'):
                self.pushgateway_url = self.pushgateway_url[:-8]
        else:
            self.pushgateway_url = pushgateway_url
    
    def export_scan_metrics(self, scan_results, scan_duration=None, job='container_scan', instance='github_actions'):
        # Create a new registry for this push
        registry = CollectorRegistry()
        
        # Extract image info - keep it simple
        image = scan_results.get('image', 'unknown')
        tag = scan_results.get('tag', 'latest')
        
        # Sanitize image name for use in labels (replace problematic characters)
        image_safe = re.sub(r'[^a-zA-Z0-9_]', '_', image)
        tag_safe = re.sub(r'[^a-zA-Z0-9_]', '_', tag)
        
        # Create simple metrics without complex labels
        
        # Total vulnerabilities by severity
        vuln_critical = Gauge(
            'container_vulnerabilities_critical',
            'Number of critical vulnerabilities',
            ['image', 'tag'],
            registry=registry
        )
        
        vuln_high = Gauge(
            'container_vulnerabilities_high',
            'Number of high vulnerabilities',
            ['image', 'tag'],
            registry=registry
        )
        
        vuln_medium = Gauge(
            'container_vulnerabilities_medium',
            'Number of medium vulnerabilities',
            ['image', 'tag'],
            registry=registry
        )
        
        vuln_low = Gauge(
            'container_vulnerabilities_low',
            'Number of low vulnerabilities',
            ['image', 'tag'],
            registry=registry
        )
        
        vuln_total = Gauge(
            'container_vulnerabilities_total',
            'Total number of vulnerabilities',
            ['image', 'tag'],
            registry=registry
        )
        
        scan_timestamp = Gauge(
            'container_scan_last_timestamp',
            'Timestamp of last scan',
            ['image', 'tag'],
            registry=registry
        )
        
        # Set the metric values
        critical_count = scan_results.get('critical_count', 0)
        high_count = scan_results.get('high_count', 0)
        medium_count = scan_results.get('medium_count', 0)
        low_count = scan_results.get('low_count', 0)
        total_count = critical_count + high_count + medium_count + low_count
        
        vuln_critical.labels(image=image_safe, tag=tag_safe).set(critical_count)
        vuln_high.labels(image=image_safe, tag=tag_safe).set(high_count)
        vuln_medium.labels(image=image_safe, tag=tag_safe).set(medium_count)
        vuln_low.labels(image=image_safe, tag=tag_safe).set(low_count)
        vuln_total.labels(image=image_safe, tag=tag_safe).set(total_count)
        scan_timestamp.labels(image=image_safe, tag=tag_safe).set(time.time())
        
        # If scan duration is provided
        if scan_duration is not None:
            scan_duration_metric = Gauge(
                'container_scan_duration_seconds',
                'Scan duration in seconds',
                ['image', 'tag'],
                registry=registry
            )
            scan_duration_metric.labels(image=image_safe, tag=tag_safe).set(scan_duration)
        
        # Push to gateway - use simple approach
        try:
            # Log what we're about to push
            logger.info(f"Pushing metrics to: {self.pushgateway_url}")
            logger.info(f"Job: {job}, Instance: {instance}")
            logger.info(f"Image: {image_safe}, Tag: {tag_safe}")
            logger.info(f"Vulnerabilities - Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}")
            
            # Simple push without complex grouping
            push_to_gateway(
                gateway=self.pushgateway_url,
                job=job,
                registry=registry,
                grouping_key={'instance': instance}  # Just use simple instance
            )
            
            logger.info(f"✅ Metrics pushed successfully")
            
        except Exception as e:
            logger.error(f"❌ Error pushing metrics: {str(e)}")
            # Try alternative push without grouping_key
            try:
                logger.info("Trying alternative push without grouping_key...")
                push_to_gateway(
                    gateway=self.pushgateway_url,
                    job=f"{job}/{instance}",  # Include instance in job name
                    registry=registry
                )
                logger.info(f"✅ Metrics pushed successfully (alternative method)")
            except Exception as e2:
                logger.error(f"❌ Alternative push also failed: {str(e2)}")
                raise