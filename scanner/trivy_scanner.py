# src/scanner/trivy_scanner.py

import json
import subprocess
import logging
from typing import Dict, List, Optional
from datetime import datetime
import docker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrivyScanner:
    """
    Trivy vulnerability scanner wrapper for container images
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.docker_client = docker.from_env()
        self.severity_levels = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
    def scan_image(self, image_name: str, tag: str = 'latest') -> Dict:
        """
        Scan a container image for vulnerabilities
        
        Args:
            image_name: Name of the container image
            tag: Image tag (default: latest)
            
        Returns:
            Dictionary containing scan results
        """
        full_image = f"{image_name}:{tag}"
        logger.info(f"Starting vulnerability scan for {full_image}")
        
        try:
            # Pull the image if not present
            self._pull_image(full_image)
            
            # Run Trivy scan
            scan_result = self._run_trivy_scan(full_image)
            
            # Parse and enhance results
            enhanced_result = self._enhance_scan_result(scan_result, full_image)
            
            logger.info(f"Scan completed for {full_image}")
            return enhanced_result
            
        except Exception as e:
            logger.error(f"Error scanning {full_image}: {str(e)}")
            raise
    
    def _pull_image(self, image_name: str):
        """Pull Docker image if not present locally"""
        try:
            self.docker_client.images.get(image_name)
            logger.info(f"Image {image_name} already exists locally")
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image {image_name}")
            self.docker_client.images.pull(image_name)
    
    def _run_trivy_scan(self, image_name: str) -> Dict:
        """Execute Trivy scan command"""
        cmd = [
            'trivy', 'image',
            '--format', 'json',
            '--severity', ','.join(self.config.get('severity_levels', self.severity_levels)),
            '--quiet',
            image_name
        ]
        
        # Add custom config if provided
        if self.config.get('ignore_unfixed'):
            cmd.append('--ignore-unfixed')
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Trivy scan failed: {result.stderr}")
        
        return json.loads(result.stdout)
    
    def _enhance_scan_result(self, scan_result: Dict, image_name: str) -> Dict:
        """Enhance scan results with additional metadata"""
        
        # Count vulnerabilities by severity
        severity_counts = self._count_vulnerabilities_by_severity(scan_result)
        
        # Extract CVE list
        cve_list = self._extract_cve_list(scan_result)
        
        enhanced_result = {
            'image': image_name,
            'scan_timestamp': datetime.now().isoformat(),
            'scanner': 'trivy',
            'scanner_version': self._get_trivy_version(),
            'severity_summary': severity_counts,
            'total_vulnerabilities': sum(severity_counts.values()),
            'cve_list': cve_list,
            'raw_result': scan_result,
            'scan_status': 'completed'
        }
        
        return enhanced_result
    
    def _count_vulnerabilities_by_severity(self, scan_result: Dict) -> Dict:
        """Count vulnerabilities by severity level"""
        counts = {level: 0 for level in self.severity_levels}
        
        for result in scan_result.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'UNKNOWN')
                if severity in counts:
                    counts[severity] += 1
        
        return counts
    
    def _extract_cve_list(self, scan_result: Dict) -> List[Dict]:
        """Extract list of CVEs from scan result"""
        cve_list = []
        
        for result in scan_result.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                cve_info = {
                    'id': vuln.get('VulnerabilityID'),
                    'package': vuln.get('PkgName'),
                    'version': vuln.get('InstalledVersion'),
                    'fixed_version': vuln.get('FixedVersion', 'Not Fixed'),
                    'severity': vuln.get('Severity'),
                    'title': vuln.get('Title', ''),
                    'description': vuln.get('Description', '')[:200] + '...' if vuln.get('Description', '') else ''
                }
                cve_list.append(cve_info)
        
        return cve_list
    
    def _get_trivy_version(self) -> str:
        """Get Trivy version"""
        try:
            result = subprocess.run(['trivy', '--version'], capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return 'unknown'