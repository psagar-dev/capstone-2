import json
import yaml
from typing import Dict, List, Set
from datetime import datetime, timedelta
import hashlib

class ExceptionManager:
    """Manage vulnerability exceptions and whitelisting"""
    
    def __init__(self, exception_file: str = 'config/exceptions.yaml'):
        self.exception_file = exception_file
        self.exceptions = self._load_exceptions()
    
    def _load_exceptions(self) -> Dict:
        """Load exceptions from configuration file"""
        try:
            with open(self.exception_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {'global': [], 'image_specific': {}}
    
    def save_exceptions(self):
        """Save exceptions to configuration file"""
        with open(self.exception_file, 'w') as f:
            yaml.dump(self.exceptions, f, default_flow_style=False)
    
    def add_exception(self, cve_id: str, reason: str, expiry_days: int = 30, 
                     image: str = None, approved_by: str = None):
        """Add a vulnerability exception"""
        
        exception = {
            'cve_id': cve_id,
            'reason': reason,
            'added_date': datetime.now().isoformat(),
            'expiry_date': (datetime.now() + timedelta(days=expiry_days)).isoformat(),
            'approved_by': approved_by,
            'hash': hashlib.sha256(f"{cve_id}{reason}".encode()).hexdigest()[:8]
        }
        
        if image:
            if image not in self.exceptions['image_specific']:
                self.exceptions['image_specific'][image] = []
            self.exceptions['image_specific'][image].append(exception)
        else:
            self.exceptions['global'].append(exception)
        
        self.save_exceptions()
        return exception
    
    def remove_exception(self, exception_hash: str):
        """Remove an exception by its hash"""
        
        # Check global exceptions
        self.exceptions['global'] = [
            e for e in self.exceptions['global'] 
            if e.get('hash') != exception_hash
        ]
        
        # Check image-specific exceptions
        for image in self.exceptions['image_specific']:
            self.exceptions['image_specific'][image] = [
                e for e in self.exceptions['image_specific'][image]
                if e.get('hash') != exception_hash
            ]
        
        self.save_exceptions()
    
    def get_active_exceptions(self, image: str = None) -> Set[str]:
        """Get list of active exception CVE IDs"""
        
        active_cves = set()
        now = datetime.now()
        
        # Add global exceptions
        for exception in self.exceptions.get('global', []):
            expiry = datetime.fromisoformat(exception['expiry_date'])
            if expiry > now:
                active_cves.add(exception['cve_id'])
        
        # Add image-specific exceptions if applicable
        if image and image in self.exceptions.get('image_specific', {}):
            for exception in self.exceptions['image_specific'][image]:
                expiry = datetime.fromisoformat(exception['expiry_date'])
                if expiry > now:
                    active_cves.add(exception['cve_id'])
        
        return active_cves
    
    def filter_scan_results(self, scan_results: Dict, image: str = None) -> Dict:
        """Filter scan results to exclude excepted vulnerabilities"""
        
        active_exceptions = self.get_active_exceptions(image)
        
        if not active_exceptions:
            return scan_results
        
        # Filter CVE list
        filtered_cves = []
        excepted_cves = []
        
        for cve in scan_results.get('cve_list', []):
            if cve['id'] in active_exceptions:
                excepted_cves.append(cve)
            else:
                filtered_cves.append(cve)
        
        # Create filtered results
        filtered_results = scan_results.copy()
        filtered_results['cve_list'] = filtered_cves
        filtered_results['excepted_cves'] = excepted_cves
        filtered_results['excepted_count'] = len(excepted_cves)
        
        # Recalculate severity summary
        severity_summary = {level: 0 for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']}
        for cve in filtered_cves:
            severity = cve.get('severity', 'UNKNOWN')
            if severity in severity_summary:
                severity_summary[severity] += 1
        
        filtered_results['severity_summary'] = severity_summary
        filtered_results['total_vulnerabilities'] = sum(severity_summary.values())
        
        return filtered_results
    
    def cleanup_expired_exceptions(self):
        """Remove expired exceptions"""
        
        now = datetime.now()
        
        # Clean global exceptions
        self.exceptions['global'] = [
            e for e in self.exceptions.get('global', [])
            if datetime.fromisoformat(e['expiry_date']) > now
        ]
        
        # Clean image-specific exceptions
        for image in self.exceptions.get('image_specific', {}):
            self.exceptions['image_specific'][image] = [
                e for e in self.exceptions['image_specific'][image]
                if datetime.fromisoformat(e['expiry_date']) > now
            ]
        
        self.save_exceptions()