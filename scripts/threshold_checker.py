import argparse
import json
import yaml
import sys
from typing import Dict

class ThresholdChecker:
    """Check if vulnerability counts exceed configured thresholds"""
    
    def __init__(self, config: Dict):
        self.thresholds = config.get('thresholds', {})
    
    def check(self, scan_results: Dict) -> Dict:
        """
        Check scan results against thresholds
        
        Returns:
            Dictionary with check results and actions
        """
        severity_summary = scan_results.get('severity_summary', {})
        check_results = {
            'passed': True,
            'violations': [],
            'actions': []
        }
        
        for severity, count in severity_summary.items():
            severity_lower = severity.lower()
            if severity_lower in self.thresholds:
                threshold = self.thresholds[severity_lower]
                max_allowed = threshold.get('max_allowed', 999)
                
                if count > max_allowed:
                    check_results['passed'] = False
                    violation = {
                        'severity': severity,
                        'count': count,
                        'max_allowed': max_allowed,
                        'action': threshold.get('action', 'log')
                    }
                    check_results['violations'].append(violation)
                    check_results['actions'].append(threshold.get('action', 'log'))
        
        return check_results

def main():
    parser = argparse.ArgumentParser(description='Check vulnerability thresholds')
    parser.add_argument('--scan-results', required=True, help='Scan results file')
    parser.add_argument('--config', required=True, help='Configuration file')
    
    args = parser.parse_args()
    
    # Load scan results
    with open(args.scan_results, 'r') as f:
        scan_results = json.load(f)
    
    # Load configuration
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    
    # Check thresholds
    checker = ThresholdChecker(config)
    check_results = checker.check(scan_results)
    
    # Print results
    if check_results['passed']:
        print("✅ All vulnerability thresholds passed")
    else:
        print("❌ Vulnerability threshold violations detected:")
        for violation in check_results['violations']:
            print(f"  - {violation['severity']}: {violation['count']} vulnerabilities "
                  f"(max allowed: {violation['max_allowed']}) - Action: {violation['action']}")
    
    # Save check results
    with open('threshold-check-results.json', 'w') as f:
        json.dump(check_results, f, indent=2)
    
    # Exit with appropriate code
    if 'block' in check_results['actions']:
        sys.exit(1)
    elif 'warn' in check_results['actions']:
        sys.exit(0)  # Warning only, don't block
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()