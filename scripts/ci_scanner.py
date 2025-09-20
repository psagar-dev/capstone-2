import argparse
import json
import sys
import os
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from scanner.trivy_scanner import TrivyScanner
from reporting.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description='CI/CD Vulnerability Scanner')
    parser.add_argument('--image', required=True, help='Docker image to scan')
    parser.add_argument('--output-format', choices=['json', 'html', 'markdown'], 
                       default='json', help='Output format')
    parser.add_argument('--output-file', required=True, help='Output file path')
    parser.add_argument('--config', default='config/trivy-config.yaml', 
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Load configuration
    with open(args.config, 'r') as f:
        import yaml
        config = yaml.safe_load(f)
    
    # Initialize scanner
    scanner = TrivyScanner(config['scanner'])
    
    # Parse image name and tag
    if ':' in args.image:
        image_name, tag = args.image.rsplit(':', 1)
    else:
        image_name = args.image
        tag = 'latest'
    
    # Perform scan
    try:
        scan_results = scanner.scan_image(image_name, tag)
        
        # Generate report
        report_gen = ReportGenerator()
        
        if args.output_format == 'json':
            with open(args.output_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
        elif args.output_format == 'html':
            html_report = report_gen.generate_html(scan_results)
            with open(args.output_file, 'w') as f:
                f.write(html_report)
        elif args.output_format == 'markdown':
            md_report = report_gen.generate_markdown(scan_results)
            with open(args.output_file, 'w') as f:
                f.write(md_report)
        
        print(f"✅ Scan completed successfully. Results saved to {args.output_file}")
        
        # Exit with appropriate code based on severity
        if scan_results['severity_summary'].get('CRITICAL', 0) > 0:
            sys.exit(1)
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()