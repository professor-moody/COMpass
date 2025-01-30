# core/report.py
"""
Reporting functionality for COM Security Analyzer
"""
from typing import Dict, List, Any
import json
from datetime import datetime

from .base import AnalysisResult
from .models import VulnerabilityLevel

class ReportGenerator:
    """Generates analysis reports in various formats"""
    
    def __init__(self, results: Dict[str, Any]):
        self.results = results
        self.timestamp = datetime.now()

    def generate_summary(self) -> str:
        """Generate a text summary of the analysis results"""
        summary = []
        summary.append("=== COM Security Analysis Summary ===")
        summary.append(f"Analysis completed: {self.timestamp}")
        
        # Add registry analysis summary
        registry_results = self.results.get('RegistryAnalyzer', {})
        if registry_results:
            summary.append(f"\nCOM Objects analyzed: {len(registry_results)}")
        
        # Add security analysis summary
        security_results = self.results.get('SecurityAnalyzer', {})
        if security_results:
            security_count = len(security_results)
            summary.append(f"\nSecurity descriptors analyzed: {security_count}")
        
                    # Add vulnerability summary
        vuln_results = self.results.get('VulnerabilityAnalyzer', {})
        if vuln_results:
            total_vulns = sum(len(vr.findings) for vr in vuln_results.values() if hasattr(vr, 'findings'))
            summary.append(f"\nTotal vulnerabilities found: {total_vulns}")
            
            # Group vulnerabilities by severity
            # Group vulnerabilities by severity and type
            severity_counts = {
                VulnerabilityLevel.CRITICAL: 0,
                VulnerabilityLevel.HIGH: 0,
                VulnerabilityLevel.MEDIUM: 0,
                VulnerabilityLevel.LOW: 0
            }
            
            vuln_types = {}  # Track vulnerability types and their counts
            
            for vuln_result in vuln_results.values():
                if not hasattr(vuln_result, 'findings'):
                    continue
                for finding in vuln_result.findings:
                    if hasattr(finding, 'level'):
                        severity_counts[finding.level] += 1
                        
                    # Track vulnerability types
                    if hasattr(finding, 'name'):
                        vuln_types[finding.name] = vuln_types.get(finding.name, 0) + 1
            
            # Add severity breakdown
            if any(severity_counts.values()):
                summary.append("\nVulnerabilities by severity:")
                for level, count in severity_counts.items():
                    if count > 0:
                        summary.append(f"  {level.name}: {count}")
            
            # Add vulnerability type breakdown
            if vuln_types:
                summary.append("\nVulnerability types found:")
                for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                    summary.append(f"  {vuln_type}: {count}")
            
            # Add severity breakdown
            if any(severity_counts.values()):
                summary.append("\nVulnerabilities by severity:")
                for level, count in severity_counts.items():
                    if count > 0:
                        summary.append(f"  {level.name}: {count}")
        
        # Add method analysis summary if available
        method_results = self.results.get('MethodDiscoveryAnalyzer', {})
        if method_results:
            successful = sum(1 for r in method_results.values() if r.accessible)
            total = len(method_results)
            summary.append(f"\nMethods analyzed: {successful}/{total} objects accessed successfully")
        
        return "\n".join(summary)

    def save_to_file(self, filename: str):
        """Save detailed results to a file"""
        def result_serializer(obj):
            if hasattr(obj, '__dict__'):
                return obj.__dict__
            return str(obj)
        
        report_data = {
            'timestamp': self.timestamp.isoformat(),
            'summary': self.generate_summary(),
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=result_serializer)