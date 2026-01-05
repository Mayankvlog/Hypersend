#!/usr/bin/env python3
"""
Deep Security Vulnerability Scanner
Comprehensive testing for HTTP 300,400,500 error handling
"""

import sys
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Tuple

class SecurityScanner:
    """Deep security vulnerability scanner"""
    
    def __init__(self, backend_dir: Path):
        self.backend_dir = backend_dir
        self.vulnerabilities = []
        self.fixes = []
    
    def scan_http_error_handling(self) -> Dict[str, Any]:
        """Scan for comprehensive HTTP error handling"""
        print("=== Scanning HTTP Error Handling ===")
        
        error_types = {
            '3xx': {
                'description': 'Redirection errors',
                'patterns': [
                    (r'status\.HTTP_3\d+', 'Redirect status codes'),
                    (r'RedirectResponse|Response.*status.*30[0-9]', 'Redirect responses'),
                    (r'location.*header|Location:', 'Location headers')
                ]
            },
            '4xx': {
                'description': 'Client errors', 
                'patterns': [
                    (r'status\.HTTP_4\d+', '4xx status code handling'),
                    (r'HTTPException.*4\d+', '4xx HTTP exceptions'),
                    (r'400|401|403|404|409|422|429', 'Specific 4xx codes'),
                    (r'BadRequest|Unauthorized|Forbidden|NotFound|Conflict', '4xx exception classes')
                ]
            },
            '5xx': {
                'description': 'Server errors',
                'patterns': [
                    (r'status\.HTTP_5\d+', '5xx status code handling'),
                    (r'HTTPException.*5\d+', '5xx HTTP exceptions'),
                    (r'500|502|503|504', 'Specific 5xx codes'),
                    (r'InternalServerError|BadGateway|ServiceUnavailable', '5xx exception classes')
                ]
            }
        }
        
        findings = {}
        
        for error_class, details in error_types.items():
            print(f"\nScanning {details['description']} ({error_class}):")
            
            class_findings = []
            for pattern, description in details['patterns']:
                found_files = self._search_in_backend(pattern)
                if found_files:
                    class_findings.append({
                        'pattern': pattern,
                        'description': description,
                        'files': found_files
                    })
                    print(f"   Found: {description}")
                else:
                    print(f"  [X] Missing: {description}")
                    self.vulnerabilities.append({
                        'type': 'HTTP_ERROR_HANDLING',
                        'severity': 'MEDIUM',
                        'issue': f"Missing {description} for {error_class}",
                        'recommendation': f"Add proper {description} handling"
                    })
            
            findings[error_class] = {
                'description': details['description'],
                'findings': class_findings,
                'coverage': len(class_findings) / len(details['patterns'])
            }
        
        return findings
    
    def scan_security_headers(self) -> Dict[str, Any]:
        """Scan for security header implementation"""
        print("\n=== Scanning Security Headers ===")
        
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Referrer-Policy',
            'Permissions-Policy',
            'Strict-Transport-Security'
        ]
        
        findings = []
        for header in security_headers:
            found_files = self._search_in_backend(header)
            if found_files:
                findings.append({
                    'header': header,
                    'implemented': True,
                    'files': found_files
                })
                print(f"   {header}: Implemented")
            else:
                findings.append({
                    'header': header,
                    'implemented': False,
                    'files': []
                })
                print(f"   {header}: Missing")
                self.vulnerabilities.append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'MEDIUM',
                    'issue': f"Missing security header: {header}",
                    'recommendation': f"Implement {header} in response headers"
                })
        
        return {'headers': findings, 'coverage': len([f for f in findings if f['implemented']]) / len(security_headers)}
    
    def scan_input_validation(self) -> Dict[str, Any]:
        """Scan for input validation security"""
        print("\n=== Scanning Input Validation ===")
        
        validation_checks = {
            'SQL Injection': [
                (r'query.*[+]|execute.*query', 'SQL query patterns'),
                (r'raw.*sql|exec.*sql', 'Raw SQL execution'),
                (r'format.*sql|%\s*.*sql', 'SQL string formatting')
            ],
            'XSS Prevention': [
                (r'escape|html.*escape|xss', 'XSS escaping'),
                (r'sanitize|clean.*input', 'Input sanitization'),
                (r'<script|javascript:', 'Script detection')
            ],
            'Path Traversal': [
                (r'\.\.|\.\.|path.*traversal', 'Path traversal detection'),
                (r'normalize|resolve.*path', 'Path normalization'),
                (r'relative.*to|absolute.*path', 'Path boundary checking')
            ],
            'Command Injection': [
                (r'subprocess|os\.system|eval', 'Command execution'),
                (r'shell=True|shell.*True', 'Shell execution'),
                (r'popen|exec\(', 'Process execution')
            ],
            'File Upload Security': [
                (r'mime.*type|content.*type', 'MIME type validation'),
                (r'file.*extension|ext.*check', 'File extension validation'),
                (r'max.*size|file.*size.*limit', 'File size limits')
            ]
        }
        
        findings = {}
        
        for vulnerability_type, patterns in validation_checks.items():
            print(f"\nScanning {vulnerability_type}:")
            
            type_findings = []
            for pattern, description in patterns:
                found_files = self._search_in_backend(pattern)
                if found_files:
                    type_findings.append({
                        'pattern': pattern,
                        'description': description,
                        'files': found_files,
                        'protective': True
                    })
                    print(f"   Found protection: {description}")
                else:
                    # Only flag as vulnerability for high-risk patterns
                    if any(risk in vulnerability_type.lower() for risk in ['injection', 'traversal']):
                        self.vulnerabilities.append({
                            'type': 'INPUT_VALIDATION',
                            'severity': 'HIGH',
                            'issue': f"Missing {description} for {vulnerability_type}",
                            'recommendation': f"Add {description} protection"
                        })
                        print(f"   Missing protection: {description}")
            
            findings[vulnerability_type] = {
                'findings': type_findings,
                'protection_score': len(type_findings) / len(patterns)
            }
        
        return findings
    
    def scan_authentication_security(self) -> Dict[str, Any]:
        """Scan for authentication and authorization security"""
        print("\n=== Scanning Authentication Security ===")
        
        auth_checks = {
            'Password Security': [
                (r'hash.*password|password.*hash', 'Password hashing'),
                (r'bcrypt|pbkdf2|scrypt|argon2', 'Strong hash algorithms'),
                (r'salt|pepper', 'Password salting'),
                (r'min.*length|password.*policy', 'Password policies')
            ],
            'Session Security': [
                (r'jwt.*secret|secret.*key', 'JWT secret management'),
                (r'expire|timeout|ttl', 'Session expiration'),
                (r'refresh.*token|rotate.*token', 'Token rotation'),
                (r'csrf.*token|anti.*csrf', 'CSRF protection')
            ],
            'Rate Limiting': [
                (r'rate.*limit|limit.*rate', 'Rate limiting'),
                (r'brute.*force|login.*attempt', 'Brute force protection'),
                (r'captcha|recaptcha', 'CAPTCHA protection'),
                (r'lockout|account.*lock', 'Account lockout')
            ],
            'Authorization': [
                (r'permission|access.*control|rbac', 'Permission checks'),
                (r'role.*based|user.*role', 'Role-based access'),
                (r'owner.*check|is.*owner', 'Ownership verification'),
                (r'member.*check|is.*member', 'Membership verification')
            ]
        }
        
        findings = {}
        
        for security_type, patterns in auth_checks.items():
            print(f"\nScanning {security_type}:")
            
            type_findings = []
            for pattern, description in patterns:
                found_files = self._search_in_backend(pattern)
                if found_files:
                    type_findings.append({
                        'pattern': pattern,
                        'description': description,
                        'files': found_files
                    })
                    print(f"   Found: {description}")
                else:
                    print(f"   Missing: {description}")
                    # Lower severity for optional features
                    severity = 'MEDIUM' if 'captcha' in description.lower() else 'HIGH'
                    self.vulnerabilities.append({
                        'type': 'AUTH_SECURITY',
                        'severity': severity,
                        'issue': f"Missing {description}",
                        'recommendation': f"Implement {description}"
                    })
            
            findings[security_type] = {
                'findings': type_findings,
                'coverage': len(type_findings) / len(patterns)
            }
        
        return findings
    
    def scan_data_protection(self) -> Dict[str, Any]:
        """Scan for data protection and privacy features"""
        print("\n=== Scanning Data Protection ===")
        
        data_protection_checks = {
            'Encryption': [
                (r'encrypt|decrypt|cipher|crypto', 'Encryption/decryption'),
                (r'tls|ssl|https', 'TLS/SSL usage'),
                (r'at.*rest|rest.*encryption', 'Data at rest encryption'),
                (r'in.*transit|transit.*encryption', 'Data in transit encryption')
            ],
            'Data Sanitization': [
                (r'pii|personal.*data|sensitive.*data', 'PII handling'),
                (r'anonymiz|pseudonym', 'Data anonymization'),
                (r'data.*mask|mask.*data', 'Data masking'),
                (r'log.*sanitiz|sanitiz.*log', 'Log sanitization')
            ],
            'Data Retention': [
                (r'retain|expir|cleanup|purge', 'Data retention policies'),
                (r'gdpr|ccpa|privacy', 'Privacy compliance'),
                (r'data.*lifecycle|lifecycle.*data', 'Data lifecycle management')
            ]
        }
        
        findings = {}
        
        for protection_type, patterns in data_protection_checks.items():
            print(f"\nScanning {protection_type}:")
            
            type_findings = []
            for pattern, description in patterns:
                found_files = self._search_in_backend(pattern)
                if found_files:
                    type_findings.append({
                        'pattern': pattern,
                        'description': description,
                        'files': found_files
                    })
                    print(f"   Found: {description}")
                else:
                    print(f"   Missing: {description}")
                    # Lower severity for compliance features
                    self.vulnerabilities.append({
                        'type': 'DATA_PROTECTION',
                        'severity': 'LOW',
                        'issue': f"Missing {description}",
                        'recommendation': f"Consider implementing {description}"
                    })
            
            findings[protection_type] = {
                'findings': type_findings,
                'coverage': len(type_findings) / len(patterns)
            }
        
        return findings
    
    def _search_in_backend(self, pattern: str) -> List[str]:
        """Search for pattern across all Python files in backend"""
        found_files = []
        
        try:
            for py_file in self.backend_dir.rglob("*.py"):
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                        found_files.append(str(py_file.relative_to(self.backend_dir)))
                        
                except Exception:
                    # Skip files that can't be read
                    continue
                    
        except Exception as e:
            print(f"Error searching for pattern {pattern}: {e}")
            
        return found_files
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("DEEP SECURITY VULNERABILITY SCAN")
        print("="*80)
        
        # Run all scans
        results = {
            'http_errors': self.scan_http_error_handling(),
            'security_headers': self.scan_security_headers(),
            'input_validation': self.scan_input_validation(),
            'authentication': self.scan_authentication_security(),
            'data_protection': self.scan_data_protection()
        }
        
        # Calculate overall security score
        scores = []
        
        # HTTP error handling score
        error_coverage = sum(
            findings.get('coverage', 0) 
            for findings in results['http_errors'].values()
            if isinstance(findings, dict) and 'coverage' in findings
        )
        scores.append(error_coverage / len(results['http_errors']) if results['http_errors'] else 0)
        
        # Other scores
        for category in ['security_headers', 'input_validation', 'authentication', 'data_protection']:
            if category in results:
                if 'coverage' in results[category]:
                    scores.append(results[category]['coverage'])
                elif isinstance(results[category], dict):
                    category_scores = [
                        item.get('protection_score', 0) or item.get('coverage', 0)
                        for item in results[category].values()
                        if isinstance(item, dict)
                    ]
                    if category_scores:
                        scores.append(sum(category_scores) / len(category_scores))
        
        overall_score = sum(scores) / len(scores) if scores else 0
        
        # Summary statistics
        high_vulns = len([v for v in self.vulnerabilities if v['severity'] == 'HIGH'])
        medium_vulns = len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM'])
        low_vulns = len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
        
        print(f"\nSECURITY SCORE: {overall_score:.1%}")
        print(f"VULNERABILITIES: {len(self.vulnerabilities)} total")
        print(f"  HIGH: {high_vulns}")
        print(f"  MEDIUM: {medium_vulns}")
        print(f"  LOW: {low_vulns}")
        
        return {
            'overall_score': overall_score,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': {
                'high': high_vulns,
                'medium': medium_vulns,
                'low': low_vulns
            },
            'detailed_results': results,
            'vulnerabilities': self.vulnerabilities
        }

def main():
    """Main scanning function"""
    script_dir = Path(__file__).parent
    backend_dir = script_dir / "backend"
    
    if not backend_dir.exists():
        print(f"ERROR: Backend directory not found: {backend_dir}")
        return False
    
    scanner = SecurityScanner(backend_dir)
    report = scanner.generate_security_report()
    
    # Print critical vulnerabilities first
    critical_vulns = [v for v in report['vulnerabilities'] if v['severity'] == 'HIGH']
    if critical_vulns:
        print(f"\n{'! '*40}CRITICAL VULNERABILITIES{'! '*40}")
        for vuln in critical_vulns:
            print(f"\n {vuln['type']}: {vuln['issue']}")
            print(f"   Recommendation: {vuln['recommendation']}")
            print(f"   Severity: {vuln['severity']}")
    
    # Overall assessment
    print(f"\n{'='*80}")
    print("SECURITY ASSESSMENT")
    print("="*80)
    
    if report['overall_score'] >= 0.8:
        print(" GOOD: Strong security posture")
    elif report['overall_score'] >= 0.6:
        print("  MODERATE: Some security improvements needed")
    elif report['overall_score'] >= 0.4:
        print(" POOR: Significant security issues found")
    else:
        print(" CRITICAL: Major security vulnerabilities")
    
    success = report['overall_score'] >= 0.6 and report['severity_breakdown']['high'] == 0
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)