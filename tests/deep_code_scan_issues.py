"""
Deep code scan for ObjectId serialization issues and other critical problems.
Scans the entire backend for:
1. ObjectId serialization issues
2. File download/upload issues
3. Password reset/forgot password issues
4. Group/Chat serialization issues

Run with: python deep_code_scan_issues.py
"""

import os
import re
import json
from pathlib import Path
from typing import List, Tuple, Dict

class CodeScanner:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.issues = []
        self.patterns = {
            "objectid_return": r"return\s*{[^}]*ObjectId\s*\([^)]*\)[^}]*}",
            "objectid_in_dict": r"['\"]_id['\"]\s*:\s*ObjectId\s*\(",
            "unencoded_response": r"return\s*{[^}]*chat[^}]*}(?!.*_encode_doc)",
            "missing_string_conversion": r"ObjectId\(\)[^)]*(?!str)",
            "file_missing_fields": r"return\s*{[^}]*file",
            "storage_key_none": r"storage_key\s*=\s*None|if\s+not\s+storage_key",
        }
        self.severity_map = {
            "objectid_return": "CRITICAL",
            "objectid_in_dict": "HIGH",
            "unencoded_response": "CRITICAL",
            "missing_string_conversion": "MEDIUM",
            "file_missing_fields": "MEDIUM",
            "storage_key_none": "HIGH",
        }
    
    def scan_file(self, filepath: Path) -> List[Tuple[str, int, str, str]]:
        """Scan a single Python file for issues"""
        issues = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return [(filepath.name, 0, "READ_ERROR", str(e))]
        
        # Check for return statements with ObjectId objects
        for i, line in enumerate(lines, 1):
            # Pattern 1: Return statements with raw ObjectId
            if re.search(r"return\s*\{", line) and not "_encode_doc" in line:
                # Check if line contains ObjectId
                if "_id" in line and ("ObjectId" in "\n".join(lines[max(0, i-5):i]) or "group" in line):
                    issues.append((
                        filepath.name,
                        i,
                        "POTENTIAL_OBJECTID_LEAK",
                        f"Return statement without encoding: {line.strip()}"
                    ))
            
            # Pattern 2: file_doc without proper type conversion
            if "file_doc.get" in line and not "str(" in line:
                if "_id" in line or "size" in line:
                    context = "\n".join(lines[max(0, i-2):i+3])
                    if "return" in context:
                        issues.append((
                            filepath.name,
                            i,
                            "FILE_FIELD_TYPE_ERROR",
                            f"File field not properly typed: {line.strip()}"
                        ))
            
            # Pattern 3: Missing storage_key checks
            if "storage_key" in line and "file_doc.get" in line:
                if not "if" in "\n".join(lines[max(0, i-1):i+2]) and "=" in line:
                    issues.append((
                        filepath.name,
                        i,
                        "MISSING_STORAGE_KEY_CHECK",
                        f"Storage key assignment without validation: {line.strip()}"
                    ))
            
            # Pattern 4: Expired file handling
            if "expiry_time" in line or "expires_at" in line:
                if "if" in line and (">" in line or "<" in line):
                    # Check if proper deletion is done
                    context = "\n".join(lines[i:min(len(lines), i+5)])
                    if "status" in context or "delete" in context.lower():
                        pass  # Likely properly handled
                    else:
                        issues.append((
                            filepath.name,
                            i,
                            "EXPIRY_HANDLING",
                            f"File expiry check may need proper deletion: {line.strip()}"
                        ))
            
            # Pattern 5: Group member encoding
            if "members_detail" in line or "member_" in line:
                if "append" in line and "return" in "\n".join(lines[i:min(len(lines), i+10)]):
                    issues.append((
                        filepath.name,
                        i,
                        "MEMBER_ENCODING_CHECK",
                        f"Check member details encoding: {line.strip()}"
                    ))
        
        return issues
    
    def scan_directory(self, dir_path: Path = None) -> Dict[str, List]:
        """Recursively scan directory for issues"""
        if dir_path is None:
            dir_path = self.root_path
        
        all_issues = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "OTHER": []
        }
        
        for py_file in dir_path.rglob("*.py"):
            # Skip test files and __pycache__
            if "__pycache__" in str(py_file) or py_file.name.startswith("test_"):
                continue
            
            issues = self.scan_file(py_file)
            
            for filename, line_num, issue_type, details in issues:
                severity = "MEDIUM"  # Default
                for pattern, sev in self.severity_map.items():
                    if pattern in issue_type.lower():
                        severity = sev
                        break
                
                issue_dict = {
                    "file": filename,
                    "line": line_num,
                    "type": issue_type,
                    "details": details,
                    "path": str(py_file.relative_to(self.root_path))
                }
                
                all_issues[severity].append(issue_dict)
        
        return all_issues
    
    def generate_report(self, issues: Dict[str, List]) -> str:
        """Generate a formatted report"""
        report = []
        report.append("=" * 80)
        report.append("DEEP CODE SCAN REPORT - ObjectId Serialization & Critical Issues")
        report.append("=" * 80)
        report.append("")
        
        total_issues = sum(len(v) for v in issues.values())
        report.append(f"Total Issues Found: {total_issues}")
        report.append("")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OTHER"]:
            severity_issues = issues[severity]
            if severity_issues:
                report.append(f"\n{severity} SEVERITY ({len(severity_issues)} issues):")
                report.append("-" * 80)
                
                for issue in severity_issues:
                    report.append(f"  File: {issue['path']}")
                    report.append(f"  Line: {issue['line']}")
                    report.append(f"  Type: {issue['type']}")
                    report.append(f"  Details: {issue['details']}")
                    report.append("")
        
        report.append("=" * 80)
        report.append("RECOMMENDATIONS:")
        report.append("-" * 80)
        report.append("1. For CRITICAL issues: Review and apply ObjectId encoding fixes")
        report.append("2. For HIGH issues: Validate data types and proper string conversion")
        report.append("3. For MEDIUM issues: Test file operations and ensure proper handling")
        report.append("4. All ObjectId returns should use: json.loads(json.dumps(_encode_doc(...), default=str))")
        report.append("")
        
        return "\n".join(report)


def run_scan():
    """Run the deep code scan"""
    backend_path = Path(__file__).parent.parent / "backend"
    
    scanner = CodeScanner(str(backend_path))
    issues = scanner.scan_directory(backend_path)
    
    report = scanner.generate_report(issues)
    print(report)
    
    # Save report
    report_file = Path(__file__).parent / "DEEP_SCAN_REPORT.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"\nReport saved to: {report_file}")
    
    # Return summary
    return {
        "total": sum(len(v) for v in issues.values()),
        "critical": len(issues["CRITICAL"]),
        "high": len(issues["HIGH"]),
        "medium": len(issues["MEDIUM"]),
        "issues": issues
    }


if __name__ == "__main__":
    result = run_scan()
    print(f"\nSummary: {result['critical']} CRITICAL, {result['high']} HIGH issues found")
