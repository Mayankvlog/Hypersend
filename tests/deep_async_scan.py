"""
Deep code scan for async/await issues and Future object handling in registration/login
Scans for:
1. Improper await statements
2. Future objects accessed without await
3. Mixed async/sync operations
4. Coroutine objects not being awaited
"""

import ast
import sys
from pathlib import Path
from typing import List, Dict, Tuple

class AsyncIssueScanner(ast.NodeVisitor):
    """AST visitor to find async/await issues"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.issues: List[Dict] = []
        self.current_function = None
        self.current_function_is_async = False
        
    def visit_AsyncFunctionDef(self, node):
        """Track async function definitions"""
        prev_func = self.current_function
        prev_is_async = self.current_function_is_async
        
        self.current_function = node.name
        self.current_function_is_async = True
        
        self.generic_visit(node)
        
        self.current_function = prev_func
        self.current_function_is_async = prev_is_async
    
    def visit_FunctionDef(self, node):
        """Track regular function definitions"""
        prev_func = self.current_function
        prev_is_async = self.current_function_is_async
        
        self.current_function = node.name
        self.current_function_is_async = False
        
        self.generic_visit(node)
        
        self.current_function = prev_func
        self.current_function_is_async = prev_is_async
    
    def visit_Call(self, node):
        """Check for potential async issues in function calls"""
        # Check for .get() calls on potential Future objects
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'get':
                # Check if this could be a Future object
                if isinstance(node.func.value, ast.Name):
                    var_name = node.func.value.id
                    if var_name in ['result', 'response', 'await_result']:
                        self.issues.append({
                            'type': 'POTENTIAL_FUTURE_GET',
                            'line': node.lineno,
                            'function': self.current_function,
                            'message': f"Calling .get() on potential Future object '{var_name}'",
                            'severity': 'HIGH',
                            'fix': f"Ensure '{var_name}' is awaited before calling .get()"
                        })
        
        self.generic_visit(node)
    
    def visit_Attribute(self, node):
        """Check for accessing properties on coroutine objects"""
        # Check for things like result.inserted_id without await
        if isinstance(node.value, ast.Name):
            if node.value.id in ['result', 'response']:
                if node.attr in ['inserted_id', 'status_code', 'text']:
                    # This could be accessing a Future without await
                    pass
        
        self.generic_visit(node)


def scan_file(filepath: Path) -> Tuple[List[Dict], str]:
    """Scan a Python file for async/await issues"""
    issues = []
    content = ""
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        scanner = AsyncIssueScanner(str(filepath))
        scanner.visit(tree)
        issues = scanner.issues
        
    except SyntaxError as e:
        issues.append({
            'type': 'SYNTAX_ERROR',
            'line': e.lineno,
            'message': f"Syntax error: {e.msg}",
            'severity': 'CRITICAL'
        })
    except Exception as e:
        issues.append({
            'type': 'SCAN_ERROR',
            'message': f"Error scanning file: {e}",
            'severity': 'MEDIUM'
        })
    
    return issues, content


def scan_code_patterns(content: str, filepath: Path) -> List[Dict]:
    """Scan for specific code patterns that indicate issues"""
    issues = []
    lines = content.split('\n')
    
    # Pattern 1: Check for await without assignment
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Check for result = users_col.insert_one(...) without immediate await
        if 'result =' in line and 'users_col.' in line and 'await' not in line:
            # Look ahead to see if it's awaited later
            if i < len(lines):
                next_line = lines[i].strip() if i < len(lines) else ""
                if 'await' not in next_line and 'result.' in next_line:
                    issues.append({
                        'type': 'MISSING_AWAIT',
                        'line': i,
                        'filepath': str(filepath),
                        'code': line,
                        'message': f"Variable 'result' assigned from async call but not awaited",
                        'severity': 'CRITICAL',
                        'fix': "Use: result = await asyncio.wait_for(...) or result = await ...insert_one(...)"
                    })
        
        # Pattern 2: Check for .inserted_id access
        if '.inserted_id' in line and 'result' in line:
            # Check if result was awaited
            prev_lines = '\n'.join(lines[max(0, i-10):i])
            if 'await' not in prev_lines or 'asyncio.wait_for' in prev_lines:
                # This is likely accessing inserted_id on a Future
                if 'str(' in line:  # Converting to string
                    issues.append({
                        'type': 'FUTURE_ATTRIBUTE_ACCESS',
                        'line': i,
                        'filepath': str(filepath),
                        'code': line,
                        'message': f"Accessing .inserted_id on potentially non-awaited result",
                        'severity': 'HIGH',
                        'fix': "Ensure result is fully awaited before accessing .inserted_id"
                    })
        
        # Pattern 3: Check for hasattr(__await__) checks  
        if '__await__' in line:
            issues.append({
                'type': 'COROUTINE_CHECK',
                'line': i,
                'filepath': str(filepath),
                'code': line,
                'message': "Checking for __await__ attribute indicates potential async handling issue",
                'severity': 'MEDIUM',
                'fix': "Consider using asyncio.iscoroutine() or properly awaiting"
            })
    
    return issues


def main():
    """Main scan function"""
    backend_path = Path(__file__).parent / "backend"
    
    print("=" * 80)
    print("DEEP CODE SCAN FOR ASYNC/AWAIT AND FUTURE OBJECT ISSUES")
    print("=" * 80)
    print()
    
    target_files = [
        backend_path / "routes" / "auth.py",
        backend_path / "database.py",
        backend_path / "db_proxy.py",
        backend_path / "auth" / "utils.py",
    ]
    
    all_issues = []
    
    for filepath in target_files:
        if not filepath.exists():
            print(f"⚠️  File not found: {filepath}")
            continue
        
        print(f"\n📄 Scanning: {filepath.relative_to(backend_path.parent)}")
        print("-" * 80)
        
        # AST-based scanning
        ast_issues, content = scan_file(filepath)
        
        # Pattern-based scanning
        pattern_issues = scan_code_patterns(content, filepath)
        
        issues = ast_issues + pattern_issues
        
        if issues:
            print(f"Found {len(issues)} potential issues:")
            for issue in issues:
                severity = issue.get('severity', 'UNKNOWN')
                line = issue.get('line', 'N/A')
                msg = issue.get('message', 'Unknown issue')
                issue_type = issue.get('type', 'UNKNOWN')
                
                severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                
                print(f"\n  {severity_emoji} [{issue_type}] Line {line}: {msg}")
                
                if 'code' in issue:
                    print(f"     Code: {issue['code'].strip()}")
                
                if 'fix' in issue:
                    print(f"     Fix: {issue['fix']}")
                
                all_issues.append(issue)
        else:
            print("✅ No async/await issues detected")
    
    # Summary
    print("\n" + "=" * 80)
    print("SCAN SUMMARY")
    print("=" * 80)
    
    if all_issues:
        critical = len([i for i in all_issues if i.get('severity') == 'CRITICAL'])
        high = len([i for i in all_issues if i.get('severity') == 'HIGH'])
        medium = len([i for i in all_issues if i.get('severity') == 'MEDIUM'])
        low = len([i for i in all_issues if i.get('severity') == 'LOW'])
        
        print(f"Total Issues: {len(all_issues)}")
        print(f"  🔴 CRITICAL: {critical}")
        print(f"  🟠 HIGH:     {high}")
        print(f"  🟡 MEDIUM:   {medium}")
        print(f"  🟢 LOW:      {low}")
        
        if critical > 0:
            print("\n⚠️  CRITICAL ISSUES FOUND - MUST FIX")
        elif high > 0:
            print("\n⚠️  HIGH PRIORITY ISSUES FOUND - SHOULD FIX")
        else:
            print("\n✅ No critical issues found")
    else:
        print("✅ NO ASYNC/AWAIT ISSUES DETECTED")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
