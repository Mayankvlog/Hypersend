#!/usr/bin/env python3
"""
Script to find unused imports in Python and Dart files
"""

import os
import re
import ast
import json
from pathlib import Path
from typing import Set, Dict, List, Tuple

class UnusedImportAnalyzer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.results = []
    
    def analyze_python_file(self, file_path: Path) -> List[Dict]:
        """Analyze a Python file for unused imports"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Find all imports
            imports = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.asname if alias.asname else alias.name
                        imports[name] = {
                            'type': 'import',
                            'module': alias.name,
                            'alias': alias.asname,
                            'line': node.lineno
                        }
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        name = alias.asname if alias.asname else alias.name
                        imports[name] = {
                            'type': 'from_import',
                            'module': module,
                            'name': alias.name,
                            'alias': alias.asname,
                            'line': node.lineno
                        }
            
            # Find all names used in the code
            used_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    used_names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    # For attribute access like module.function
                    if isinstance(node.value, ast.Name):
                        used_names.add(node.value.id)
            
            # Find unused imports
            unused = []
            for import_name, import_info in imports.items():
                if import_name not in used_names:
                    # Special cases for type hints and decorators
                    if self._is_special_case(content, import_name):
                        continue
                    unused.append(import_info)
            
            return unused
            
        except Exception as e:
            return [{'error': str(e), 'file': str(file_path)}]
    
    def _is_special_case(self, content: str, import_name: str) -> bool:
        """Check if import is used in type hints, decorators, or other special cases"""
        # Check for type hints
        type_hint_pattern = rf':\s*{re.escape(import_name)}\b'
        if re.search(type_hint_pattern, content):
            return True
        
        # Check for function return type hints
        return_pattern = rf'->\s*{re.escape(import_name)}\b'
        if re.search(return_pattern, content):
            return True
        
        # Check for decorators
        decorator_pattern = rf'@\s*{re.escape(import_name)}\b'
        if re.search(decorator_pattern, content):
            return True
        
        # Check for class inheritance
        class_pattern = rf'class\s+\w+\([^)]*{re.escape(import_name)}[^)]*\)'
        if re.search(class_pattern, content):
            return True
        
        # Check for docstrings or string references
        string_pattern = rf'["\'][^"\']*{re.escape(import_name)}[^"\']*["\']'
        if re.search(string_pattern, content):
            return True
        
        return False
    
    def analyze_directory(self) -> Dict:
        """Analyze all Python files in the directory"""
        results = {
            'python_files': [],
            'summary': {
                'total_python_files': 0,
                'python_files_with_unused_imports': 0,
                'total_unused_python_imports': 0
            }
        }
        
        # Only analyze specific directories, exclude .venv and other system dirs
        target_dirs = ['backend', 'tests', 'frontend']
        
        for target_dir in target_dirs:
            dir_path = self.root_dir / target_dir
            if not dir_path.exists():
                continue
                
            for py_file in dir_path.rglob('*.py'):
                if '__pycache__' in str(py_file) or '.venv' in str(py_file):
                    continue
                
                results['summary']['total_python_files'] += 1
                unused_imports = self.analyze_python_file(py_file)
                
                if unused_imports:
                    results['summary']['python_files_with_unused_imports'] += 1
                    results['summary']['total_unused_python_imports'] += len(unused_imports)
                    results['python_files'].append({
                        'file': str(py_file.relative_to(self.root_dir)),
                        'unused_imports': unused_imports
                    })
        
        return results

def main():
    root_dir = Path(__file__).parent
    analyzer = UnusedImportAnalyzer(root_dir)
    
    print("Analyzing unused imports in hypersend project...")
    print("=" * 60)
    
    results = analyzer.analyze_directory()
    
    # Print Python results
    print("\nPYTHON FILES WITH UNUSED IMPORTS:")
    print("-" * 40)
    
    if results['python_files']:
        for file_info in results['python_files']:
            print(f"\n{file_info['file']}:")
            for unused in file_info['unused_imports']:
                if 'error' in unused:
                    print(f"  ERROR: {unused['error']}")
                else:
                    if unused['type'] == 'import':
                        print(f"  Line {unused['line']}: import {unused['module']}")
                    else:  # from_import
                        alias_part = f" as {unused['alias']}" if unused['alias'] else ""
                        print(f"  Line {unused['line']}: from {unused['module']} import {unused['name']}{alias_part}")
    else:
        print("No unused imports found in Python files")
    
    # Print summary
    print("\nSUMMARY:")
    print("-" * 40)
    summary = results['summary']
    print(f"Python files analyzed: {summary['total_python_files']}")
    print(f"Python files with unused imports: {summary['python_files_with_unused_imports']}")
    print(f"Total unused Python imports: {summary['total_unused_python_imports']}")
    
    # Save detailed results to JSON
    output_file = root_dir / 'unused_imports_analysis.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")

if __name__ == '__main__':
    main()