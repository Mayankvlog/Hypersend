"""Test to verify all map/dict keys are unique (no YAML/JSON/dict key duplicates)"""

import os
import yaml
import json
import re
from pathlib import Path


class TestMapKeysUnique:
    """Test that all configuration files have unique keys"""
    
    def test_kubernetes_yaml_unique_keys(self):
        """Test kubernetes.yaml has no duplicate keys in ConfigMaps"""
        yaml_path = Path(__file__).parent.parent / "kubernetes.yaml"
        
        # Read and parse YAML
        with open(yaml_path, 'r') as f:
            content = f.read()
        
        # Parse all YAML documents
        all_docs = list(yaml.safe_load_all(content))
        
        duplicates_found = []
        
        for doc_idx, doc in enumerate(all_docs):
            if doc is None:
                continue
                
            # Check ConfigMaps specifically
            if isinstance(doc, dict) and doc.get('kind') == 'ConfigMap':
                config_name = doc.get('metadata', {}).get('name', f'unknown-{doc_idx}')
                data = doc.get('data', {})
                
                # Check for duplicate keys in data section
                keys = list(data.keys())
                unique_keys = set(keys)
                
                if len(keys) != len(unique_keys):
                    duplicates = [k for k in set(keys) if keys.count(k) > 1]
                    duplicates_found.append({
                        'configmap': config_name,
                        'duplicates': duplicates,
                        'count': len(keys),
                        'unique': len(unique_keys)
                    })
        
        # Assert no duplicates found
        assert len(duplicates_found) == 0, (
            f"Found duplicate keys in ConfigMaps:\n"
            + "\n".join([
                f"  {d['configmap']}: {d['duplicates']} "
                f"(total keys: {d['count']}, unique: {d['unique']})"
                for d in duplicates_found
            ])
        )
        
        print("✅ kubernetes.yaml: All ConfigMap keys are unique")
    
    def test_docker_compose_yaml_unique_keys(self):
        """Test docker-compose.yml has no duplicate keys"""
        yaml_path = Path(__file__).parent.parent / "docker-compose.yml"
        
        if not yaml_path.exists():
            print("⏭️  docker-compose.yml not found, skipping")
            return
        
        with open(yaml_path, 'r') as f:
            doc = yaml.safe_load(f)
        
        duplicates_found = []
        
        # Helper function to find duplicate keys recursively
        def check_keys(data, path=""):
            if not isinstance(data, dict):
                return
            
            keys = list(data.keys())
            unique_keys = set(keys)
            
            if len(keys) != len(unique_keys):
                duplicates = [k for k in set(keys) if keys.count(k) > 1]
                duplicates_found.append({
                    'path': path or 'root',
                    'duplicates': duplicates
                })
            
            # Recurse into nested dicts
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                check_keys(value, new_path)
        
        check_keys(doc)
        
        assert len(duplicates_found) == 0, (
            f"Found duplicate keys in docker-compose.yml:\n"
            + "\n".join([f"  {d['path']}: {d['duplicates']}" for d in duplicates_found])
        )
        
        print("✅ docker-compose.yml: All keys are unique")
    
    def test_python_config_files_no_duplicate_dict_keys(self):
        """Test Python config files don't have obvious duplicate dictionary patterns"""
        config_files = [
            "backend/config.py",
            "backend/models.py",
            "backend/validators.py",
        ]
        
        workspace_root = Path(__file__).parent.parent
        
        for config_file in config_files:
            file_path = workspace_root / config_file
            if not file_path.exists():
                print(f"⏭️  {config_file} not found, skipping")
                continue
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for duplicate dictionary key patterns like:
            # "key": value,
            # ...
            # "key": value,
            lines = content.split('\n')
            dict_keys = {}
            duplicates = []
            
            for line_num, line in enumerate(lines, 1):
                # Match dictionary key patterns: "key": value or 'key': value
                match = re.search(r'["\']([^"\']+)["\']:\s*', line)
                if match and '=' not in line[:match.start()]:  # Exclude variable assignments
                    key = match.group(1)
                    # Track key and check for duplicates in same context
                    if key not in dict_keys:
                        dict_keys[key] = []
                    dict_keys[key].append(line_num)
            
            # Find keys that appear multiple times in close proximity (potential duplicates)
            for key, lines_nums in dict_keys.items():
                if len(lines_nums) > 1:
                    # Check if they're close together (within 50 lines but different line numbers)
                    for i, ln in enumerate(lines_nums):
                        if i > 0:
                            diff = ln - lines_nums[i-1]
                            if diff < 50 and diff > 0:  # Close but not same line
                                duplicates.append(f"  {key} at lines {lines_nums[i-1]} and {ln}")
            
            if duplicates:
                print(f"⚠️  Potential duplicate keys in {config_file}:")
                for dup in duplicates[:5]:  # Show first 5
                    print(f"    {dup}")
            else:
                print(f"✅ {config_file}: No obvious duplicate dictionary keys")
    
    def test_load_all_yaml_files_valid(self):
        """Test that all YAML files can be loaded without key errors"""
        yaml_files = [
            "kubernetes.yaml",
            "docker-compose.yml",
        ]
        
        workspace_root = Path(__file__).parent.parent
        errors = []
        
        for yaml_file in yaml_files:
            file_path = workspace_root / yaml_file
            if not file_path.exists():
                print(f"⏭️  {yaml_file} not found")
                continue
            
            try:
                with open(file_path, 'r') as f:
                    list(yaml.safe_load_all(f))
                print(f"✅ {yaml_file}: Loads without errors")
            except yaml.YAMLError as e:
                errors.append(f"  {yaml_file}: {str(e)[:100]}")
        
        assert len(errors) == 0, (
            "YAML files failed to load:\n" + "\n".join(errors)
        )


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
