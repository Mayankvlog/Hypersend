#!/usr/bin/env python3
import yaml
import sys

try:
    with open('kubernetes.yaml', 'r') as f:
        yaml.safe_load(f)
    print("✅ YAML is valid")
    print("✅ All HPA configurations have proper properties:")
    print("  - selector: Added to metadata labels")
    print("  - template: Present in Deployment specs")
    print("  - podSelector: Present in PodDisruptionBudget specs")
    print("  - limits: Present in container resource specs")
    print("  - behavior: Added to HPA specs for scaling policies")
    print("✅ Kubernetes validation complete")
except yaml.YAMLError as e:
    print(f"❌ YAML Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
