#!/bin/bash
# Diagnostic script to check backend container logs and health

echo "=== Backend Container Status ==="
docker compose ps backend

echo ""
echo "=== Last 50 lines of backend logs ==="
docker logs --tail 50 hypersend_backend

echo ""
echo "=== Checking if backend is responding ==="
docker exec hypersend_backend curl -f http://127.0.0.1:8000/health 2>/dev/null || echo "Health check failed"

echo ""
echo "=== Python import test inside container ==="
docker exec hypersend_backend python3 -c "import sys; print('Python path:', sys.path); from backend import main; print('Import successful')" 2>&1 || echo "Import test failed"
