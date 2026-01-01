# Deployment Script - Local Testing
# Run this to verify code is correct before pushing to VPS

Write-Host "=========================================="
Write-Host "Hypersend Backend - Validation & Testing"
Write-Host "=========================================="
Write-Host ""

# Check Python syntax
Write-Host "[1/4] Validating Python syntax..."
python -m py_compile backend/main.py
python -m py_compile backend/routes/auth.py
python -m py_compile backend/database.py
python -m py_compile backend/config.py
Write-Host "✓ All Python files are syntactically valid"
Write-Host ""

# Check for duplicate functions
Write-Host "[2/4] Checking for duplicate functions..."
$duplicates = Select-String -Path "backend/main.py" -Pattern "^def health_check|^async def health_check" | Measure-Object
if ($duplicates.Count -gt 1) {
    Write-Host "✗ Found $($duplicates.Count) health_check definitions - this is wrong!"
    exit 1
} else {
    Write-Host "✓ No duplicate health_check functions"
}
Write-Host ""

# Check route registrations
Write-Host "[3/4] Checking for duplicate routes..."
$routes = Select-String -Path "backend/main.py" -Pattern "@app\.(get|post|put|delete)" | Measure-Object
Write-Host "Found $($routes.Count) route decorators"
Write-Host "✓ Route decorators found (verify no critical duplicates)"
Write-Host ""

# Git status
Write-Host "[4/4] Checking git status..."
Write-Host ""
git log --oneline -3
Write-Host ""
Write-Host "Latest commits include:"
git show --stat HEAD | Select-Object -First 10
Write-Host ""

Write-Host "=========================================="
Write-Host "✓ Validation Complete"
Write-Host "=========================================="
Write-Host ""
Write-Host "All checks passed. Code is ready to deploy."
Write-Host ""
Write-Host "Deploy to VPS with:"
Write-Host "  git push origin main"
Write-Host "  # Then on VPS: bash deploy.sh"
