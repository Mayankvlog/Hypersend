import pytest
import os
from pathlib import Path

# Check if frontend assets exist
frontend_path = Path(__file__).parent.parent / "frontend"
dart_assets_exist = (
    (frontend_path / "lib").exists() and 
    (frontend_path / "pubspec.yaml").exists()
)

if not dart_assets_exist:
    pytest.skip(
        "Frontend Dart assets are not present in this backend-only workspace; skipping Contact Us removal checks.",
        allow_module_level=True,
    )
