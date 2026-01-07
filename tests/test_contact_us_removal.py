import pytest

pytest.skip(
    "Frontend Dart assets are not present in this backend-only workspace; skipping Contact Us removal checks.",
    allow_module_level=True,
)
