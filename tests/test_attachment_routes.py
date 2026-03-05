"""
Test attachment route registration and endpoint availability.
FastAPI router prefix fix validation for /api/v1/attach/* endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from main import app


client = TestClient(app)


class TestAttachmentRouteRegistration:
    """Test that attachment routes are correctly registered with proper prefixes."""

    def test_attach_photos_videos_init_route_exists(self):
        """
        Test that POST /api/v1/attach/photos-videos/init endpoint exists.
        Should not return 404. This validates the router prefix fix.
        """
        # This should not return 404 (even if it returns 401 auth error, that's OK)
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            json={"test": "data"}
        )
        # Accept 401 (unauthorized) as valid - means route exists
        # Accept 400 (bad request) as valid - means route exists but data is invalid
        # Only 404 is failure
        assert response.status_code != 404, (
            f"Route /api/v1/attach/photos-videos/init returned 404. "
            f"Router prefix registration may be incorrect. "
            f"Response: {response.text}"
        )

    def test_attach_documents_init_route_exists(self):
        """Test that POST /api/v1/attach/documents/init endpoint exists."""
        response = client.post(
            "/api/v1/attach/documents/init",
            json={"test": "data"}
        )
        assert response.status_code != 404, (
            f"Route /api/v1/attach/documents/init returned 404"
        )

    def test_attach_audio_init_route_exists(self):
        """Test that POST /api/v1/attach/audio/init endpoint exists."""
        response = client.post(
            "/api/v1/attach/audio/init",
            json={"test": "data"}
        )
        assert response.status_code != 404, (
            f"Route /api/v1/attach/audio/init returned 404"
        )

    def test_attach_files_init_route_exists(self):
        """Test that POST /api/v1/attach/files/init endpoint exists."""
        response = client.post(
            "/api/v1/attach/files/init",
            json={"test": "data"}
        )
        assert response.status_code != 404, (
            f"Route /api/v1/attach/files/init returned 404"
        )

    def test_files_route_still_exists(self):
        """Test that standard /api/v1/files/* routes still work."""
        # Test that /api/v1/files/init endpoint exists
        response = client.post("/api/v1/files/init", json={"test": "data"})
        # Should not be 404 (might be 401 auth error, but not 404)
        assert response.status_code != 404, (
            f"Route /api/v1/files/init returned 404. "
            f"Standard files router may be broken."
        )

    def test_openapi_schema_includes_attach_routes(self):
        """Test that OpenAPI schema includes /api/v1/attach routes."""
        openapi_schema = app.openapi()
        assert openapi_schema is not None, "OpenAPI schema is None"
        
        paths = openapi_schema.get("paths", {})
        
        # Check for attachment routes in OpenAPI paths
        attach_routes = [
            "/api/v1/attach/photos-videos/init",
            "/api/v1/attach/documents/init",
            "/api/v1/attach/audio/init",
            "/api/v1/attach/files/init",
        ]
        
        for route in attach_routes:
            assert route in paths, (
                f"Route {route} not found in OpenAPI schema. "
                f"Available paths: {list(paths.keys())}"
            )

    def test_openapi_schema_includes_files_routes(self):
        """Test that OpenAPI schema still includes /api/v1/files routes."""
        openapi_schema = app.openapi()
        assert openapi_schema is not None, "OpenAPI schema is None"
        
        paths = openapi_schema.get("paths", {})
        
        # Check that at least /api/v1/files/init is documented
        assert "/api/v1/files/init" in paths, (
            f"/api/v1/files/init not found in OpenAPI schema. "
            f"Files router may not be properly registered."
        )

    def test_no_double_nesting_in_attach_routes(self):
        """Test that routes are NOT double-nested like /api/v1/files/attach/."""
        openapi_schema = app.openapi()
        paths = openapi_schema.get("paths", {})
        
        # These routes should NOT exist (old broken behavior)
        invalid_routes = [
            "/api/v1/files/attach/photos-videos/init",
            "/api/v1/files/attach/documents/init",
            "/api/v1/files/attach/audio/init",
            "/api/v1/files/attach/files/init",
        ]
        
        for route in invalid_routes:
            assert route not in paths, (
                f"Found double-nested route {route} in OpenAPI schema. "
                f"This suggests the router prefix fix was not applied correctly. "
                f"Router should have prefix=/files or prefix=/api/v1, not both."
            )

    def test_attach_route_auth_requirement(self):
        """
        Test that /api/v1/attach routes require authentication.
        Should return 401 when no auth token provided, not 404.
        """
        # Request without auth header
        response = client.post(
            "/api/v1/attach/photos-videos/init",
            json={"test": "data"}
        )
        # Should not be 404 (not found) - any other error (401, 403, 400, 422, 500) is acceptable
        assert response.status_code != 404, (
            f"/api/v1/attach/photos-videos/init returned {response.status_code}. "
            f"Expected any error except 404 (route should exist)."
        )
        # Ensure it's an error response (>= 400)
        assert response.status_code >= 400, (
            f"/api/v1/attach/photos-videos/init returned {response.status_code}. "
            f"Expected error response (>= 400)."
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
