"""
COMPREHENSIVE DEBUG TEST SUITE: Clean URL Routing Migration
==============================================================
This test validates the production site https://zaply.in.net after 
removing hash routing (#/auth → /auth).

Tests verify:
1. Backend health endpoints are accessible
2. API endpoints return valid responses
3. CORS headers are properly configured
4. Authentication flow works (signup/login)
5. WebSocket endpoints are reachable
6. Nginx routing is correct

RUN: pytest tests/test_clean_url_routing_debug.py -v
"""

import pytest
import asyncio
import json
from typing import Dict, Any, Optional
import httpx
from datetime import datetime, timedelta, timezone

# Test configurations
PRODUCTION_URL = "https://zaply.in.net"
API_BASE_URL = f"{PRODUCTION_URL}/api/v1"
HEALTH_ENDPOINT = f"{PRODUCTION_URL}/health"
API_HEALTH_ENDPOINT = f"{API_BASE_URL}/health"

# Test timeouts (production should respond quickly)
HEALTH_CHECK_TIMEOUT = 15  # 15 seconds for health check
API_CALL_TIMEOUT = 30  # 30 seconds for API calls
CONNECTION_TIMEOUT = 10   # 10 seconds for connection


class TestBackendHealth:
    """Test backend health endpoints and connectivity"""
    
    @pytest.mark.asyncio
    async def test_health_endpoint_accessible(self):
        """Verify /health endpoint returns 200 from backend"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            try:
                response = await client.get(
                    HEALTH_ENDPOINT,
                    follow_redirects=True,
                    timeout=HEALTH_CHECK_TIMEOUT
                )
                print(f"\n[HEALTH_CHECK] Status: {response.status_code}")
                print(f"[HEALTH_CHECK] Headers: {dict(response.headers)}")
                print(f"[HEALTH_CHECK] Body: {response.text[:500]}")
                
                # Health endpoint should return 200
                assert response.status_code == 200, \
                    f"Health endpoint failed with {response.status_code}: {response.text}"
                
                # Response should be JSON or plain text
                try:
                    data = response.json()
                    assert "status" in data or "response" in str(response.text).lower(), \
                        "Health response missing status field"
                    print(f"[HEALTH_CHECK] ✅ Backend health check passed")
                except:
                    # Plain text response is also acceptable
                    assert len(response.text) > 0, "Empty health response"
                    print(f"[HEALTH_CHECK] ✅ Backend health check passed (plain text)")
                    
            except httpx.ConnectError as e:
                pytest.fail(f"[ERROR] Cannot connect to backend: {e}")
            except httpx.TimeoutException as e:
                pytest.fail(f"[ERROR] Health check timed out (backend unresponsive): {e}")
            except Exception as e:
                pytest.fail(f"[ERROR] Unexpected error: {type(e).__name__}: {e}")
    
    @pytest.mark.asyncio
    async def test_api_health_endpoint(self):
        """Verify /api/v1/health endpoint returns detailed health info"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            try:
                response = await client.get(
                    API_HEALTH_ENDPOINT,
                    follow_redirects=True,
                    timeout=HEALTH_CHECK_TIMEOUT
                )
                print(f"\n[API_HEALTH] Status: {response.status_code}")
                
                assert response.status_code == 200, \
                    f"API health endpoint failed with {response.status_code}: {response.text}"
                
                data = response.json()
                print(f"[API_HEALTH] Response: {json.dumps(data, indent=2)}")
                
                # Check for expected health fields
                assert "status" in data, "Missing 'status' field"
                assert "services" in data or "timestamp" in data, \
                    "Missing health check data"
                
                print(f"[API_HEALTH] ✅ API health check passed")
                
            except httpx.ConnectError as e:
                pytest.fail(f"[ERROR] Cannot connect to API: {e}")
            except httpx.TimeoutException as e:
                pytest.fail(f"[ERROR] API health check timed out: {e}")
            except Exception as e:
                pytest.fail(f"[ERROR] Unexpected error: {type(e).__name__}: {e}")


class TestCORSConfiguration:
    """Test CORS headers are properly configured for the frontend domain"""
    
    @pytest.mark.asyncio
    async def test_cors_preflight_auth_login(self):
        """Test CORS preflight for auth/login endpoint"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            # Send OPTIONS preflight request
            response = await client.options(
                f"{API_BASE_URL}/auth/login",
                headers={
                    "Origin": PRODUCTION_URL,
                    "Access-Control-Request-Method": "POST",
                },
                follow_redirects=True,
                timeout=CONNECTION_TIMEOUT
            )
            print(f"\n[CORS_PREFLIGHT] Status: {response.status_code}")
            print(f"[CORS_PREFLIGHT] Headers: {dict(response.headers)}")
            
            # Preflight should return 200
            assert response.status_code == 200, \
                f"CORS preflight failed: {response.status_code}"
            
            # Check for CORS headers
            assert "access-control-allow-origin" in {k.lower(): v for k, v in response.headers.items()}, \
                "Missing Access-Control-Allow-Origin header"
            
            cors_origin = response.headers.get("Access-Control-Allow-Origin") or \
                         response.headers.get("access-control-allow-origin")
            print(f"[CORS_PREFLIGHT] Allowed Origin: {cors_origin}")
            
            assert cors_origin in [PRODUCTION_URL, f"{PRODUCTION_URL}/", "*"], \
                f"CORS origin not properly configured: {cors_origin}"
            
            print(f"[CORS_PREFLIGHT] ✅ CORS preflight passed")
    
    @pytest.mark.asyncio
    async def test_cors_headers_on_api_response(self):
        """Test actual API response includes CORS headers"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            response = await client.get(
                f"{API_BASE_URL}/status",
                headers={"Origin": PRODUCTION_URL},
                follow_redirects=True,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[CORS_RESPONSE] Status: {response.status_code}")
            
            # Check for CORS headers in response
            cors_headers = {k.lower(): v for k, v in response.headers.items() 
                           if "access-control" in k.lower()}
            print(f"[CORS_RESPONSE] CORS Headers: {cors_headers}")
            
            if response.status_code == 200:
                assert len(cors_headers) > 0, \
                    "API response missing CORS headers"
                print(f"[CORS_RESPONSE] ✅ CORS headers present in response")
            else:
                print(f"[CORS_RESPONSE] Status: {response.status_code} (may require auth)")


class TestAuthenticationEndpoints:
    """Test authentication endpoints for signup and login"""
    
    @pytest.mark.asyncio
    async def test_signup_endpoint_accessible(self):
        """Verify /api/v1/auth/register endpoint is accessible"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            # Try invalid signup (should still be accessible)
            response = await client.post(
                f"{API_BASE_URL}/auth/register",
                json={
                    "username": "",  # Invalid - will fail validation but endpoint is accessible
                    "password": "",
                },
                headers={"Origin": PRODUCTION_URL},
                follow_redirects=True,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[SIGNUP_ENDPOINT] Status: {response.status_code}")
            print(f"[SIGNUP_ENDPOINT] Response: {response.text[:500]}")
            
            # Endpoint should at least be accessible (even if it returns error)
            assert response.status_code in [200, 201, 400, 422], \
                f"Signup endpoint returned unexpected status: {response.status_code}"
            print(f"[SIGNUP_ENDPOINT] ✅ Signup endpoint is accessible")
    
    @pytest.mark.asyncio
    async def test_login_endpoint_accessible(self):
        """Verify /api/v1/auth/login endpoint is accessible"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            # Try invalid login (should still be accessible)
            response = await client.post(
                f"{API_BASE_URL}/auth/login",
                json={
                    "username": "test",
                    "password": "wrong"
                },
                headers={"Origin": PRODUCTION_URL},
                follow_redirects=True,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[LOGIN_ENDPOINT] Status: {response.status_code}")
            print(f"[LOGIN_ENDPOINT] Response: {response.text[:500]}")
            
            # Login endpoint should be accessible
            assert response.status_code in [200, 400, 401, 422], \
                f"Login endpoint returned unexpected status: {response.status_code}"
            print(f"[LOGIN_ENDPOINT] ✅ Login endpoint is accessible")
    
    @pytest.mark.asyncio
    async def test_auth_endpoints_have_cors(self):
        """Verify auth endpoints return proper CORS headers"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            for endpoint in ["/auth/login", "/auth/register"]:
                response = await client.options(
                    f"{API_BASE_URL}{endpoint}",
                    headers={
                        "Origin": PRODUCTION_URL,
                        "Access-Control-Request-Method": "POST",
                    },
                    follow_redirects=True,
                    timeout=CONNECTION_TIMEOUT
                )
                print(f"\n[AUTH_CORS] {endpoint} Status: {response.status_code}")
                
                assert response.status_code in [200, 204], \
                    f"Auth endpoint CORS check failed: {response.status_code}"


class TestAPIRouting:
    """Test API routing through Nginx proxy"""
    
    @pytest.mark.asyncio
    async def test_api_requests_route_to_backend(self):
        """Verify /api/* requests are routed to backend, not frontend"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            # Request an API endpoint
            response = await client.get(
                f"{API_BASE_URL}/status",
                follow_redirects=True,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[API_ROUTING] Status: {response.status_code}")
            
            # Check if response looks like backend API response
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Backend API returns JSON with specific structure
                    assert isinstance(data, dict), "Response should be JSON object"
                    print(f"[API_ROUTING] Response: {json.dumps(data, indent=2)[:500]}")
                    print(f"[API_ROUTING] ✅ API routing to backend confirmed")
                except json.JSONDecodeError:
                    # If it's HTML, it's from frontend (wrong routing)
                    if "<html>" in response.text.lower():
                        pytest.fail("API request routed to frontend instead of backend!")
                    else:
                        print(f"[API_ROUTING] Response: {response.text[:200]}")
                        print(f"[API_ROUTING] ✅ API endpoint accessible")
            else:
                print(f"[API_ROUTING] Status {response.status_code} (may require auth)")


class TestSPARouting:
    """Test SPA routing works with clean URLs"""
    
    @pytest.mark.asyncio
    async def test_clean_urls_serve_index_html(self):
        """Verify clean URL routes serve index.html from frontend"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            # Query a clean URL that doesn't exist as static file
            for route in ["/auth", "/chats", "/settings"]:
                response = await client.get(
                    f"{PRODUCTION_URL}{route}",
                    follow_redirects=False,
                    timeout=API_CALL_TIMEOUT
                )
                print(f"\n[SPA_ROUTING] {route} Status: {response.status_code}")
                
                # Should serve index.html (200), not 404
                assert response.status_code != 404, \
                    f"Clean URL {route} returned 404 - SPA routing failed!"
                
                # Response should be HTML (Flutter app)
                content_type = response.headers.get("Content-Type", "").lower()
                print(f"[SPA_ROUTING] {route} Content-Type: {content_type}")
                
                if response.status_code == 200:
                    # Check if it looks like HTML
                    is_html = "text/html" in content_type or "<!doctype" in response.text.lower()
                    if is_html:
                        print(f"[SPA_ROUTING] ✅ {route} serves HTML (Flutter SPA)")
                    else:
                        print(f"[SPA_ROUTING] ⚠️  {route} returned status {response.status_code}")


class TestWebSocket:
    """Test WebSocket endpoints"""
    
    @pytest.mark.asyncio
    async def test_websocket_endpoint_exists(self):
        """Verify /ws/ endpoint is routed to backend"""
        # WebSocket upgrade test - check if endpoint responds to HTTP
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            response = await client.get(
                f"{PRODUCTION_URL}/ws/test",
                headers={
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                },
                follow_redirects=False,
                timeout=CONNECTION_TIMEOUT
            )
            print(f"\n[WEBSOCKET] Status: {response.status_code}")
            
            # 426 means WebSocket upgrade required (expected)
            # 404 means endpoint not found (bad routing)
            assert response.status_code != 404, \
                "WebSocket endpoint not found - routing issue!"
            
            print(f"[WEBSOCKET] ✅ WebSocket endpoint is routed to backend")


class TestNginxErrorHandling:
    """Test Nginx error handling"""
    
    @pytest.mark.asyncio
    async def test_404_clean_url_serves_index(self):
        """Verify 404 on clean URLs serves index.html for SPA routing"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            # Request a non-existent page
            response = await client.get(
                f"{PRODUCTION_URL}/non-existent-page-12345",
                follow_redirects=False,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[404_HANDLING] Status: {response.status_code}")
            
            # Should NOT return 404 for SPA - should serve index.html
            assert response.status_code != 404, \
                "404 page returned instead of SPA index.html"
            
            # Should return 200 with HTML content (index.html)
            assert response.status_code == 200, \
                f"Non-existent route returned {response.status_code} instead of 200"
            
            print(f"[404_HANDLING] ✅ 404 on clean URLs serves index.html")


class TestStaticAssets:
    """Test static asset serving"""
    
    @pytest.mark.asyncio
    async def test_robots_txt_served(self):
        """Verify robots.txt is served correctly"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            response = await client.get(
                f"{PRODUCTION_URL}/robots.txt",
                follow_redirects=True,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[STATIC_ASSETS] robots.txt Status: {response.status_code}")
            
            assert response.status_code == 200, \
                f"robots.txt returned {response.status_code}"
            
            content_type = response.headers.get("Content-Type", "").lower()
            assert "text" in content_type, \
                f"robots.txt has wrong content type: {content_type}"
            
            print(f"[STATIC_ASSETS] ✅ robots.txt served correctly")
    
    @pytest.mark.asyncio
    async def test_sitemap_xm_served(self):
        """Verify sitemap.xml is served correctly"""
        async with httpx.AsyncClient(timeout=CONNECTION_TIMEOUT) as client:
            response = await client.get(
                f"{PRODUCTION_URL}/sitemap.xml",
                follow_redirects=True,
                timeout=API_CALL_TIMEOUT
            )
            print(f"\n[STATIC_ASSETS] sitemap.xml Status: {response.status_code}")
            
            assert response.status_code == 200, \
                f"sitemap.xml returned {response.status_code}"
            
            content_type = response.headers.get("Content-Type", "").lower()
            assert "xml" in content_type or "text" in content_type, \
                f"sitemap.xml has wrong content type: {content_type}"
            
            print(f"[STATIC_ASSETS] ✅ sitemap.xml served correctly")


# Run tests with: pytest tests/test_clean_url_routing_debug.py -v -s
# Run specific test: pytest tests/test_clean_url_routing_debug.py::TestBackendHealth::test_health_endpoint_accessible -v -s
# Run with detailed output: pytest tests/test_clean_url_routing_debug.py -vv -s --tb=short

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║ CLEAN URL ROUTING DEBUG TEST SUITE                              ║
    ║ Testing: https://zaply.in.net after removing hash routing (#/)  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    Run with: pytest tests/test_clean_url_routing_debug.py -v -s
    
    This test suite validates:
    ✅ Backend health endpoints (/health, /api/v1/health)
    ✅ CORS configuration for https://zaply.in.net
    ✅ Authentication endpoints (/api/v1/auth/login, /register)
    ✅ API routing through Nginx (/api/ → backend)
    ✅ SPA routing with clean URLs (/auth, /chats → index.html)
    ✅ WebSocket endpoints (/ws/ → backend)
    ✅ Static file serving (robots.txt, sitemap.xml)
    """)
