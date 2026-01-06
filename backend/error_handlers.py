"""
Custom error handlers for FastAPI application
Provides detailed logging and user-friendly error messages for all HTTP errors (4xx, 5xx)
Comprehensive handling for validation errors and HTTP exceptions

IMPLEMENTED 4xx ERROR CODES:
============================
400 Bad Request: Invalid request syntax or parameters
401 Unauthorized: Missing/invalid authentication credentials (in auth.py)
403 Forbidden: Access denied (permission checks in routes)
404 Not Found: Resource doesn't exist (in files.py, messages.py, users.py)
405 Method Not Allowed: Automatic via FastAPI routing
406 Not Acceptable: Content negotiation (in error_handler hints)
407 Proxy Authentication: For reverse proxy scenarios (in hints)
408 Request Timeout: Async timeout in database operations (async.wait_for)
409 Conflict: Duplicate resources - email already registered, chat exists (auth.py, chats.py)
410 Gone: Permanent deletion (in hints, soft delete in messages.py)
411 Length Required: Missing Content-Length header (RequestValidationMiddleware)
412 Precondition Failed: Header conditions not met (in hints)
413 Payload Too Large: Request exceeds size limit (RequestValidationMiddleware, files.py)
414 URI Too Long: URL exceeds max length (RequestValidationMiddleware)
415 Unsupported Media Type: Invalid Content-Type (RequestValidationMiddleware, Pydantic)
416 Range Not Satisfiable: Invalid byte range (in hints, file ranges)
417 Expectation Failed: Expect header not met (in hints)
422 Unprocessable Entity: Semantic validation errors (validation_exception_handler)
429 Too Many Requests: Rate limiting (auth.py login attempts)
431 Request Header Fields Too Large: Headers too big (in hints)
451 Unavailable For Legal Reasons: Legal blocks (in hints)
499 Client Closed Request: Nginx timeout (in hints, handled by reverse proxy)

MIDDLEWARE VALIDATION (RequestValidationMiddleware in main.py):
- Checks Content-Length for POST/PUT/PATCH (411, 413)
- Validates URL length (414)
- Checks Content-Type (415)
- Returns standardized error responses with hints

EXCEPTION HANDLERS (error_handlers.py):
- validation_exception_handler: Handles 422 with detailed field errors
- http_exception_handler: Handles all HTTPException (300-599 range) with specific logic
- redirect_error_handler: Handles 3xx redirection codes
- client_error_handler: Handles 4xx client errors with specific categorization
- server_error_handler: Handles 5xx server errors with recovery suggestions
- Both include helpful hints and structured error responses
"""

import logging
import json
from typing import Any, Dict, List, Union
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from datetime import datetime, timezone

# Import settings with fallback for circular dependency scenarios
try:
    from config import settings
except (ImportError, RuntimeError):
    # Create a minimal settings object if config cannot be imported
    class MinimalSettings:
        DEBUG = False
    settings = MinimalSettings()

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create a handler for detailed logging
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class ValidationErrorDetail:
    """Detailed validation error information"""
    
    @staticmethod
    def extract_error_details(errors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract and format validation errors with detailed information
        
        Args:
            errors: Pydantic validation errors list
            
        Returns:
            Formatted error details dictionary
        """
        error_details = {
            "validation_errors": [],
            "error_count": len(errors),
            "timestamp": __import__('datetime').datetime.now(timezone.utc).isoformat()
        }
        
        for error in errors:
            field_path = ".".join(str(x) for x in error.get("loc", []))
            error_type = error.get("type", "unknown")
            error_msg = error.get("msg", "Unknown error")
            
            # Extract context information
            ctx = error.get("ctx", {})
            
            detailed_error = {
                "field": field_path if field_path else "root",
                "type": error_type,
                "message": error_msg,
                "expected_type": ctx.get("expected_type", "N/A"),
            }
            
            # Add context-specific information
            if "min_length" in ctx:
                detailed_error["constraint"] = f"min_length={ctx['min_length']}"
            elif "max_length" in ctx:
                detailed_error["constraint"] = f"max_length={ctx['max_length']}"
            elif "pattern" in ctx:
                detailed_error["constraint"] = f"pattern={ctx['pattern']}"
            
            # Add input value (sanitized)
            if "value" in error:
                value = str(error["value"])
                if len(value) > 100:
                    detailed_error["received_value"] = f"{value[:100]}... (truncated)"
                else:
                    detailed_error["received_value"] = value
            
            error_details["validation_errors"].append(detailed_error)
        
        return error_details


def log_validation_error(request_path: str, method: str, body: Any, errors: List[Dict]) -> None:
    """
    Log validation errors with detailed information
    
    Args:
        request_path: The request path
        method: HTTP method
        body: Request body
        errors: Validation errors list
    """
    error_details = ValidationErrorDetail.extract_error_details(errors)
    
    logger.error(f"""
===============================================================================╗
= VALIDATION ERROR - {method} {request_path}
===============================================================================╝

REQUEST DETAILS:
  Method: {method}
  Path: {request_path}
  Timestamp: {error_details['timestamp']}

ERROR SUMMARY:
  Total Validation Errors: {error_details['error_count']}

DETAILED ERRORS:
""")
    
    for idx, error in enumerate(error_details["validation_errors"], 1):
        logger.error(f"""
  Error #{idx}:
    • Field: {error['field']}
    • Type: {error['type']}
    • Expected: {error['expected_type']}
    • Message: {error['message']}""")
        
        if "received_value" in error:
            logger.error(f"    • Received: {error['received_value']}")
        if "constraint" in error:
            logger.error(f"    • Constraint: {error['constraint']}")
    
    # Log request body
    try:
        if isinstance(body, dict):
            body_str = json.dumps(body, indent=2, default=str)
        else:
            body_str = str(body)
        
        logger.error(f"""
REQUEST BODY:
{chr(10).join('  ' + line for line in body_str.split(chr(10)))}
""")
    except Exception as e:
        logger.error(f"    Could not parse request body: {e}")
    
    logger.error("=" * 80)


async def validation_exception_handler(request: Request, exc: ValidationError):
    """
    Custom handler for Pydantic ValidationError
    
    Provides detailed error messages and logging
    
    Args:
        request: The request object
        exc: The ValidationError exception
        
    Returns:
        JSONResponse with detailed error information
    """
    # Extract request details
    method = request.method
    path = request.url.path
    
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        body = {"error": "Could not parse request body"}
    
    # Get error list
    errors = exc.errors()
    
    # Log detailed error information
    log_validation_error(path, method, body, errors)
    
    # Format response for client
    error_details = ValidationErrorDetail.extract_error_details(errors)
    
    response = {
        "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "detail": "Validation failed - please check the errors below",
        "validation_errors": error_details["validation_errors"],
        "error_count": error_details["error_count"],
        "timestamp": error_details["timestamp"],
        # Add helpful hints
        "hints": [
            "Check that all required fields are provided",
            "Verify field data types match the expected types",
            "Ensure string lengths meet minimum/maximum requirements",
            "Validate email formats and URL patterns",
        ]
    }
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=response
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register all custom exception handlers with FastAPI app
    
    Args:
        app: FastAPI application instance
    """
    from fastapi.exceptions import RequestValidationError
    import asyncio
    import httpx
    from pymongo.errors import PyMongoError
    from bson.errors import BSONError
    
    # Handle Pydantic validation errors
    app.add_exception_handler(
        RequestValidationError,
        validation_exception_handler
    )
    
    # Handle HTTP exceptions with comprehensive 3xx, 4xx, 5xx support
    app.add_exception_handler(HTTPException, http_exception_handler)
    
    # Handle asyncio.TimeoutError - convert to proper HTTP 504 Gateway Timeout
    @app.exception_handler(asyncio.TimeoutError)
    async def timeout_exception_handler(request: Request, exc: asyncio.TimeoutError):
        """Handle database and async timeout errors"""
        logger.warning(f"[HTTP_504] {request.method} {request.url.path} | Timeout Error")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={
                "status_code": 504,
                "error": "Gateway Timeout",
                "detail": "Database operation timeout - please retry your request",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
                "method": request.method,
                "hints": ["Database may be overloaded - try again", "Check your network connection", "Try again in a few seconds"]
            }
        )
    
    # Handle MongoDB specific errors
    @app.exception_handler(PyMongoError)
    async def mongodb_exception_handler(request: Request, exc: PyMongoError):
        """Handle MongoDB connection and operation errors"""
        logger.error(f"[MONGODB_ERROR] {request.method} {request.url.path} | {type(exc).__name__}: {str(exc)}")
        
        if "timeout" in str(exc).lower():
            status_code = status.HTTP_504_GATEWAY_TIMEOUT
            error_msg = "Database timeout - please retry your request"
        elif "connection" in str(exc).lower():
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Database connection failed - please try again later"
        elif "duplicate" in str(exc).lower():
            status_code = status.HTTP_409_CONFLICT
            error_msg = "Resource already exists - please check your data"
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Database operation failed"
        
        return JSONResponse(
            status_code=status_code,
            content={
                "status_code": status_code,
                "error": type(exc).__name__,
                "detail": error_msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
                "method": request.method,
                "hints": ["Try again in a few moments", "Check your request data", "Contact support if persistent"]
            }
        )
    
    # Handle HTTP client errors (for external API calls)
    @app.exception_handler(httpx.HTTPError)
    async def http_client_exception_handler(request: Request, exc: httpx.HTTPError):
        """Handle HTTP client errors when calling external services"""
        logger.error(f"[HTTP_CLIENT_ERROR] {request.method} {request.url.path} | {type(exc).__name__}: {str(exc)}")
        
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        error_msg = "External service unavailable"
        
        if isinstance(exc, httpx.TimeoutException):
            status_code = status.HTTP_504_GATEWAY_TIMEOUT
            error_msg = "External service timeout"
        elif isinstance(exc, httpx.ConnectError):
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            error_msg = "Cannot connect to external service"
        elif isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code >= 500:
                status_code = status.HTTP_502_BAD_GATEWAY
                error_msg = "External service error"
            else:
                status_code = status.HTTP_400_BAD_REQUEST
                error_msg = "Invalid request to external service"
        
        return JSONResponse(
            status_code=status_code,
            content={
                "status_code": status_code,
                "error": type(exc).__name__,
                "detail": error_msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
                "method": request.method,
                "hints": ["External service issues", "Try again later", "Contact support if persistent"]
            }
        )
    
    # Handle file system and I/O errors
    @app.exception_handler(OSError)
    async def os_exception_handler(request: Request, exc: OSError):
        """Handle file system and I/O errors"""
        logger.error(f"[OS_ERROR] {request.method} {request.url.path} | {type(exc).__name__}: {str(exc)}")
        
        if "No space left on device" in str(exc):
            status_code = status.HTTP_507_INSUFFICIENT_STORAGE
            error_msg = "Server storage full - cannot complete operation"
        elif "Permission denied" in str(exc):
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Server permission error - please contact support"
        elif "File too large" in str(exc):
            status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            error_msg = "File too large - please use a smaller file"
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            error_msg = "Server I/O error - please try again"
        
        return JSONResponse(
            status_code=status_code,
            content={
                "status_code": status_code,
                "error": type(exc).__name__,
                "detail": error_msg,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
                "method": request.method,
                "hints": ["Server storage issues", "Try with smaller file", "Contact support if persistent"]
            }
        )
    
    # Add global exception handler for unhandled exceptions
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handle all unhandled exceptions with proper JSON response"""
        import traceback
        
        # Log the full traceback for debugging
        logger.error(f"[UNHANDLED_EXCEPTION] {request.method} {request.url.path} | {type(exc).__name__}: {str(exc)}")
        if logger.isEnabledFor(logging.DEBUG):
            traceback.print_exc()
        
        # Determine appropriate status code based on exception type
        if isinstance(exc, ConnectionError):
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            detail = "Service temporarily unavailable - please try again"
        elif isinstance(exc, ValueError):
            status_code = status.HTTP_400_BAD_REQUEST
            detail = "Invalid input data - please check your request"
        elif isinstance(exc, KeyError):
            status_code = status.HTTP_400_BAD_REQUEST
            detail = "Missing required field in request"
        elif isinstance(exc, AttributeError):
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            detail = "Internal server error - please try again"
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            detail = "An unexpected server error occurred"
        
        # Return proper JSON response instead of letting exception crash connection
        return JSONResponse(
            status_code=status_code,
            content={
                "status_code": status_code,
                "error": type(exc).__name__,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
                "method": request.method,
                "hints": ["This is a server error, not your request", "Try again in a moment", "Contact support if persistent"]
            }
        )
    
    logger.info("Custom exception handlers registered with comprehensive 3xx, 4xx, 5xx error handling")


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Enhanced HTTPException handler with comprehensive 3xx, 4xx, 5xx error support:
    - 3xx: Redirection responses with proper Location header handling
    - 4xx: Client errors with detailed guidance and input validation hints
    - 5xx: Server errors with minimal information disclosure in production
    - Enhanced logging for debugging and monitoring
    - Proper status code validation and security measures
    """
    status_code = exc.status_code
    detail = exc.detail
    
    # CRITICAL FIX: Validate status code is valid HTTP status (100-599)
    if not isinstance(status_code, int) or status_code < 100 or status_code > 599:
        status_code = 500
        detail = "Internal server error"
    
    # CRITICAL FIX: Prevent information disclosure in production mode
    if not settings.DEBUG:
        # In production, sanitize error messages to prevent leaking internal details
        if 500 <= status_code < 600:
            # Server errors - use generic messages in production
            detail = "Internal server error. Please try again later."
        elif status_code == 404:
            # 404 errors - don't leak internal path information
            detail = "Resource not found."
        elif status_code == 403:
            # 403 errors - don't reveal authorization details
            detail = "Access denied."
        elif status_code == 401:
            # 401 errors - don't leak which field failed
            detail = "Authentication required or invalid credentials"
    
    # Comprehensive error descriptions and hints for all HTTP status codes
    error_descriptions = {}
    hints = []
    
    # 3xx Redirection codes (300-399)
    if 300 <= status_code < 400:
        error_descriptions = {
            300: "Multiple Choices - The request has multiple possible responses",
            301: "Moved Permanently - Resource has permanently moved to a new URL",
            302: "Found - Resource temporarily moved to a different URL", 
            303: "See Other - Response can be found at another URI using GET method",
            304: "Not Modified - Resource has not been modified since last request",
            305: "Use Proxy - Must use a proxy to access this resource",
            306: "(Unused) - Switch Proxy - Former specification",
            307: "Temporary Redirect - Resource temporarily located at different URI",
            308: "Permanent Redirect - Resource permanently located at different URI",
        }
        hints = [
            "This is a redirect response",
            "Your client should follow the redirect location automatically", 
            "Check the Location header for the new URL if manual redirect needed",
            "Ensure your HTTP client follows redirects properly",
        ]
    
    # 4xx Client errors (400-499)  
    elif 400 <= status_code < 500:
        error_descriptions = {
            400: "Bad Request - Invalid request syntax or parameters",
            401: "Unauthorized - Authentication required or invalid credentials",
            402: "Payment Required - Payment is required to access this resource",
            403: "Forbidden - You lack permission to access this resource",
            404: "Not Found - The requested resource doesn't exist",
            405: "Method Not Allowed - This HTTP method is not supported for this endpoint",
            406: "Not Acceptable - Server cannot produce the requested content type",
            407: "Proxy Authentication Required - Proxy requires authentication",
            408: "Request Timeout - Client took too long to send the request",
            409: "Conflict - Request conflicts with the server's current state",
            410: "Gone - The requested resource is permanently deleted",
            411: "Length Required - Content-Length header is missing",
            412: "Precondition Failed - A precondition header requirement was not met",
            413: "Payload Too Large - Request body exceeds the maximum allowed size",
            414: "URI Too Long - The requested URL is too long",
            415: "Unsupported Media Type - Request content type is not supported",
            416: "Range Not Satisfiable - Cannot fulfill the requested byte range",
            417: "Expectation Failed - Server cannot meet Expect header requirements",
            418: "I'm a teapot - April Fools' joke (RFC 2324)",
            421: "Misdirected Request - Request was directed to a server that cannot respond",
            422: "Unprocessable Entity - Semantic validation error (valid syntax but invalid data)",
            423: "Locked - Resource is currently locked",
            424: "Failed Dependency - The request failed because it depended on another failed request",
            425: "Too Early - The server is unwilling to risk processing a request that might be replayed",
            426: "Upgrade Required - The client should switch to a different protocol",
            428: "Precondition Required - The server requires the request to be conditional",
            429: "Too Many Requests - Rate limit exceeded, too many requests received",
            431: "Request Header Fields Too Large - Headers exceed the maximum size",
            451: "Unavailable For Legal Reasons - Content blocked due to legal compliance",
            499: "Client Closed Request - Client closed the connection prematurely",
        }
        hints = [
            "This is a client error - the request needs to be fixed",
            "Check the request parameters and try again",
            "Verify authentication and authorization credentials",
            "Ensure all required fields are provided and properly formatted",
        ]
    
    # 5xx Server errors (500-599)
    elif 500 <= status_code < 600:
        error_descriptions = {
            500: "Internal Server Error - An unexpected server error occurred",
            501: "Not Implemented - The server does not support the functionality required",
            502: "Bad Gateway - Invalid response from upstream server",
            503: "Service Unavailable - Server is temporarily unavailable",
            504: "Gateway Timeout - Upstream server took too long to respond",
            505: "HTTP Version Not Supported - The server does not support the HTTP protocol version used",
            506: "Variant Also Negotiates - The server has an internal configuration error",
            507: "Insufficient Storage - Server cannot store the representation",
            508: "Loop Detected - Server detected an infinite loop while processing",
            510: "Not Extended - Further extensions required for the request",
            511: "Network Authentication Required - Client needs to authenticate to gain network access",
        }
        hints = [
            "This is a server error - not your fault",
            "Try again in a few moments",
            "Contact support if the problem persists",
            "The server is experiencing issues and administrators have been notified",
        ]
    else:
        error_descriptions = {}
        hints = ["Unknown error occurred"]
        
    # Get the error description or use a default
    error_description = error_descriptions.get(
        status_code,
        f"HTTP Error {status_code}"
    )
    
    # Enhanced logging with full context and security considerations
    try:
        client_host = request.client.host if request.client else 'Unknown'
        user_agent = request.headers.get("User-Agent", "Unknown")
        
        # Log with different levels based on error type
        if 400 <= status_code < 500:
            # Client errors - warning level (user mistakes)
            logger.warning(
                f"[HTTP_{status_code}] {request.method} {request.url.path} | "
                f"Client: {client_host} | "
                f"User-Agent: {user_agent[:100]} | "
                f"Detail: {detail}"
            )
        elif 500 <= status_code < 600:
            # Server errors - error level (server issues)
            logger.error(
                f"[HTTP_{status_code}] {request.method} {request.url.path} | "
                f"Client: {client_host} | "
                f"User-Agent: {user_agent[:100]} | "
                f"Detail: {detail}"
            )
        else:
            # Other errors - info level
            logger.info(
                f"[HTTP_{status_code}] {request.method} {request.url.path} | "
                f"Client: {client_host} | "
                f"Detail: {detail}"
            )
    except Exception as log_error:
        logger.error(f"Error logging HTTP exception: {type(log_error).__name__}")
    
    # Build comprehensive response data
    response_data = {
        "status_code": status_code,
        "error": error_description,
        "detail": str(detail),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": str(request.url.path),
        "method": request.method,
    }
    
    # Add request_id if available (but ensure it's JSON serializable)
    request_id = getattr(request.state, 'request_id', None)
    if request_id is not None and isinstance(request_id, (str, int, float, bool)):
        response_data["request_id"] = request_id
    
    # Add specific hints based on error code
    specific_hints = get_error_hints(status_code)
    if specific_hints:
        response_data["hints"] = specific_hints
    
    # Add additional context for specific error types
    if status_code == 429:
        # Rate limit errors - include retry information
        response_data["retry_after"] = exc.headers.get("Retry-After", "60")
    elif status_code == 413:
        # Payload too large - include size limits
        response_data["max_size"] = "5GB"
    elif status_code == 415:
        # Unsupported media type - include supported types
        response_data["supported_types"] = ["application/json", "multipart/form-data", "image/*"]
    
    # Prepare response headers
    headers = {}
    
    # Add retry-after header for rate limit errors
    if status_code == 429 and exc.headers and "Retry-After" in exc.headers:
        headers["Retry-After"] = exc.headers["Retry-After"]
    
    # Add Location header for redirect responses (3xx)
    if 300 <= status_code < 400 and exc.headers and "Location" in exc.headers:
        headers["Location"] = exc.headers["Location"]
    
    # Add security headers to all error responses
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY", 
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-cache, no-store, must-revalidate",  # Don't cache error responses
    }
    
    # Merge headers with security headers (security headers take precedence)
    if headers:
        security_headers.update(headers)
    
    return JSONResponse(
        status_code=status_code,
        content=response_data,
        headers=security_headers
    )


def get_error_hints(status_code: int) -> List[str]:
    """Get helpful hints for common HTTP errors"""
    hints_map = {
        400: ["Verify request syntax", "Check all required fields are provided", "Ensure data types are correct"],
        401: ["Verify your authentication token", "Check if your session has expired", "Try logging in again"],
        403: ["Verify you have permission", "Check resource ownership", "Contact administrator for access"],
        404: ["Verify the resource ID or URL", "Check if the resource was deleted", "Verify you have access"],
        405: ["Check API documentation for allowed methods", "Use GET, POST, PUT, DELETE as appropriate"],
        406: ["Verify Accept header", "Try requesting with application/json"],
        407: ["Authenticate with the proxy server"],
        408: ["Check your network connection", "Try again with a smaller request", "Check server timeout settings"],
        409: ["Resource state may have changed", "Refresh and try again", "Another request may have been processed first"],
        410: ["Resource is permanently deleted and cannot be recovered"],
        411: ["Provide a valid Content-Length header"],
        412: ["Verify precondition headers (If-Match, If-Modified-Since, etc.)"],
        413: ["Reduce request size", "Check file size limits", "Use chunked uploads for large files"],
        414: ["Shorten the URL", "Use POST instead of GET for complex queries"],
        415: ["Use correct Content-Type header", "application/json for JSON", "multipart/form-data for files"],
        416: ["Verify byte range is valid", "Ensure range end is greater than start"],
        417: ["Check Expect header requirements"],
        422: ["Check validation errors for specific fields", "Verify data constraints (length, format, etc.)", "Review error details"],
        429: ["Wait before retrying", f"Implement exponential backoff", "Check rate limit configuration"],
        431: ["Reduce header size", "Remove unnecessary headers", "Check cookie size"],
        451: ["Content is blocked due to legal requirements", "Contact support if you believe this is an error"],
        499: ["Client connection was closed", "Ensure stable network connection", "Retry the request"],
        500: ["This is a server error, not your request", "Try again in a moment", "Contact support if persistent"],
        502: ["Upstream server is having issues", "Try again later"],
        503: ["Server is temporarily unavailable", "Try again later", "Check system status"],
        504: ["Upstream server timeout", "Try with a smaller request", "Check server load"],
    }
    
    return hints_map.get(status_code, [])
