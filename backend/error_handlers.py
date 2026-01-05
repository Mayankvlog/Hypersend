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
- http_exception_handler: Handles all HTTPException (400-599 range)
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
    
    app.add_exception_handler(
        RequestValidationError,
        validation_exception_handler
    )
    
    app.add_exception_handler(HTTPException, http_exception_handler)
    
    # Add global exception handler for unhandled exceptions
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handle all unhandled exceptions with proper JSON response"""
        import traceback
        
        # Log the full traceback for debugging
        logger.error(f"Unhandled exception: {type(exc).__name__}: {str(exc)}")
        if logger.isEnabledFor(logging.DEBUG):
            traceback.print_exc()
        
        # Return proper JSON response instead of letting exception crash connection
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status_code": 500,
                "error": "Internal Server Error",
                "detail": "An unexpected server error occurred",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(request.url.path),
                "method": request.method,
                "hints": ["This is a server error, not your request", "Try again in a moment", "Contact support if persistent"]
            }
        )
    
    logger.info("Custom exception handlers registered")


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Comprehensive HTTP exception handler for all 4xx/5xx errors
    
    Handles:
    400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found,
    405 Method Not Allowed, 406 Not Acceptable, 407 Proxy Auth Required,
    408 Request Timeout, 409 Conflict, 410 Gone, 411 Length Required,
    412 Precondition Failed, 413 Payload Too Large, 414 URI Too Long,
    415 Unsupported Media Type, 416 Range Not Satisfiable, 417 Expectation Failed,
    422 Unprocessable Entity, 429 Too Many Requests, 431 Headers Too Large,
    451 Unavailable For Legal Reasons, 499 Client Closed Request
    """
    
    status_code = exc.status_code
    detail = exc.detail
    
    error_descriptions = {
            400: "Bad Request - Invalid request syntax or parameters",
            401: "Unauthorized - Authentication required or invalid credentials",
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
            422: "Unprocessable Entity - Semantic validation error (valid syntax but invalid data)",
            429: "Too Many Requests - Rate limit exceeded, too many requests received",
            431: "Request Header Fields Too Large - Headers exceed the maximum size",
            451: "Unavailable For Legal Reasons - Content blocked due to legal compliance",
            499: "Client Closed Request - Client closed the connection prematurely",
            500: "Internal Server Error - An unexpected server error occurred",
            502: "Bad Gateway - Invalid response from upstream server",
            503: "Service Unavailable - Server is temporarily unavailable",
            504: "Gateway Timeout - Upstream server took too long to respond",
        }
        
    error_description = error_descriptions.get(
        status_code,
        f"HTTP Error {status_code}"
    )
    
    # Custom 5xx exception classes for better error handling (defined outside function)
    # Note: These can be used for raising specific HTTP exceptions
    
    # Log error with full context
    logger.warning(
        f"[HTTP_{status_code}] {request.method} {request.url.path} | "
        f"Client: {request.client.host if request.client else 'Unknown'} | "
        f"Detail: {detail}"
    )
    
    response_data = {
        "status_code": status_code,
        "error": error_description,
        "detail": str(detail),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": str(request.url.path),
        "method": request.method,
    }
    
    # Add helpful hints based on error code
    hints = get_error_hints(status_code)
    if hints:
        response_data["hints"] = hints
    
    return JSONResponse(
        status_code=status_code,
        content=response_data
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
