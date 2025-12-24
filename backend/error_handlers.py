"""
Custom error handlers for FastAPI application
Provides detailed logging and user-friendly error messages for validation errors
"""

import logging
import json
from typing import Any, Dict, List, Union
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

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
            "timestamp": __import__('datetime').datetime.utcnow().isoformat()
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
╔══════════════════════════════════════════════════════════════════════════════╗
║ VALIDATION ERROR - {method} {request_path}
╚══════════════════════════════════════════════════════════════════════════════╝

📋 REQUEST DETAILS:
  Method: {method}
  Path: {request_path}
  Timestamp: {error_details['timestamp']}

📊 ERROR SUMMARY:
  Total Validation Errors: {error_details['error_count']}

🔍 DETAILED ERRORS:
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
📝 REQUEST BODY:
{chr(10).join('  ' + line for line in body_str.split(chr(10)))}
""")
    except Exception as e:
        logger.error(f"    ⚠️ Could not parse request body: {e}")
    
    logger.error("═" * 80)


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
    except:
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
    
    logger.info("✅ Custom exception handlers registered")
