"""
Error handling utilities for the Hypersend frontend application.
Provides centralized error handling, logging, and user feedback.
"""

import flet as ft
from typing import Optional, Dict, Any
import traceback
from datetime import datetime


class ErrorHandler:
    """Centralized error handler for the application"""
    
    def __init__(self, page: ft.Page):
        self.page = page
        self.error_count = 0
        self.last_errors = []  # Keep track of recent errors
        
    def log_error(self, error: Exception, context: str = ""):
        """Log error with context and timestamp"""
        error_info = {
            "timestamp": datetime.now().isoformat(),
            "context": context,
            "type": type(error).__name__,
            "message": str(error),
            "traceback": traceback.format_exc()
        }
        
        self.last_errors.append(error_info)
        # Keep only last 10 errors
        if len(self.last_errors) > 10:
            self.last_errors.pop(0)
        
        self.error_count += 1
        
        # Print to console for debugging (ASCII safe)
        print(f"[ERROR] {context}: {type(error).__name__}: {error}")
        if self.error_count <= 3:  # Only show traceback for first few errors
            try:
                print(traceback.format_exc())
            except Exception as tb_error:
                print(f"[ERROR] Traceback formatting failed: {tb_error}")
    
    def show_error_snackbar(self, message: str, duration: int = 3000):
        """Show error message as snackbar"""
        snack = ft.SnackBar(
            content=ft.Row([
                ft.Icon(ft.Icons.ERROR_OUTLINE, color=ft.Colors.WHITE, size=20),
                ft.Text(message, color=ft.Colors.WHITE, size=14)
            ], spacing=8),
            bgcolor=ft.Colors.RED_600,
            duration=duration
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def show_success_snackbar(self, message: str, duration: int = 2000):
        """Show success message as snackbar"""
        snack = ft.SnackBar(
            content=ft.Row([
                ft.Icon(ft.Icons.CHECK_CIRCLE, color=ft.Colors.WHITE, size=20),
                ft.Text(message, color=ft.Colors.WHITE, size=14)
            ], spacing=8),
            bgcolor=ft.Colors.GREEN_600,
            duration=duration
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def show_info_snackbar(self, message: str, duration: int = 2000):
        """Show info message as snackbar"""
        snack = ft.SnackBar(
            content=ft.Row([
                ft.Icon(ft.Icons.INFO_OUTLINE, color=ft.Colors.WHITE, size=20),
                ft.Text(message, color=ft.Colors.WHITE, size=14)
            ], spacing=8),
            bgcolor=ft.Colors.BLUE_600,
            duration=duration
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def handle_api_error(self, error: Exception, context: str = "") -> str:
        """Handle API errors and return user-friendly message"""
        self.log_error(error, context)
        
        error_str = str(error).lower()
        
        # Network errors
        if "timeout" in error_str or "connection" in error_str:
            message = "Network error. Please check your internet connection."
            self.show_error_snackbar(message)
            return message
        
        # Authentication errors
        if "401" in error_str or "unauthorized" in error_str:
            message = "Session expired. Please log in again."
            self.show_error_snackbar(message)
            return message
        
        # Permission errors
        if "403" in error_str or "forbidden" in error_str:
            message = "You don't have permission to perform this action."
            self.show_error_snackbar(message)
            return message
        
        # Not found errors
        if "404" in error_str or "not found" in error_str:
            message = "The requested resource was not found."
            self.show_error_snackbar(message)
            return message
        
        # Server errors
        if "500" in error_str or "server" in error_str:
            message = "Server error. Please try again later."
            self.show_error_snackbar(message)
            return message
        
        # Generic error
        message = f"An error occurred: {str(error)[:100]}"
        self.show_error_snackbar(message)
        return message
    
    def handle_async_error(self, error: Exception, context: str = ""):
        """Handle errors in async functions"""
        self.handle_api_error(error, f"Async operation - {context}")
    
    def create_error_dialog(self, title: str, message: str, on_dismiss=None) -> ft.AlertDialog:
        """Create an error dialog"""
        return ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.ERROR_OUTLINE, color=ft.Colors.RED_600),
                ft.Text(title, color=ft.Colors.RED_600)
            ]),
            content=ft.Column([
                ft.Text(message),
                ft.Container(height=10),
                ft.Text(
                    "If this problem persists, please contact support.",
                    size=12,
                    color=ft.Colors.BLUE_GREY_600
                )
            ], tight=True),
            actions=[
                ft.TextButton(
                    "OK",
                    on_click=lambda e: self._close_dialog(on_dismiss)
                )
            ],
            actions_alignment=ft.MainAxisAlignment.END
        )
    
    def _close_dialog(self, on_dismiss):
        """Close dialog and call dismiss callback"""
        self.page.dialog.open = False
        self.page.update()
        if on_dismiss:
            on_dismiss()
    
    def show_error_dialog(self, title: str, message: str, on_dismiss=None):
        """Show error dialog"""
        dialog = self.create_error_dialog(title, message, on_dismiss)
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors for debugging"""
        return {
            "total_errors": self.error_count,
            "recent_errors": self.last_errors[-5:],  # Last 5 errors
            "error_types": list(set(err["type"] for err in self.last_errors))
        }


# Global error handler instance
_error_handler: Optional[ErrorHandler] = None


def init_error_handler(page: ft.Page) -> ErrorHandler:
    """Initialize the global error handler"""
    global _error_handler
    _error_handler = ErrorHandler(page)
    return _error_handler


def get_error_handler() -> Optional[ErrorHandler]:
    """Get the global error handler"""
    return _error_handler


def handle_error(error: Exception, context: str = "") -> str:
    """Convenience function to handle errors"""
    if _error_handler:
        return _error_handler.handle_api_error(error, context)
    else:
        print(f"[ERROR] {context}: {error}")
        return str(error)


def show_success(message: str, duration: int = 2000):
    """Convenience function to show success message"""
    if _error_handler:
        _error_handler.show_success_snackbar(message, duration)


def show_info(message: str, duration: int = 2000):
    """Convenience function to show info message"""
    if _error_handler:
        _error_handler.show_info_snackbar(message, duration)