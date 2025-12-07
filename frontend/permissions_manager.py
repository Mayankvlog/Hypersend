"""
Android Permissions Manager for Zaply
Handles runtime permission requests for Android 6.0+
"""

import sys
import os

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

def debug_log(msg: str):
    """Log debug messages only when DEBUG is enabled"""
    if DEBUG:
        print(msg)


# List of permissions required by Zaply
REQUIRED_PERMISSIONS = [
    "android.permission.CAMERA",                  # For video calls
    "android.permission.RECORD_AUDIO",            # For audio/voice calls
    "android.permission.READ_CONTACTS",           # For contact sharing
    "android.permission.WRITE_CONTACTS",          # For saving contacts
    "android.permission.READ_PHONE_STATE",        # For phone state detection
    "android.permission.CALL_PHONE",              # For making calls
    "android.permission.ACCESS_FINE_LOCATION",    # For location sharing
    "android.permission.ACCESS_COARSE_LOCATION",  # For approximate location
    "android.permission.READ_EXTERNAL_STORAGE",   # For file access
    "android.permission.WRITE_EXTERNAL_STORAGE",  # For file uploads
]


def request_android_permissions():
    """
    Request Android runtime permissions using JNI.
    Only works on Android API 23+
    """
    debug_log("[PERMS] Starting permission request process...")
    if sys.platform != "android":
        debug_log("[PERMS] Not on Android, skipping permission request")
        return False
    
    try:
        debug_log("[PERMS] Attempting to import jnius...")
        from jnius import autoclass
        debug_log("[PERMS] jnius imported successfully.")
        
        # Get the Android activity
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        activity = PythonActivity.mActivity
        debug_log(f"[PERMS] Android activity obtained: {activity}")
        
        # Get Context for permission checking

        PackageManager = autoclass('android.content.pm.PackageManager')
        
        # Create String array
        String = autoclass('java.lang.String')
        
        # Filter permissions that are not already granted
        permissions_to_request = []
        debug_log(f"[PERMS] Checking {len(REQUIRED_PERMISSIONS)} required permissions.")
        
        for perm in REQUIRED_PERMISSIONS:
            try:
                # Check if permission is already granted
                result = activity.checkSelfPermission(String(perm))
                if result != PackageManager.PERMISSION_GRANTED:
                    debug_log(f"[PERMS] - {perm}: Not granted")
                    permissions_to_request.append(perm)
                else:
                    debug_log(f"[PERMS] - {perm}: Already granted")
            except (AttributeError, RuntimeError, OSError) as e:
                debug_log(f"[PERMS] Error checking {perm}: {e}")
                permissions_to_request.append(perm)
        
        if not permissions_to_request:
            debug_log("[PERMS] All necessary permissions are already granted.")
            return True
        
        debug_log(f"[PERMS] Requesting {len(permissions_to_request)} new permissions: {', '.join(permissions_to_request)}")
        
        # Request permissions with request code 1
        activity.requestPermissions(
            [String(p) for p in permissions_to_request],
            1
        )
        
        debug_log("[PERMS] Android permission request dialog has been triggered.")
        return True
        
    except ImportError:
        debug_log("[PERMS] FATAL: jnius module not found. Permissions cannot be requested. Is it installed in the build?")
        return False
    except (AttributeError, RuntimeError, OSError, TypeError) as e:
        debug_log(f"[PERMS] FATAL: An unhandled error occurred while requesting permissions: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_permission(permission: str) -> bool:
    """
    Check if a specific permission is granted.
    
    Args:
        permission: Permission string (e.g., "android.permission.CAMERA")
    
    Returns:
        True if granted, False otherwise
    """
    if sys.platform != "android":
        return True  # Assume granted on non-Android
    
    try:
        from jnius import autoclass
        
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        activity = PythonActivity.mActivity
        PackageManager = autoclass('android.content.pm.PackageManager')
        String = autoclass('java.lang.String')
        
        result = activity.checkSelfPermission(String(permission))
        return result == PackageManager.PERMISSION_GRANTED
        
    except Exception as e:
        debug_log(f"[PERMS] Error checking permission: {e}")
        return False


def get_granted_permissions() -> list:
    """
    Get list of all granted permissions from REQUIRED_PERMISSIONS.
    
    Returns:
        List of granted permission strings
    """
    granted = []
    for perm in REQUIRED_PERMISSIONS:
        if check_permission(perm):
            granted.append(perm)
    return granted


if __name__ == "__main__":
    # Test script
    print("Testing permission manager...")
    print(f"Platform: {sys.platform}")
    
    if sys.platform == "android":
        print("Requesting permissions...")
        request_android_permissions()
        
        import time
        time.sleep(2)
        
        print("Granted permissions:")
        for perm in get_granted_permissions():
            print(f"  - {perm}")
    else:
        print("Not on Android, test skipped")
