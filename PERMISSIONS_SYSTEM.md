
# Permissions System Documentation

## Overview

Zaply now includes a comprehensive permission management system similar to Telegram, allowing users to control access to device permissions including location, camera, microphone, contacts, phone, and storage.

## Permissions Supported

| Permission | Type | Icon | Description |
|-----------|------|------|------------|
| location | 📍 | 📍 | Geolocation/GPS access |
| camera | 📷 | 📷 | Camera hardware access |
| microphone | 🎤 | 🎤 | Microphone/Audio input |
| contacts | 👥 | 👥 | Contact list access |
| phone | 📱 | 📱 | Phone state/Call info |
| storage | 💾 | 💾 | File system access |

## Architecture

### 1. Frontend (Flet-based)

**Components:**
- `frontend/views/permissions.py` - Full permissions management UI
  - `PermissionsView`: Full-screen permission manager
  - `PermissionsSettingsCard`: Compact card for settings view
  - Color-coded permission cards with toggle switches
  - Save/Update button with backend sync

- `frontend/views/settings.py` - Settings view integrating permissions
  - `SettingsView`: Main settings container
  - Account section with user email
  - Permissions section with edit button
  - About section (app version)
  - Logout functionality

- `frontend/app.py` - Main app integration
  - Settings gear icon in AppBar
  - `show_settings()` method
  - `handle_logout()` method
  - Navigation flow to permissions

**UI Flow:**
```
AppBar (Settings Icon) 
  → show_settings() 
    → SettingsView 
      → load_permissions() [API call] 
        → PermissionsSettingsCard [display current]
        → Edit button 
          → PermissionsView [full manager]
            → Toggle switches
            → Save button 
              → update_permissions() [API call]
```

### 2. Backend (FastAPI + MongoDB)

**Endpoints:**

#### GET /api/v1/users/permissions
Fetch current user's permission settings

**Request:**
```bash
curl -X GET http://localhost:8000/api/v1/users/permissions \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

**Response:**
```json
{
  "location": false,
  "camera": false,
  "microphone": false,
  "contacts": false,
  "phone": false,
  "storage": false
}
```

#### PUT /api/v1/users/permissions
Update current user's permission settings

**Request:**
```bash
curl -X PUT http://localhost:8000/api/v1/users/permissions \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "location": true,
    "camera": true,
    "microphone": false,
    "contacts": true,
    "phone": false,
    "storage": true
  }'
```

**Response:**
```json
{
  "message": "Permissions updated successfully",
  "permissions": {
    "location": true,
    "camera": true,
    "microphone": false,
    "contacts": true,
    "phone": false,
    "storage": true
  }
}
```

**Error Responses:**
- `404 Not Found`: User not found in database
- `503 Service Unavailable`: Database operation timed out
- `500 Internal Server Error`: Unexpected error

### 3. Database (MongoDB)

**Model:**
```python
# In backend/models.py - UserInDB class
permissions: dict = Field(default_factory=lambda: {
    "location": False,
    "camera": False,
    "microphone": False,
    "contacts": False,
    "phone": False,
    "storage": False
})
```

**MongoDB Document Structure:**
```json
{
  "_id": "user_id_here",
  "name": "User Name",
  "email": "user@example.com",
  "password_hash": "hashed_password",
  "quota_used": 0,
  "quota_limit": 42949672960,
  "created_at": "2024-01-01T00:00:00",
  "permissions": {
    "location": false,
    "camera": false,
    "microphone": false,
    "contacts": false,
    "phone": false,
    "storage": false
  }
}
```

## Android Permissions

All 6 permissions have been enabled in `pyproject.toml`:

```toml
[tool.flet.android.permissions]
location = true
camera = true
microphone = true
contacts = true
phone = true
storage = true
```

This ensures the APK will request these permissions during installation on Android devices.

## API Client Methods

**File:** `frontend/api_client.py`

### get_permissions()
```python
async def get_permissions(self) -> Dict[str, bool]:
    """
    Fetch current user's permissions from backend
    
    Returns:
        dict: Permission states {location, camera, microphone, contacts, phone, storage}
    """
```

### update_permissions(permissions)
```python
async def update_permissions(self, permissions: Dict[str, bool]) -> Dict[str, Any]:
    """
    Update permissions on backend
    
    Args:
        permissions: dict with 6 boolean keys
    
    Returns:
        dict: Response with message and updated permissions
    """
```

## Code Files Modified/Created

### Created Files:
1. **frontend/views/permissions.py** (312 lines)
   - PermissionsView class
   - PermissionsSettingsCard class
   - Permission definitions with icons and colors
   - UI rendering and state management

2. **frontend/views/settings.py** (171 lines)
   - SettingsView class
   - Settings UI layout
   - Permissions integration
   - Logout handler

3. **test_permissions.py** (Testing utility)
   - Complete test suite for permissions endpoints
   - GET endpoint testing
   - PUT endpoint testing
   - Full flow validation

### Modified Files:
1. **frontend/app.py**
   - Added import: `from .views.settings import SettingsView`
   - Added settings button to AppBar
   - Added `show_settings()` method
   - Added `handle_logout()` method

2. **frontend/api_client.py**
   - Added `get_permissions()` method
   - Added `update_permissions()` method

3. **backend/routes/users.py**
   - Added `PermissionsUpdate` Pydantic model
   - Added `GET /api/v1/users/permissions` endpoint
   - Added `PUT /api/v1/users/permissions` endpoint

4. **backend/models.py**
   - Added `permissions` field to UserInDB
   - Default factory with all permissions = False

5. **pyproject.toml**
   - Enabled all 6 Android permissions

## Testing

### Manual Testing

1. **Start Backend:**
```bash
cd backend
python -m uvicorn main:app --reload
```

2. **Start Frontend:**
```bash
cd frontend
python app.py
```

3. **Test Flow:**
   - Login with test credentials
   - Click settings gear icon (top-right)
   - View current permissions
   - Click "Edit Permissions"
   - Toggle permissions on/off
   - Click "Save Changes"
   - Verify update message appears

### Automated Testing

Run the test suite:
```bash
python test_permissions.py
```

This will test:
- GET /api/v1/users/permissions endpoint
- PUT /api/v1/users/permissions endpoint
- Permission persistence in database
- Error handling

**Note:** Replace TEST_TOKEN in the test file with a valid JWT token from login.

## Error Handling

### Frontend
- Toast notifications for success/error
- Timeout handling for slow connections
- Graceful fallback if API unavailable
- Logging with [API] prefix

### Backend
- 5-second timeout on database operations
- Proper HTTP status codes
- Detailed error messages
- Exception handling for all edge cases

## Integration Points

1. **User Registration**: New users automatically get default permissions (all false)
2. **User Login**: Permissions loaded from database on session start
3. **Settings View**: Accessible from AppBar settings icon
4. **Logout**: Clears permissions cache and tokens
5. **Database**: Persisted in MongoDB user document

## Security

- JWT Bearer token authentication required for all endpoints
- User can only access/modify their own permissions
- All sensitive operations use timeouts
- No permission data exposed in logs (except debug mode)

## Performance

- Async/await for non-blocking database operations
- 5-second timeout prevents hanging requests
- Cached permissions in frontend state
- Lazy loading of settings view

## Future Enhancements

1. **Permission Groups**: Bundle related permissions
2. **Permission History**: Track when permissions changed
3. **App-specific Permissions**: Control per-app access
4. **Permission Prompts**: Request permissions on-demand
5. **Biometric Auth**: Require authentication for sensitive permissions
6. **Permission Scopes**: Fine-grained permission levels

## Troubleshooting

### Permissions not saving
- Check MongoDB is running
- Verify JWT token is valid
- Check backend logs for timeout errors
- Ensure backend can access database

### Permissions endpoint returns 404
- Verify user exists in database
- Check JWT token contains valid user ID
- Restart backend service

### Frontend not showing settings
- Verify SettingsView import in app.py
- Check that settings gear icon is visible in AppBar
- Check browser console for JavaScript errors

### Android permissions not working
- Ensure pyproject.toml has permissions enabled
- Rebuild APK after changes
- Install on device/emulator
- Check app permissions in Android settings

## API Response Examples

### Successful GET
```json
{
  "location": false,
  "camera": false,
  "microphone": true,
  "contacts": true,
  "phone": false,
  "storage": true
}
```

### Successful PUT
```json
{
  "message": "Permissions updated successfully",
  "permissions": {
    "location": false,
    "camera": false,
    "microphone": true,
    "contacts": true,
    "phone": false,
    "storage": true
  }
}
```

### Error Responses

**User Not Found (404):**
```json
{
  "detail": "User not found"
}
```

**Timeout (503):**
```json
{
  "detail": "Database operation timed out. Please try again."
}
```

**Server Error (500):**
```json
{
  "detail": "Failed to fetch permissions: [error message]"
}
```

## Git Commits

The following commits implement the permissions system:

1. `67cdddf` - Add comprehensive permissions management system
2. `891e615` - Add permissions field to UserInDB model
3. `bfb6242` - Integrate settings view with permissions management
4. `ab22463` - Enable Android permissions

## Summary

The Zaply permissions system provides:
- ✅ 6 device permissions (location, camera, microphone, contacts, phone, storage)
- ✅ Telegram-style UI with color-coded cards and toggles
- ✅ REST API endpoints for GET/PUT operations
- ✅ MongoDB persistence per user
- ✅ Android permission declarations
- ✅ Full error handling and timeouts
- ✅ Secure JWT authentication
- ✅ Complete testing utilities

The system is production-ready and can be deployed immediately.
