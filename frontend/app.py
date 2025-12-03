import flet as ft
# Compatibility shims
icons = ft.Icons
colors = ft.Colors
ft.colors = ft.Colors
import httpx
import asyncio
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

# dotenv is optional in some Android build environments; import defensively
try:
    from dotenv import load_dotenv
except Exception:  # ImportError or any other unexpected issue
    def load_dotenv(*args, **kwargs):  # type: ignore
        return None

# Load environment variables if available
load_dotenv()

try:
    from .update_manager import check_app_updates
except Exception:  
    async def check_app_updates(page: ft.Page):
        return

try:
    from .views.settings import SettingsView
except Exception:
    SettingsView = None

#
# Default backend URL now points to your DigitalOcean VPS
DEFAULT_DEV_URL = "http://139.59.82.105:8000"
PRODUCTION_API_URL = os.getenv("PRODUCTION_API_URL", "").strip()
DEV_API_URL = os.getenv("API_BASE_URL", DEFAULT_DEV_URL).strip()

# Select which URL to use
# Prefer explicit PRODUCTION_API_URL when set; otherwise fall back to DEV_API_URL.
if PRODUCTION_API_URL:
    # Use production URL if explicitly provided (VPS, domain, etc.)
    API_URL = PRODUCTION_API_URL
else:
    # Fallback to development URL (typically your VPS IP from API_BASE_URL)
    API_URL = DEV_API_URL

# Debug mode - disable in production for better performance
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# Supported UI languages for the app
LANGUAGES = [
    ("en", "English"),
    ("hi", "हिन्दी (Hindi)"),
    ("te", "తెలుగు (Telugu)"),
    ("ta", "தமிழ் (Tamil)"),
    ("mr", "मराठी (Marathi)"),
    ("pa", "ਪੰਜਾਬੀ (Punjabi)"),
    ("gu", "ગુજરાતી (Gujarati)"),
    ("bho", "भोजपुरी (Bhojpuri)"),
    ("bn", "বাংলা (Bengali)"),
    ("ur", "اردو (Urdu)"),
    ("ar", "العربية (Arabic)"),
    ("fr", "Français (French)"),
    ("de", "Deutsch (German)"),
    ("ja", "日本語 (Japanese)"),
    ("zh", "中文 (Chinese)")
]
def debug_log(msg: str):
    """Log debug messages only when DEBUG is enabled"""
    if DEBUG:
        print(msg)

debug_log(f"[CONFIG] API URL: {API_URL}")

class ZaplyApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Zaply"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 0
        self.page.window.width = 400
        self.page.window.height = 850

        # Ensure a stable background color on launch to avoid black/white flashing
        # while the first frame is being rendered on Android.
        self.primary_color = "#0088cc"
        self.bg_dark = "#FDFBFB"
        self.bg_light = "#F6F5F5F6"
        self.text_primary = "#ffffff"
        self.text_secondary = "#8e8e93"
        self.page.bgcolor = self.bg_dark
        self.page.window_bgcolor = self.bg_dark
        
        # Performance optimizations for mobile
        self.page.scroll = None  # Disable page-level scroll for better performance
        self.page.auto_scroll = False
        
        # State
        self.token: Optional[str] = None
        self.current_user: Optional[dict] = None
        self.current_chat: Optional[dict] = None
        self.chats: list = []
        self.messages: list = []
        # Selected UI language (default English)
        self.language: str = "en"
        
        # HTTP client - optimized for production VPS with connection pooling
        # Prefer HTTP/2 when available, but gracefully fall back to HTTP/1.1 if h2 is missing
        try:
            self.client = httpx.AsyncClient(
                base_url=API_URL,
                timeout=httpx.Timeout(60.0, connect=15.0, read=45.0, write=30.0),
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0),
                http2=True  # Enable HTTP/2 for better performance
            )
        except ImportError:
            debug_log("[WARN] HTTP/2 not available (h2 package not installed), using HTTP/1.1")
            self.client = httpx.AsyncClient(
                base_url=API_URL,
                timeout=httpx.Timeout(60.0, connect=15.0, read=45.0, write=30.0),
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0)
            )
        
        # Theme colors already initialized above (before we set page.bgcolor)
        # Setup custom theme
        self.page.theme = ft.Theme(
            color_scheme_seed=self.primary_color,
            use_material3=True
        )
        
        # Check for updates on startup using Flet's task runner to avoid event loop issues
        try:
            self.page.run_task(check_app_updates, self.page)
        except Exception as e:
            debug_log(f"[UPDATES] Failed to schedule update check: {e}")
        
        # Show login screen
        self.show_login()
    
    def show_login(self):
        """Show login/register screen"""
        debug_log(f"[INIT] ZaplyApp initialized, API URL: {API_URL}")
        # Ensure page is properly styled
        self.page.bgcolor = self.bg_dark
        
        def on_language_change(e: ft.ControlEvent):
            self.language = e.control.value or "en"
            debug_log(f"[LANG] Selected UI language: {self.language}")
            self.page.update()
        
        language_dropdown = ft.Dropdown(
            label="Language / भाषा",
            value=self.language,
            options=[
                ft.dropdown.Option(code, label) for code, label in LANGUAGES
            ],
            on_change=on_language_change,
            width=300,
        )
        
        email_field = ft.TextField(
            label="Email",
            autofocus=True,
            keyboard_type=ft.KeyboardType.EMAIL,
            prefix_icon=icons.EMAIL,
            filled=True
        )
        
        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            prefix_icon=icons.LOCK,
            filled=True
        )
        
        username_field = ft.TextField(
            label="Username",
            prefix_icon=icons.PERSON,
            filled=True,
            visible=False
        )
        
        error_text = ft.Text(
            "",
            color=ft.colors.RED,
            size=12,
            visible=False
        )
        
        async def login_clicked(e):
            if not email_field.value or not password_field.value:
                error_text.value = "Please fill all fields"
                error_text.visible = True
                self.page.update()
                return
            
            # Show loading state
            login_btn.disabled = True
            login_btn.text = "Logging in..."
            error_text.visible = False
            self.page.update()
            
            try:
                debug_log(f"[LOGIN] Attempting login to {self.client.base_url}/api/v1/auth/login")
                response = await self.client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": email_field.value,
                        "password": password_field.value
                    }
                )
                debug_log(f"[LOGIN] Response status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    self.token = data["access_token"]
                    debug_log(f"[LOGIN] Token received, fetching user info")
                    
                    # Fetch user info after login
                    self.client.headers["Authorization"] = f"Bearer {self.token}"
                    user_response = await self.client.get("/api/v1/users/me")
                    
                    if user_response.status_code == 200:
                        self.current_user = user_response.json()
                        debug_log(f"[LOGIN] Success! User: {self.current_user.get('email')}")
                        self.show_chat_list()
                    else:
                        error_text.value = "Login successful but failed to fetch user info"
                        error_text.visible = True
                        login_btn.disabled = False
                        login_btn.text = "Login"
                else:
                    # Handle specific error codes
                    try:
                        error_data = response.json()
                        error_detail = error_data.get("detail", "Login failed")
                    except Exception:
                        error_detail = response.text[:100] if response.text else "Unknown error"
                    
                    if response.status_code == 401:
                        error_text.value = "❌ Incorrect email or password"
                    elif response.status_code == 500:
                        error_text.value = f"⚠️ Server error: {error_detail}"
                        debug_log(f"[LOGIN] 500 Error detail: {error_detail}")
                    elif response.status_code == 503:
                        error_text.value = "⚠️ Database connection error. Try again later."
                    else:
                        error_text.value = f"Login failed ({response.status_code}): {error_detail}"
                    
                    error_text.visible = True
                    login_btn.disabled = False
                    login_btn.text = "Login"
                    
            except httpx.TimeoutException as ex:
                debug_log(f"[LOGIN] Timeout: {ex}")
                error_text.value = "⏱️ Request timeout. Check your internet connection."
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Login"
            except httpx.ConnectError as ex:
                debug_log(f"[LOGIN] Connection error: {ex}")
                error_text.value = (
                    "🔌 Cannot connect to server.\n"
                    f"URL: {API_URL}\n\n"
                    "⚠️ SOLUTION:\n"
                    "1. Start the backend: python -m uvicorn backend.main:app\n"
                    "2. Check API_BASE_URL environment variable\n"
                    "3. For VPS: Set PRODUCTION_API_URL in .env\n"
                    "4. Check your internet connection.\n\n"
                    f"Error: {str(ex)[:50]}"
                )
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Login"
            except Exception as ex:
                debug_log(f"[LOGIN] Unexpected error: {type(ex).__name__}: {ex}")
                error_text.value = f"❗ Error: {str(ex)}"
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Login"
            
            self.page.update()
        
        async def register_clicked(e):
            if not email_field.value or not password_field.value or not username_field.value:
                error_text.value = "Please fill all fields"
                error_text.visible = True
                self.page.update()
                return
            
            # Show loading state
            login_btn.disabled = True
            login_btn.text = "Registering..."
            error_text.visible = False
            self.page.update()
            
            try:
                debug_log(f"[REGISTER] Attempting registration for: {email_field.value}")
                response = await self.client.post(
                    "/api/v1/auth/register",
                    json={
                        "email": email_field.value,
                        "name": username_field.value,
                        "password": password_field.value
                    }
                )
                
                if response.status_code == 201:
                    # Some environments (reverse proxies, error pages, etc.) may return
                    # non-JSON even with 201, so be defensive here.
                    try:
                        data = response.json()
                    except Exception:
                        data = {}
                    debug_log(f"[REGISTER] Registration successful, logging in...")
                    
                    # Registration successful, now login
                    login_response = await self.client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": email_field.value,
                            "password": password_field.value
                        }
                    )
                    if login_response.status_code == 200:
                        login_data = login_response.json()
                        self.token = login_data["access_token"]
                        self.client.headers["Authorization"] = f"Bearer {self.token}"
                        
                        # Always fetch user profile from backend instead of trusting
                        # the register response payload.
                        try:
                            user_response = await self.client.get("/api/v1/users/me")
                            if user_response.status_code == 200:
                                self.current_user = user_response.json()
                        except Exception as profile_ex:
                            debug_log(f"[REGISTER] Failed to fetch profile after registration: {profile_ex}")
                        
                        debug_log(f"[REGISTER] Success! User: {email_field.value}")
                        self.show_chat_list()
                    else:
                        error_text.value = "Registration successful but auto-login failed. Please login manually."
                        error_text.visible = True
                        login_btn.disabled = False
                        login_btn.text = "Register"
                else:
                    try:
                        error_data = response.json()
                        error_detail = error_data.get("detail", "Registration failed")
                    except Exception:
                        error_detail = response.text[:100] if response.text else "Unknown error"
                    
                    if response.status_code == 400:
                        error_text.value = "❌ Email already registered"
                    elif response.status_code == 500:
                        error_text.value = f"⚠️ Server error: {error_detail}"
                        debug_log(f"[REGISTER] 500 Error: {error_detail}")
                    else:
                        error_text.value = f"Registration failed ({response.status_code}): {error_detail}"
                    
                    error_text.visible = True
                    login_btn.disabled = False
                    login_btn.text = "Register"
                    
            except httpx.TimeoutException as ex:
                debug_log(f"[REGISTER] Timeout: {ex}")
                error_text.value = "⏱️ Request timeout. Check your internet connection."
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Register"
            except httpx.ConnectError as ex:
                debug_log(f"[REGISTER] Connection error: {ex}")
                # Show the same helpful message as the login handler so users
                # know exactly how to fix backend connectivity for both flows.
                error_text.value = (
                    "🔌 Cannot connect to server.\n"
                    f"URL: {API_URL}\n\n"
                    "⚠️ SOLUTION:\n"
                    "1. Start the backend: python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000\n"
                    "2. Check API_BASE_URL / PRODUCTION_API_URL in your .env file\n"
                    "3. For Android APK: build using .env.production so it uses your VPS URL\n"
                    "4. Make sure your phone and server have internet access.\n\n"
                    f"Error: {str(ex)[:50]}"
                )
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Register"
            except Exception as ex:
                debug_log(f"[REGISTER] Unexpected error: {type(ex).__name__}: {ex}")
                error_text.value = f"❗ Error: {str(ex)}"
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Register"
            
            self.page.update()
        
        def toggle_mode(e):
            if username_field.visible:
                # Switch to login
                username_field.visible = False
                login_btn.text = "Login"
                register_btn.text = "Need an account? Register"
                login_btn.on_click = login_clicked
            else:
                # Switch to register
                username_field.visible = True
                login_btn.text = "Register"
                register_btn.text = "Have an account? Login"
                login_btn.on_click = register_clicked
            
            error_text.visible = False
            self.page.update()
        
        login_btn = ft.ElevatedButton(
            "Login",
            on_click=login_clicked,
            style=ft.ButtonStyle(
                color=ft.colors.WHITE,
                bgcolor=self.primary_color,
                padding=15
            ),
            width=300
        )
        
        register_btn = ft.TextButton(
            "Need an account? Register",
            on_click=toggle_mode
        )
        
        forgot_password_btn = ft.TextButton(
            "Forgot Password?",
            on_click=lambda e: self.show_forgot_password()
        )
        
        self.page.controls = [
            ft.Container(
                content=ft.Column(
                    [
                        language_dropdown,
                        email_field,
                        username_field,
                        password_field,
                        error_text,
                        login_btn,
                        forgot_password_btn,
                        register_btn
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=15
                ),
                padding=ft.padding.only(left=30, right=30, top=150, bottom=30),
                alignment=ft.alignment.top_center,
                expand=True
            )
        ]
        self.page.update()
    
    def show_forgot_password(self):
        """Show forgot password screen"""
        step = "email"  # email or reset
        reset_token = None
        
        # Email step UI
        email_field = ft.TextField(
            label="Enter your email",
            keyboard_type=ft.KeyboardType.EMAIL,
            prefix_icon=icons.EMAIL,
            filled=True,
            autofocus=True
        )
        
        email_submit_btn = ft.ElevatedButton(
            "Request Reset",
            style=ft.ButtonStyle(
                color=ft.colors.WHITE,
                bgcolor=self.primary_color,
                padding=15
            ),
            width=300
        )
        
        # Reset password step UI
        # Show token in plain text so users can see/copy it when backend returns
        # it in the API response (useful during development or when SMTP is not
        # configured). The field is still hidden until a token is generated.
        token_field = ft.TextField(
            label="Reset Token (check email)",
            password=False,
            prefix_icon=icons.VPN_KEY,
            filled=True,
            visible=False
        )
        
        new_password_field = ft.TextField(
            label="New Password",
            password=True,
            can_reveal_password=True,
            prefix_icon=icons.LOCK,
            filled=True,
            visible=False
        )
        
        confirm_password_field = ft.TextField(
            label="Confirm Password",
            password=True,
            can_reveal_password=True,
            prefix_icon=icons.LOCK,
            filled=True,
            visible=False
        )
        
        reset_submit_btn = ft.ElevatedButton(
            "Reset Password",
            style=ft.ButtonStyle(
                color=ft.colors.WHITE,
                bgcolor=self.primary_color,
                padding=15
            ),
            width=300,
            visible=False
        )
        
        error_text = ft.Text(
            "",
            color=ft.colors.RED,
            size=12,
            visible=False
        )
        
        success_text = ft.Text(
            "",
            color=ft.colors.GREEN,
            size=12,
            visible=False
        )
        
        info_text = ft.Text(
            "Enter your email to receive a password reset token",
            size=13,
            color=ft.colors.GREY_700
        )
        
        back_btn = ft.TextButton(
            "← Back to Login",
            on_click=lambda e: self.show_login()
        )
        
        async def request_reset_clicked(e):
            email = email_field.value.strip()
            
            if not email:
                error_text.value = "Please enter your email"
                error_text.visible = True
                success_text.visible = False
                self.page.update()
                return
            
            email_submit_btn.disabled = True
            email_submit_btn.text = "Sending..."
            error_text.visible = False
            success_text.visible = False
            self.page.update()
            
            try:
                response = await self.client.post(
                    "/api/v1/auth/forgot-password",
                    json={"email": email}
                )
                
                if response.status_code == 200:
                    # Be defensive: some environments (reverse proxies, error pages)
                    # may return non-JSON content even with 200 status.
                    try:
                        data = response.json()
                    except Exception:
                        data = {"message": response.text or "Password reset request processed."}

                    nonlocal step, reset_token
                    step = "reset"
                    
                    # Show reset form
                    info_text.value = "Check your email or copy the token below"
                    email_field.visible = False
                    email_submit_btn.visible = False
                    
                    token_field.visible = True
                    new_password_field.visible = True
                    confirm_password_field.visible = True
                    reset_submit_btn.visible = True
                    
                    # Auto-fill token if backend returned it (now always true for our API)
                    if "reset_token" in data and data["reset_token"]:
                        token_field.value = data["reset_token"]
                        success_text.value = f"✅ Token copied here. Also sent by email if configured."
                    else:
                        success_text.value = f"✅ {data.get('message', 'Reset token sent to your email')}"
                    
                    success_text.visible = True
                else:
                    # Try to show detailed backend error when available
                    try:
                        err = response.json()
                        detail = err.get("detail", f"Error: {response.status_code}")
                    except Exception:
                        detail = f"Error: {response.status_code}"
                    error_text.value = detail
                    error_text.visible = True
                
            except Exception as ex:
                error_text.value = f"Error: {str(ex)}"
                error_text.visible = True
            finally:
                email_submit_btn.disabled = False
                email_submit_btn.text = "Request Reset"
                self.page.update()
        
        async def reset_password_clicked(e):
            token = token_field.value.strip()
            password = new_password_field.value
            confirm = confirm_password_field.value
            
            if not token or not password or not confirm:
                error_text.value = "Please fill all fields"
                error_text.visible = True
                success_text.visible = False
                self.page.update()
                return
            
            if password != confirm:
                error_text.value = "Passwords don't match"
                error_text.visible = True
                success_text.visible = False
                self.page.update()
                return
            
            if len(password) < 8:
                error_text.value = "Password must be at least 8 characters"
                error_text.visible = True
                success_text.visible = False
                self.page.update()
                return
            
            reset_submit_btn.disabled = True
            reset_submit_btn.text = "Resetting..."
            error_text.visible = False
            success_text.visible = False
            self.page.update()
            
            try:
                response = await self.client.post(
                    "/api/v1/auth/reset-password",
                    json={"token": token, "new_password": password}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    success_text.value = f"✅ {data.get('message', 'Password reset successful!')}"
                    success_text.visible = True
                    self.page.update()
                    
                    # Go back to login immediately
                    await asyncio.sleep(0.5)
                    self.show_login()
                else:
                    error_data = response.json() if response.status_code < 500 else {}
                    error_text.value = error_data.get("detail", f"Error: {response.status_code}")
                    error_text.visible = True
                
            except Exception as ex:
                error_text.value = f"Error: {str(ex)}"
                error_text.visible = True
            finally:
                reset_submit_btn.disabled = False
                reset_submit_btn.text = "Reset Password"
                self.page.update()
        
        email_submit_btn.on_click = lambda e: self.page.run_task(request_reset_clicked, e)
        reset_submit_btn.on_click = lambda e: self.page.run_task(reset_password_clicked, e)
        
        self.page.controls = [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Reset Password", size=24, weight="bold", color=ft.colors.BLACK),
                        ft.Container(height=10),
                        info_text,
                        ft.Container(height=20),
                        email_field,
                        token_field,
                        new_password_field,
                        confirm_password_field,
                        error_text,
                        success_text,
                        ft.Container(height=20),
                        email_submit_btn,
                        reset_submit_btn,
                        ft.Container(height=20),
                        back_btn
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=12
                ),
                padding=ft.padding.only(left=30, right=30, top=100, bottom=30),
                alignment=ft.alignment.top_center,
                expand=True
            )
        ]
        self.page.update()
    
    def show_chat_list(self):
        """Show list of chats"""
        async def load_chats():
            try:
                debug_log(f"[CHATS] Loading chats from {self.client.base_url}/api/v1/chats/")
                response = await self.client.get("/api/v1/chats/")
                debug_log(f"[CHATS] Response status: {response.status_code}")
                
                if response.status_code == 200:
                    payload = response.json()
                    self.chats = payload.get("chats", [])
                    debug_log(f"[CHATS] Loaded {len(self.chats)} chats")
                    update_chat_list()
                else:
                    debug_log(f"[CHATS] Failed to load chats: {response.status_code}")
                    # Still call update to show at least Saved Messages
                    update_chat_list()
            except Exception as ex:
                debug_log(f"[CHATS] Error loading chats: {type(ex).__name__}: {ex}")
                # Still show Saved Messages even if loading fails
                update_chat_list()
        
        def update_chat_list():
            chat_items = []
            
            # Add Saved Messages at the top
            saved_messages_item = ft.Container(
                content=ft.Row(
                    [
                        ft.CircleAvatar(
                            content=ft.Icon(icons.BOOKMARK, size=24, color=ft.colors.WHITE),
                            bgcolor=self.primary_color,
                            radius=20
                        ),
                        ft.Column(
                            [
                                ft.Text(
                                    "Saved Messages",
                                    size=16,
                                    weight=ft.FontWeight.W_500,
                                    color=ft.colors.BLACK
                                ),
                                ft.Text(
                                    "Your personal collection",
                                    size=13,
                                    color=ft.colors.BLACK54
                                )
                            ],
                            spacing=5,
                            expand=True
                        )
                    ],
                    spacing=15
                ),
                padding=15,
                on_click=lambda e: self.show_saved_messages(),
                ink=True,
                bgcolor=ft.colors.WHITE
            )
            chat_items.append(saved_messages_item)
            chat_items.append(ft.Divider(height=1, color=self.bg_light))
            
            # Add regular chats
            for chat in self.chats:
                # Skip saved type chats from regular list
                if chat.get("type") == "saved":
                    continue
                    
                # Determine chat name and avatar based on backend schema
                chat_name = chat.get("name") or ("Group Chat" if chat.get("type") == "group" else "Private Chat")
                avatar = (
                    ft.Icon(icons.GROUP, size=40)
                    if chat.get("type") == "group"
                    else ft.CircleAvatar(
                        content=ft.Text(
                            (chat_name or "?")[0].upper(),
                            size=20,
                            weight=ft.FontWeight.BOLD
                        ),
                        bgcolor=self.primary_color
                    )
                )
                
                last_message_text = (chat.get("last_message") or {}).get("text", "No messages yet")
                
                chat_item = ft.Container(
                    content=ft.Row(
                        [
                            avatar,
                            ft.Column(
                                [
                                    ft.Text(
                                        chat_name,
                                        size=16,
                                        weight=ft.FontWeight.W_500,
                                        color=self.text_primary
                                    ),
                                    ft.Text(
                                        last_message_text[:50] + "..." if len(last_message_text) > 50 else last_message_text,
                                        size=13,
                                        color=self.text_secondary
                                    )
                                ],
                                spacing=5,
                                expand=True
                            )
                        ],
                        spacing=15
                    ),
                    padding=15,
                    on_click=lambda e, c=chat: self.show_chat(c),
                    ink=True
                )
                chat_items.append(chat_item)
                chat_items.append(ft.Divider(height=1, color=self.bg_light))
            
            chat_list_view.controls = chat_items if chat_items else [
                ft.Container(
                    content=ft.Text(
                        "No chats yet. Start a new conversation!",
                        color=self.text_secondary,
                        text_align=ft.TextAlign.CENTER
                    ),
                    padding=30,
                    alignment=ft.alignment.center
                )
            ]
            self.page.update()
        
        chat_list_view = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            expand=True
        )
        
        # AppBar
        appbar = ft.AppBar(
            title=ft.Text("", weight=ft.FontWeight.BOLD),
            center_title=False,
            bgcolor=self.bg_light,
            actions=[
                ft.IconButton(
                    icon=icons.SEARCH,
                    on_click=lambda e: print("Search")
                ),
                ft.IconButton(
                    icon=icons.ADD,
                    on_click=lambda e: self.show_new_chat_dialog()
                ),
                ft.IconButton(
                    icon=icons.SETTINGS,
                    on_click=lambda e: self.show_settings()
                )
            ]
        )
        
        self.page.appbar = appbar
        self.page.controls = [
            ft.Container(
                content=chat_list_view,
                bgcolor=self.bg_dark,
                expand=True
            )
        ]
        
        # Show Saved Messages immediately
        update_chat_list()
        
        # Load chats in background
        self.page.run_task(load_chats)
        self.page.update()
    
    def show_saved_messages(self):
        """Open the 'Saved Messages' chat if it exists, else show info page"""
        # Find a chat marked as saved (type == 'saved')
        saved_chat = next((c for c in self.chats if c.get("type") == "saved"), None)

        if saved_chat:
            # Re-use existing chat UI
            self.show_chat(saved_chat)
            return

        # Fallback screen if backend has no saved chat yet
        self.page.appbar = ft.AppBar(
            leading=ft.IconButton(
                icon=icons.ARROW_BACK,
                icon_color=ft.colors.BLACK,
                on_click=lambda e: self.show_chat_list(),
            ),
            title=ft.Text("Saved Messages", weight=ft.FontWeight.BOLD, color=ft.colors.BLACK),
            center_title=False,
            bgcolor=ft.colors.WHITE,
        )

        self.page.controls = [
            ft.Container(
                content=ft.Text(
                    "No saved messages chat is available yet.",
                    color=self.text_secondary,
                    text_align=ft.TextAlign.CENTER,
                ),
                alignment=ft.alignment.center,
                expand=True,
            )
        ]
        self.page.update()

    def show_settings(self):
        """Show settings view"""
        if not SettingsView:
            print("[ERROR] SettingsView not available")
            return
        
        try:
            settings_view = SettingsView(
                page=self.page,
                api_client=self.client,
                current_user=self.current_user,
                on_logout=self.handle_logout,
                on_back=self.show_chat_list
            )
            self.page.clean()
            self.page.add(settings_view)
            self.page.update()
        except Exception as e:
            debug_log(f"[SETTINGS] Error opening settings: {e}")
            print(f"Error opening settings: {e}")

    def show_chat(self, chat: dict):
        """Show chat messages"""
        self.current_chat = chat
        
        async def load_messages():
            try:
                response = await self.client.get(f"/api/v1/chats/{chat['_id']}/messages")
                if response.status_code == 200:
                    payload = response.json()
                    self.messages = payload.get("messages", [])
                    update_messages()
            except Exception as ex:
                print(f"Error loading messages: {ex}")
        
        def update_messages():
            message_items = []
            for msg in self.messages:
                is_mine = msg.get("sender_id") == self.current_user.get("id", self.current_user.get("_id"))
                
                # Message bubble
                if msg.get("type") == "text":
                    content = ft.Text(
                        msg.get("text", ""),
                        color=self.text_primary,
                        selectable=True
                    )
                else:
                    # File message (simplified)
                    filename = msg.get("file_id", "File")
                    content = ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Icon(icons.INSERT_DRIVE_FILE, size=40),
                                    ft.Column(
                                        [
                                            ft.Text(
                                                str(filename),
                                                weight=ft.FontWeight.W_500
                                            )
                                        ],
                                        spacing=2
                                    )
                                ],
                                spacing=10
                            ),
                            ft.ElevatedButton(
                                "Download",
                                icon=icons.DOWNLOAD,
                                on_click=lambda e, fid=msg.get("file_id"): self.download_file(fid)
                            )
                        ],
                        spacing=10
                    )
                
                message_bubble = ft.Container(
                    content=ft.Column(
                        [
                            content,
                            ft.Text(
                                datetime.fromisoformat(msg.get("created_at", msg.get("timestamp", "")).replace("Z", "+00:00")).strftime("%H:%M"),
                                size=10,
                                color=self.text_secondary
                            )
                        ],
                        spacing=5
                    ),
                    bgcolor=self.primary_color if is_mine else self.bg_light,
                    padding=10,
                    border_radius=10,
                    margin=ft.margin.only(
                        left=50 if is_mine else 0,
                        right=0 if is_mine else 50,
                        top=5,
                        bottom=5
                    )
                )
                
                message_items.append(message_bubble)
            
            messages_view.controls = message_items
            self.page.update()
        
        messages_view = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            expand=True,
            spacing=5
        )
        
        # Language selector for composing messages in this chat
        chat_language_dropdown = ft.Dropdown(
            value=self.language,
            width=130,
            options=[ft.dropdown.Option(code, label) for code, label in LANGUAGES],
            on_change=lambda e: setattr(self, "language", e.control.value or "en"),
        )
        
        message_input = ft.TextField(
            hint_text="Type a message...",
            border=ft.InputBorder.NONE,
            filled=True,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5
        )
        
        async def send_message(e):
            if not message_input.value:
                return
            
            try:
                response = await self.client.post(
                    f"/api/v1/chats/{chat['_id']}/messages",
                    json={
                        "text": message_input.value,
                        # Pass selected language code to backend
                        "language": self.language,
                    }
                )
                
                if response.status_code == 200:
                    message_input.value = ""
                    await load_messages()
            except Exception as ex:
                print(f"Error sending message: {ex}")
            
            self.page.update()
        
        async def pick_file(e):
            file_picker.pick_files(allow_multiple=False)
        
        async def upload_file(e: ft.FilePickerResultEvent):
            if not e.files:
                return
            
            file = e.files[0]
            await self.upload_file_chunked(file.path, chat["_id"])
        
        file_picker = ft.FilePicker(on_result=upload_file)
        self.page.overlay.append(file_picker)
        
        # AppBar for chat
        chat_name = chat.get("other_user", {}).get("username", "Chat") if not chat.get("is_group") else chat.get("group_name", "Group")
        
        self.page.appbar = ft.AppBar(
            leading=ft.IconButton(
                icon=icons.ARROW_BACK,
                on_click=lambda e: self.show_chat_list()
            ),
            title=ft.Text(chat_name, weight=ft.FontWeight.BOLD),
            center_title=False,
            bgcolor=self.bg_light
        )
        
        self.page.controls = [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Container(
                            content=messages_view,
                            expand=True,
                            padding=10
                        ),
                        ft.Container(
                            content=ft.Row(
                                [
                                    chat_language_dropdown,
                                    ft.IconButton(
                                        icon=icons.ATTACH_FILE,
                                        on_click=pick_file
                                    ),
                                    message_input,
                                    ft.IconButton(
                                        icon=icons.SEND,
                                        on_click=send_message,
                                        bgcolor=self.primary_color,
                                        icon_color=ft.colors.WHITE
                                    )
                                ],
                                spacing=10
                            ),
                            padding=10,
                            bgcolor=self.bg_light
                        )
                    ],
                    spacing=0
                ),
                bgcolor=self.bg_dark,
                expand=True
            )
        ]
        
        # Load messages
        self.page.run_task(load_messages)
        self.page.update()
    
    async def upload_file_chunked(self, file_path: str, chat_id: str):
        """Upload file in chunks"""
        try:
            path = Path(file_path)
            file_size = path.stat().st_size
            
            # Start upload
            response = await self.client.post(
                "/api/v1/files/init",
                json={
                    "filename": path.name,
                    "size": file_size,
                    "mime": "application/octet-stream",
                    "chat_id": chat_id
                }
            )
            
            if response.status_code != 200:
                debug_log("Failed to start upload")
                return
            
            upload_info = response.json()
            upload_id = upload_info["upload_id"]
            chunk_size = upload_info["chunk_size"]
            total_chunks = upload_info["total_chunks"]
            
            # Upload chunks
            with open(file_path, 'rb') as f:
                for chunk_index in range(total_chunks):
                    chunk_data = f.read(chunk_size)
                    if not chunk_data:
                        break
                    
                    response = await self.client.put(
                        f"/api/v1/files/{upload_id}/chunk",
                        params={"chunk_index": chunk_index},
                        content=chunk_data
                    )
                    
                    if response.status_code != 200:
                        debug_log(f"Failed to upload chunk {chunk_index}")
                        return
            
            # Complete upload
            response = await self.client.post(
                f"/api/v1/files/{upload_id}/complete"
            )
            
            if response.status_code != 200:
                debug_log("Failed to complete upload")
                return
                
            complete_info = response.json()
            file_id = complete_info["file_id"]
            
            # Send message with file
            await self.client.post(
                f"/api/v1/chats/{chat_id}/messages",
                json={
                    "file_id": file_id
                }
            )
            
            debug_log("File uploaded successfully")
            
        except Exception as ex:
            debug_log(f"Upload error: {ex}")
    
    async def download_file(self, file_id: str):
        """Download file"""
        try:
            response = await self.client.get(f"/api/v1/files/{file_id}/download")
            if response.status_code == 200:
                # Get filename from headers
                filename = response.headers.get("Content-Disposition", "download").split("filename=")[-1].strip('"')
                
                # Save file
                save_path = Path.home() / "Downloads" / filename
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                
                debug_log(f"File downloaded to {save_path}")
        except Exception as ex:
            debug_log(f"Download error: {ex}")
    
    def show_new_chat_dialog(self):
        """Show dialog to create new chat"""
        # Simplified - in production, show user search
        pass

    def handle_logout(self):
        """Handle logout action"""
        self.token = None
        self.current_user = None
        self.chats = []
        self.messages = []
        self.show_login()


async def main(page: ft.Page):
    """Flet entrypoint with robust startup error handling.

    If anything goes wrong while building the first page, show a simple
    error screen instead of leaving the user on a blank white screen.
    """
    # Set page properties first
    page.title = "Zaply"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 0
    page.bgcolor = "#FDFBFB"
    
    try:
        ZaplyApp(page)
    except Exception as e:
        # Log the error to console for debugging
        debug_log(f"[FATAL] Failed to start ZaplyApp: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

        # Show a minimal fallback UI so the user never sees an empty page
        page.controls = [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Zaply", size=24, weight=ft.FontWeight.BOLD, color=ft.colors.BLACK),
                        ft.Text(
                            "App failed to start. Please close and reopen.\n"
                            "If this keeps happening, reinstall the app.",
                            size=14,
                            text_align=ft.TextAlign.CENTER,
                            color=ft.colors.BLACK87,
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=10,
                ),
                alignment=ft.alignment.center,
                expand=True,
                bgcolor="#FDFBFB",
            )
        ]
        page.update()


if __name__ == "__main__":
    ft.app(target=main, name="Zaply")
