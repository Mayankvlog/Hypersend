import flet as ft
import asyncio
import sys
import os
from typing import Optional, List, Dict, Any
from datetime import datetime

# Add current directory to sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import API client
from api_client import APIClient

# Import error handler
from error_handler import init_error_handler, handle_error, show_success, show_info

# Import views
from views.settings import SettingsView
from views.login import LoginView
from views.profile import ProfileView
from views.saved_messages import SavedMessagesView

# Compatibility shims
icons = ft.Icons
colors = ft.Colors
ft.Colors = ft.Colors

# dotenv is optional in some Android build environments; import defensively
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):  # type: ignore
        return None

# Load environment variables if available
load_dotenv()

# Default backend URL - use VPS for testing
DEFAULT_DEV_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
PRODUCTION_API_URL = os.getenv("PRODUCTION_API_URL", "").strip()
DEV_API_URL = os.getenv("API_BASE_URL", DEFAULT_DEV_URL).strip()

# Select which URL to use
if PRODUCTION_API_URL:
    API_URL = PRODUCTION_API_URL
else:
    API_URL = DEV_API_URL

# Debug mode - disable in production for better performance
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

def debug_log(msg: str):
    """Log debug messages only when DEBUG is enabled"""
    if DEBUG:
        print(msg)

class ChatsView(ft.View):
    def __init__(self, page: ft.Page, api_client: APIClient, current_user: dict, on_logout=None, on_chat_click=None, on_saved_click=None, on_profile_click=None):
        super().__init__("/")
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_logout = on_logout
        self.on_chat_click = on_chat_click
        self.on_saved_click = on_saved_click
        self.on_profile_click = on_profile_click
        
        # Theme colors - Light blue themed
        self.primary_color = "#0088CC"
        self.bg_color = "#FDFBFB"
        self.card_color = "#FFFFFF"
        self.text_color = "#000000"
        self.text_secondary = "#8e8e93"
        self.accent_light = "#E7F5FF"
        self.accent_hover = "#0077B5"
        
        # State
        self.chats: List[Dict[str, Any]] = []
        self.loading = False
        self.dark_mode = False
        
        # Build drawer first
        self.build_drawer()
        self.build_ui()
    
    def build_drawer(self):
        """Build Telegram-style navigation drawer"""
        user_name = self.current_user.get("name", self.current_user.get("username", "User"))
        user_email = self.current_user.get("email", "")
        user_initials = user_name[0].upper() if user_name else "U"
        
        # Drawer header with user info
        drawer_header = ft.Container(
            content=ft.Column([
                # User avatar
                ft.Container(
                    content=ft.Text(user_initials, size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                    width=60,
                    height=60,
                    bgcolor=self.primary_color,
                    border_radius=30,
                    alignment=ft.alignment.center,
                ),
                ft.Container(height=12),
                # User name
                ft.Row([
                    ft.Text(user_name, size=18, weight=ft.FontWeight.W_600, color=ft.Colors.WHITE),
                    ft.Icon(ft.Icons.EXPAND_MORE, color=ft.Colors.WHITE, size=20)
                ], spacing=4),
                # User status/email
                ft.Text(user_email or "Set Emoji Status", size=13, color=ft.Colors.WHITE70),
            ], spacing=4),
            padding=ft.padding.all(20),
            bgcolor=self.primary_color,
        )
        
        # Night mode switch
        self.night_mode_switch = ft.Switch(
            value=self.dark_mode,
            active_color=self.primary_color,
            on_change=self.toggle_night_mode
        )
        
        # Drawer menu items
        menu_items = [
            self.drawer_item("👤", "My Profile", lambda e: self.open_profile()),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("👥", "New Group", lambda e: self.page.run_task(self.create_new_group)),
            self.drawer_item("📢", "New Channel", lambda e: self.page.run_task(self.create_new_channel)),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("💾", "Saved Messages", lambda e: self.show_saved_messages()),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("⚙️", "Settings", lambda e: self.open_settings()),
            # Night mode with switch
            ft.Container(
                content=ft.Row([
                    ft.Text("🌙", size=20),
                    ft.Container(width=12),
                    ft.Text("Night Mode", size=16, color=self.text_color, expand=True),
                    self.night_mode_switch
                ], spacing=0),
                padding=ft.padding.symmetric(horizontal=20, vertical=12),
                on_click=lambda e: self.toggle_night_mode_click()
            ),
        ]
        
        # Create drawer
        self.drawer = ft.NavigationDrawer(
            controls=[
                drawer_header,
                ft.Container(
                    content=ft.Column(menu_items, spacing=0),
                    bgcolor=self.card_color,
                    expand=True
                )
            ],
            bgcolor=self.card_color,
        )
        
        self.page.drawer = self.drawer
    
    def drawer_item(self, emoji: str, text: str, on_click):
        """Create a drawer menu item"""
        return ft.Container(
            content=ft.Row([
                ft.Text(emoji, size=20),
                ft.Container(width=12),
                ft.Text(text, size=16, color=self.text_color)
            ], spacing=0),
            padding=ft.padding.symmetric(horizontal=20, vertical=14),
            on_click=on_click
        )
    
    def toggle_night_mode(self, e):
        """Toggle night/dark mode"""
        self.dark_mode = e.control.value
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        self.page.update()
    
    def toggle_night_mode_click(self):
        """Toggle night mode from row click"""
        self.dark_mode = not self.dark_mode
        self.night_mode_switch.value = self.dark_mode
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        self.page.update()
    
    def open_profile(self):
        """Open profile page"""
        self.page.drawer.open = False
        self.page.update()
        try:
            profile_view = ProfileView(
                page=self.page,
                api_client=self.api_client,
                current_user=self.current_user,
                on_back=lambda: self.page.run_task(self.load_chats)
            )
            self.page.clean()
            self.page.add(profile_view)
            self.page.update()
        except Exception as e:
            print(f"Error opening profile: {e}")
    
    async def create_new_group(self):
        """Create new group chat"""
        self.page.drawer.open = False
        self.page.update()
        
        name_field = ft.TextField(label="Group Name", autofocus=True)
        
        def create_click(e):
            if not name_field.value:
                name_field.error_text = "Name is required"
                name_field.update()
                return
            
            self.page.run_task(self.do_create_chat, name_field.value, "group", dialog)
        
        dialog = ft.AlertDialog(
            title=ft.Text("New Group"),
            content=ft.Column([
                ft.Text("Enter group name:"),
                name_field
            ], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton("Create", on_click=create_click)
            ]
        )
        self.page.open(dialog)
    
    async def create_new_channel(self):
        """Create new channel"""
        self.page.drawer.open = False
        self.page.update()
        
        name_field = ft.TextField(label="Channel Name", autofocus=True)
        
        def create_click(e):
            if not name_field.value:
                name_field.error_text = "Name is required"
                name_field.update()
                return
            
            self.page.run_task(self.do_create_chat, name_field.value, "channel", dialog)
        
        dialog = ft.AlertDialog(
            title=ft.Text("New Channel"),
            content=ft.Column([
                ft.Text("Enter channel name:"),
                name_field,
                ft.Text("Channels are for broadcasting public messages.", size=12, color=self.text_secondary)
            ], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton("Create", on_click=create_click)
            ]
        )
        self.page.open(dialog)
    
    async def do_create_chat(self, name: str, char_type: str, dialog):
        """Perform chat creation"""
        try:
            # Pass empty list for user_ids for now, or self user id
            user_id = self.current_user.get("id", self.current_user.get("_id"))
            await self.api_client.create_chat(name=name, user_ids=[user_id], chat_type=char_type)
            
            self.page.close(dialog)
            
            show_success("Success", f"{char_type.capitalize()} '{name}' created!")
            await self.load_chats()
            
        except Exception as e:
            print(f"Error creating {char_type}: {e}")
            self.page.close(dialog)
            error_msg = str(e)
            if "401" in error_msg or "403" in error_msg:
                self.show_session_expired_dialog()
            else:
                show_error("Error", f"Could not create {char_type}")
    
    def show_session_expired_dialog(self):
        """Show session expired dialog prompting user to re-login"""
        def do_logout(e):
            from session_manager import SessionManager
            SessionManager.clear_session()
            # Navigate to logout handler
            self.page.close(expired_dialog)
            if self.on_logout:
                self.on_logout()
        
        expired_dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(ft.Icons.WARNING, color=ft.Colors.ORANGE),
                ft.Text("Session Expired", weight=ft.FontWeight.BOLD)
            ]),
            content=ft.Column([
                ft.Text("Your session has expired and could not be refreshed."),
                ft.Text("Please log out and log in again to continue.", size=13),
                ft.Container(height=10),
                ft.Text("This usually happens when your login session is old.", size=12, color=ft.Colors.GREY)
            ], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(expired_dialog)),
                ft.ElevatedButton("Logout & Re-login", on_click=do_logout, bgcolor=ft.Colors.BLUE, color=ft.Colors.WHITE)
            ]
        )
        self.page.open(expired_dialog)

    
    def open_contacts(self):
        """Open contacts"""
        self.page.drawer.open = False
        self.page.update()
        self.show_coming_soon_dialog("Contacts", "View and manage your contacts")
    
    def open_calls(self):
        """Open calls history"""
        self.page.drawer.open = False
        self.page.update()
        self.show_coming_soon_dialog("Calls", "View your call history")
    
    def open_settings(self):
        """Open settings"""
        self.page.drawer.open = False
        self.page.update()
        try:
            settings_view = SettingsView(
                page=self.page,
                api_client=self.api_client,
                current_user=self.current_user,
                on_logout=self.on_logout,
                on_back=lambda: self.page.run_task(self.load_chats)
            )
            self.page.views.clear()
            self.page.views.append(settings_view)
            self.page.update()
        except Exception as e:
            print(f"Error opening settings: {e}")
            import traceback
            traceback.print_exc()
    
    def show_faq(self):
        """Show FAQ"""
        self.page.drawer.open = False
        self.page.update()
        self.show_coming_soon_dialog("Zaply FAQ", "Frequently asked questions")
    
    def show_features(self):
        """Show features"""
        self.page.drawer.open = False
        self.page.update()
        self.show_coming_soon_dialog("Zaply Features", "Discover what Zaply can do")
    
    def show_coming_soon_dialog(self, title: str, description: str):
        """Show coming soon dialog"""
        dialog = ft.AlertDialog(
            title=ft.Text(title),
            content=ft.Column([
                ft.Text(description),
                ft.Container(height=10),
                ft.Text("🚧 Coming soon in the next update!", color=self.text_secondary)
            ], tight=True),
            actions=[ft.TextButton("OK", on_click=lambda e: self.close_dialog(dialog))]
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def close_dialog(self, dialog):
        dialog.open = False
        self.page.update()
    
    def open_drawer(self):
        """Open navigation drawer"""
        self.page.drawer.open = True
        self.page.update()

    
    def build_ui(self):
        """Build the chats interface with Telegram-style left sidebar"""
        # Create Telegram-style left sidebar
        def create_telegram_sidebar():
            def on_theme_click(e):
                self.dark_mode = not self.dark_mode
                self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
                self.page.update()
            
            def on_menu_click(e):
                self.open_drawer()
            
            def on_search_click(e):
                self.show_search_dialog()
            
            # Search bar with light-blue theme
            search_bar = ft.Container(
                content=ft.TextField(
                    hint_text="Search...",
                    border=ft.InputBorder.NONE,
                    filled=True,
                    text_size=14,
                    content_padding=ft.padding.symmetric(horizontal=15, vertical=8),
                    bgcolor=self.accent_light,
                    focused_border_color=self.primary_color,
                    on_click=on_search_click
                ),
                width=200,
                height=40,
                border_radius=20,
                bgcolor=self.accent_light
            )
            
            # Menu button with light-blue theme
            menu_button = ft.Container(
                content=ft.IconButton(
                    icon=icons.MENU,
                    icon_size=18,
                    icon_color=self.primary_color,
                    tooltip="Menu",
                    style=ft.ButtonStyle(
                        bgcolor=self.accent_light,
                        padding=8,
                        shape=ft.CircleBorder(),
                        overlay_color=self.accent_hover
                    ),
                    on_click=on_menu_click
                ),
                width=36,
                height=36,
                bgcolor=self.accent_light,
                border_radius=18
            )
            
            # Theme toggle button with light-blue theme
            theme_button = ft.Container(
                content=ft.IconButton(
                    icon=icons.BRIGHTNESS_6 if not self.dark_mode else icons.BRIGHTNESS_4,
                    icon_size=18,
                    icon_color=self.primary_color,
                    tooltip="Toggle Theme",
                    style=ft.ButtonStyle(
                        bgcolor=self.accent_light,
                        padding=8,
                        shape=ft.CircleBorder(),
                        overlay_color=self.accent_hover
                    ),
                    on_click=on_theme_click
                ),
                width=36,
                height=36,
                bgcolor=self.accent_light,
                border_radius=18
            )
            
            # Left sidebar container
            sidebar = ft.Container(
                content=ft.Column([
                    # Search bar at top
                    search_bar,
                    ft.Container(height=10),
                    # Menu button
                    menu_button,
                    ft.Container(height=8),
                    # Theme toggle button
                    theme_button,
                    ft.Container(height=20),
                    # Divider
                    ft.Container(height=1, bgcolor="#E0E0E0"),
                    ft.Container(height=20),
                    # Additional options
                    ft.Text("Options", size=12, color=ft.Colors.GREY),
                ], spacing=0, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                width=240,
                padding=ft.padding.all(15),
                bgcolor="#FFFFFF",
                border=ft.border.only(right=ft.BorderSide(1, "#E0E0E0")),
                alignment=ft.alignment.top_center
            )
            
            return sidebar
        
        # AppBar - Light blue themed
        self.page.appbar = ft.AppBar(
            title=ft.Text("Zaply", weight=ft.FontWeight.BOLD, color="#0088CC"),
            center_title=False,
            bgcolor="#FFFFFF",
            elevation=0.5,
            actions=[]  # No actions - all in sidebar
        )
        
        # Chat list
        self.chat_list = ft.ListView(
            expand=True,
            spacing=1,
            padding=ft.padding.symmetric(vertical=8)
        )
        
        # Loading indicator with light-blue theme
        self.loading_indicator = ft.Container(
            content=ft.Column(
                [
                    ft.ProgressRing(width=30, height=30, color=self.primary_color),
                    ft.Text("Loading chats...", color=self.text_secondary),
                    ft.Container(
                        content=ft.Text("⚡ Fast & Secure Messaging", size=12, color=self.primary_color),
                        margin=ft.margin.only(top=10)
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10
            ),
            alignment=ft.alignment.center,
            expand=True
        )
        
        # Create main layout with left sidebar
        sidebar = create_telegram_sidebar()
        main_content = ft.Container(
            content=self.chat_list,
            bgcolor=self.bg_color,
            expand=True,
            padding=ft.padding.all(16)
        )
        
        main_layout = ft.Row([
            sidebar,  # Left sidebar
            main_content,  # Chat list
        ], spacing=0, expand=True)
        
        # Set initial content
        self.content = [
            ft.Container(
                content=self.loading_indicator,
                bgcolor=self.bg_color,
                expand=True
            )
        ]
        
        # Add to page
        self.page.add(self.content)
        self.page.update()
        
        # Load chats
        self.page.run_task(self.load_chats)
    
    async def load_chats(self):
        """Load chats from API"""
        try:
            self.loading = True
            self.update_content(self.loading_indicator)
            
            debug_log(f"[CHATS] Loading chats from {API_URL}/api/v1/chats/")
            response = await self.api_client.get("/api/v1/chats/")
            debug_log(f"[CHATS] Response status: {response.status_code if hasattr(response, 'status_code') else 'No status'}")
            
            if hasattr(response, 'status_code') and response.status_code == 200:
                payload = response.json() if hasattr(response, 'json') else {"chats": []}
                self.chats = payload.get("chats", [])
                debug_log(f"[CHATS] Loaded {len(self.chats)} chats")
                self.update_chat_list()
            else:
                debug_log(f"[CHATS] Failed to load chats")
                self.update_chat_list()
                
        except Exception as ex:
            debug_log(f"[CHATS] Error loading chats: {type(ex).__name__}: {ex}")
            self.update_chat_list()
        finally:
            self.loading = False
    
    def update_chat_list(self):
        """Update the chat list display with unread counts and timestamps"""
        chat_items = []
        
        # Add regular chats
        for chat in self.chats:
            if chat.get("type") == "saved":
                continue
                
            chat_name = chat.get("name") or ("Group Chat" if chat.get("type") == "group" else "Private Chat")
            
            # Determine avatar based on chat type with light-blue theme
            if chat.get("type") == "group":
                avatar_content = ft.Icon(icons.GROUP, size=40, color=ft.Colors.WHITE)
                avatar_bg = "#7C3AED"  # Purple for groups
            elif chat.get("type") == "channel":
                avatar_content = ft.Icon(icons.CAMPAIGN, size=40, color=ft.Colors.WHITE)
                avatar_bg = "#EC4899"  # Pink for channels
            else:
                first_letter = (chat_name or "?")[0].upper()
                avatar_content = ft.Text(first_letter, size=20, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)
                avatar_bg = self.primary_color  # Light blue for private chats
            
            avatar = ft.Container(
                content=avatar_content,
                width=56,
                height=56,
                bgcolor=avatar_bg,
                border_radius=28,
                alignment=ft.alignment.center,
                shadow=ft.BoxShadow(
                    spread_radius=0,
                    blur_radius=2,
                    color=ft.Colors.with_opacity(0.12, ft.Colors.BLACK),
                    offset=ft.Offset(0, 1),
                )
            )
            
            last_message_obj = chat.get("last_message") or {}
            last_message_text = last_message_obj.get("text", "No messages yet")
            last_message_time = last_message_obj.get("timestamp") or chat.get("updated_at", "")
            
            # Format timestamp to relative time (e.g., "2m ago", "Yesterday")
            time_label = self.format_timestamp(last_message_time)
            
            # Get unread count
            unread_count = chat.get("unread_count", 0)
            
            # Create unread badge if needed with light-blue accent
            unread_badge = ft.Container(
                content=ft.Text(
                    str(unread_count),
                    size=12,
                    weight=ft.FontWeight.BOLD,
                    color=ft.Colors.WHITE
                ),
                width=24,
                height=24,
                bgcolor=self.primary_color,  # Light blue for unread
                border_radius=12,
                alignment=ft.alignment.center,
                shadow=ft.BoxShadow(
                    spread_radius=0,
                    blur_radius=4,
                    color=ft.Colors.with_opacity(0.3, self.primary_color),
                    offset=ft.Offset(0, 1)
                )
            ) if unread_count > 0 else ft.Container()
            
            chat_item = ft.Container(
                content=ft.Row(
                    [
                        avatar,
                        ft.Column(
                            [
                                ft.Row([
                                    ft.Text(
                                        chat_name,
                                        size=16,
                                        weight=ft.FontWeight.W_600 if unread_count > 0 else ft.FontWeight.W_500,
                                        color=self.text_color,
                                        expand=True,
                                        no_wrap=True
                                    ),
                                    ft.Text(
                                        time_label,
                                        size=12,
                                        color=self.primary_color if unread_count > 0 else self.text_secondary,
                                        weight=ft.FontWeight.W_500 if unread_count > 0 else ft.FontWeight.NORMAL
                                    )
                                ], spacing=10, alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                                ft.Row([
                                    ft.Text(
                                        last_message_text[:40] + "..." if len(last_message_text) > 40 else last_message_text,
                                        size=13,
                                        color=self.text_color if unread_count > 0 else self.text_secondary,
                                        no_wrap=True,
                                        expand=True,
                                        weight=ft.FontWeight.W_600 if unread_count > 0 else ft.FontWeight.NORMAL
                                    ),
                                    unread_badge
                                ], spacing=10, alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
                            ],
                            spacing=5,
                            expand=True
                        )
                    ],
                    spacing=15,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER
                ),
                padding=12,
                bgcolor=self.accent_light if unread_count > 0 else self.card_color,
                border_radius=12,
                on_click=lambda e, c=chat: self.page.run_task(self.open_chat, c),
                margin=ft.margin.symmetric(horizontal=8, vertical=4),
                shadow=ft.BoxShadow(
                    spread_radius=0,
                    blur_radius=2 if unread_count > 0 else 0.5,
                    color=ft.Colors.with_opacity(0.1 if unread_count > 0 else 0.05, ft.Colors.BLACK),
                    offset=ft.Offset(0, 1),
                ),
                animate=ft.animation.Animation(200, ft.AnimationCurve.EASE_OUT)
            )
            chat_items.append(chat_item)
    
    def format_timestamp(self, timestamp: str) -> str:
        """Format timestamp to relative time"""
        if not timestamp:
            return ""
        
        try:
            from datetime import datetime
            msg_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            now = datetime.now(msg_time.tzinfo)
            diff = now - msg_time
            
            seconds = diff.total_seconds()
            if seconds < 60:
                return "now"
            elif seconds < 3600:
                return f"{int(seconds // 60)}m"
            elif seconds < 86400:
                return f"{int(seconds // 3600)}h"
            elif seconds < 604800:
                return f"{int(seconds // 86400)}d"
            else:
                return msg_time.strftime("%b %d")
        except:
            return ""
        
        # Add Saved Messages at the end
        if chat_items:
            if chat_items and isinstance(chat_items[-1], ft.Divider):
                chat_items.pop()
            chat_items.append(ft.Divider(height=1, color="#E0E0E0"))
        
        saved_messages_item = ft.Container(
            content=ft.Row(
                [
                    ft.CircleAvatar(
                        content=ft.Icon(icons.BOOKMARK, size=24, color=ft.Colors.WHITE),
                        bgcolor=self.primary_color,
                        radius=20
                    ),
                    ft.Column(
                        [
                            ft.Text(
                                "Saved Messages",
                                size=16,
                                weight=ft.FontWeight.W_600,
                                color=self.text_color
                            ),
                            ft.Text(
                                "Your personal collection",
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
            on_click=lambda e: self.show_saved_messages(),
            bgcolor=self.accent_light,
            border_radius=12,
            margin=ft.margin.symmetric(horizontal=8, vertical=4),
            shadow=ft.BoxShadow(
                spread_radius=0,
                blur_radius=1,
                color=ft.Colors.with_opacity(0.08, ft.Colors.BLACK),
                offset=ft.Offset(0, 1),
            ),
            animate=ft.animation.Animation(200, ft.AnimationCurve.EASE_OUT)
        )
        chat_items.append(saved_messages_item)
        
        # Update chat list
        self.chat_list.controls = chat_items if chat_items else [
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
        
        # Create Telegram-style sidebar for updated content
        def create_telegram_sidebar():
            def on_theme_click(e):
                self.dark_mode = not self.dark_mode
                self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
                self.page.update()
            
            def on_menu_click(e):
                self.open_drawer()
            
            def on_search_click(e):
                self.show_search_dialog()
            
            # Search bar with light-blue theme
            search_bar = ft.Container(
                content=ft.TextField(
                    hint_text="Search...",
                    border=ft.InputBorder.NONE,
                    filled=True,
                    text_size=14,
                    content_padding=ft.padding.symmetric(horizontal=15, vertical=8),
                    bgcolor=self.accent_light,
                    focused_border_color=self.primary_color,
                    on_click=on_search_click
                ),
                width=200,
                height=40,
                border_radius=20,
                bgcolor=self.accent_light
            )
            
            # Menu button with light-blue theme
            menu_button = ft.Container(
                content=ft.IconButton(
                    icon=icons.MENU,
                    icon_size=18,
                    icon_color=self.primary_color,
                    tooltip="Menu",
                    style=ft.ButtonStyle(
                        bgcolor=self.accent_light,
                        padding=8,
                        shape=ft.CircleBorder(),
                        overlay_color=self.accent_hover
                    ),
                    on_click=on_menu_click
                ),
                width=36,
                height=36,
                bgcolor=self.accent_light,
                border_radius=18
            )
            
            # Theme toggle button with light-blue theme
            theme_button = ft.Container(
                content=ft.IconButton(
                    icon=icons.BRIGHTNESS_6 if not self.dark_mode else icons.BRIGHTNESS_4,
                    icon_size=18,
                    icon_color=self.primary_color,
                    tooltip="Toggle Theme",
                    style=ft.ButtonStyle(
                        bgcolor=self.accent_light,
                        padding=8,
                        shape=ft.CircleBorder(),
                        overlay_color=self.accent_hover
                    ),
                    on_click=on_theme_click
                ),
                width=36,
                height=36,
                bgcolor=self.accent_light,
                border_radius=18
            )
            
            # Left sidebar container
            sidebar = ft.Container(
                content=ft.Column([
                    # Search bar at top
                    search_bar,
                    ft.Container(height=10),
                    # Menu button
                    menu_button,
                    ft.Container(height=8),
                    # Theme toggle button
                    theme_button,
                    ft.Container(height=20),
                    # Divider
                    ft.Container(height=1, bgcolor="#E0E0E0"),
                    ft.Container(height=20),
                    # Additional options
                    ft.Text("Options", size=12, color=ft.Colors.GREY),
                ], spacing=0, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                width=240,
                padding=ft.padding.all(15),
                bgcolor="#FFFFFF",
                border=ft.border.only(right=ft.BorderSide(1, "#E0E0E0")),
                alignment=ft.alignment.top_center
            )
            
            return sidebar
        
        # Update main content with sidebar
        main_content = ft.Container(
            content=self.chat_list,
            bgcolor=self.bg_color,
            expand=True,
            padding=ft.padding.all(16)
        )
        
        sidebar = create_telegram_sidebar()
        main_layout = ft.Row([
            sidebar,  # Left sidebar
            main_content,  # Chat list
        ], spacing=0, expand=True)
        
        self.update_content(main_layout)
    
    def update_content(self, content):
        """Update the main content"""
        self.content.clear()
        self.content.append(content)
        self.page.update()
    
    def show_saved_messages(self):
        """Show saved messages view"""
        try:
            saved_view = SavedMessagesView(
                page=self.page,
                api_client=self.api_client,
                current_user=self.current_user.get("id", self.current_user.get("_id")),
                on_back=lambda: self.page.run_task(self.load_chats)
            )
            
            self.page.clean()
            self.page.add(saved_view)
            self.page.update()
        except Exception as e:
            debug_log(f"[CHATS] Error showing saved messages: {e}")
            show_error("Error", "Could not open saved messages")
    
    def open_chat(self, chat: dict):
        """Open a specific chat with full messaging interface"""
        debug_log(f"[CHATS] Opening chat: {chat.get('name', 'Unknown')}")
        try:
            from views.message_view import MessageView
            
            message_view = MessageView(
                page=self.page,
                api_client=self.api_client,
                chat=chat,
                current_user=self.current_user.get("id", self.current_user.get("_id", "")),
                on_back=lambda: self.page.run_task(self.return_to_chats),
                dark_mode=False
            )
            
            self.page.clean()
            self.page.views.append(message_view)
            self.page.update()
        except Exception as e:
            debug_log(f"[CHATS] Error opening chat: {e}")
            print(f"Error opening chat: {e}")
    
    async def return_to_chats(self):
        """Return to chats list after closing a chat"""
        self.page.views.pop()
        self.build_ui()
        await self.load_chats()

    
    def new_chat(self, e):
        """Start new chat"""
        # User search and chat creation - coming soon
        print("New chat feature - user search coming in next update")
    
    async def handle_logout(self, e):
        """Logout"""
        try:
            await self.api_client.logout()
            if self.on_logout:
                self.on_logout()
        except Exception as ex:
            debug_log(f"[CHATS] Logout error: {ex}")
            show_error("Error", "Could not logout")
    
    def show_search_dialog(self):
        """Show search dialog with filtering options"""
        search_field = ft.TextField(
            label="Search chats and users...",
            autofocus=True,
            on_change=self.filter_chats
        )
        
        # Search results container
        search_results = ft.ListView(expand=True, spacing=1)
        
        async def update_search(e):
            """Update search results as user types"""
            query = search_field.value.lower().strip()
            search_results.controls.clear()
            
            if not query:
                search_results.controls.append(
                    ft.Container(
                        content=ft.Text(
                            "Type to search chats by name or find new users",
                            color=self.text_secondary,
                            text_align=ft.TextAlign.CENTER
                        ),
                        padding=20,
                        alignment=ft.alignment.center
                    )
                )
            else:
                found = False
                
                # Search existing chats
                for chat in self.chats:
                    # Search by chat name
                    chat_name = chat.get("name") or ("Group Chat" if chat.get("type") == "group" else "Private Chat")
                    if query in chat_name.lower():
                        found = True
                        chat_item = ft.Container(
                            content=ft.Row([
                                ft.Icon(
                                    ft.Icons.CAMPAIGN if chat.get("type") == "channel" else ft.Icons.GROUP if chat.get("type") == "group" else ft.Icons.PERSON,
                                    size=24,
                                    color=self.primary_color
                                ),
                                ft.Column([
                                    ft.Text(chat_name, weight=ft.FontWeight.W_500),
                                    ft.Text(f"{len(chat.get('members', []))} members", size=12, color=self.text_secondary)
                                ], expand=True, spacing=2)
                            ], spacing=15),
                            padding=12,
                            on_click=lambda e, c=chat: self.open_chat(c)
                        )
                        search_results.controls.append(chat_item)
                        search_results.controls.append(ft.Divider(height=1, color="#E0E0E0"))
                
                # Search for new users
                try:
                    users_data = await self.api_client.search_users(query)
                    users = users_data.get("users", [])
                    
                    if users:
                        # Add section header for new users
                        if found:  # Only add header if we already found chats
                            search_results.controls.append(
                                ft.Container(
                                    content=ft.Text(
                                        "New Users",
                                        size=14,
                                        weight=ft.FontWeight.W_600,
                                        color=self.text_secondary
                                    ),
                                    padding=ft.padding.symmetric(horizontal=12, vertical=8)
                                )
                            )
                        
                        for user in users:
                            found = True
                            user_item = ft.Container(
                                content=ft.Row([
                                    ft.CircleAvatar(
                                        content=ft.Text(
                                            user["name"][0].upper(),
                                            size=16,
                                            weight=ft.FontWeight.BOLD,
                                            color=ft.Colors.WHITE
                                        ),
                                        bgcolor=self.primary_color,
                                        radius=20
                                    ),
                                    ft.Column([
                                        ft.Text(user["name"], weight=ft.FontWeight.W_500),
                                        ft.Text(user["email"], size=12, color=self.text_secondary)
                                    ], expand=True, spacing=2),
                                    ft.IconButton(
                                        icon=ft.Icons.MESSAGE,
                                        icon_color=self.primary_color,
                                        tooltip="Start chat",
                                        on_click=lambda e, u=user: self.start_new_chat(u)
                                    )
                                ], spacing=15),
                                padding=12,
                                bgcolor="#F8F9FA",
                                border_radius=8
                            )
                            search_results.controls.append(user_item)
                            search_results.controls.append(ft.Divider(height=1, color="#E0E0E0"))
                
                except Exception as search_e:
                    print(f"[CHATS] User search error: {search_e}")
                    # Continue without user search results
                
                if not found:
                    search_results.controls.append(
                        ft.Container(
                            content=ft.Text(
                                "No chats or users found",
                                color=self.text_secondary,
                                text_align=ft.TextAlign.CENTER
                            ),
                            padding=20,
                            alignment=ft.alignment.center
                        )
                    )
            
            self.page.update()
        
        search_field.on_change = lambda e: self.page.run_task(update_search, e)
        
        # Initial message
        search_results.controls.append(
            ft.Container(
                content=ft.Text(
                    "Type to search chats by name or find new users",
                    color=self.text_secondary,
                    text_align=ft.TextAlign.CENTER
                ),
                padding=20,
                alignment=ft.alignment.center
            )
        )
        
        dialog = ft.AlertDialog(
            title=ft.Text("Search", weight=ft.FontWeight.BOLD),
            content=ft.Container(
                content=ft.Column([
                    search_field,
                    ft.Divider(),
                    search_results
                ], spacing=10, expand=True),
                width=450,
                height=600
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))
            ]
        )
        
        self.page.open(dialog)
    
    def filter_chats(self, e):
        """Filter chats based on search query"""
        # This is handled by the update_search callback in show_search_dialog
        pass
    
    async def start_new_chat(self, user: dict):
        """Start a new chat with searched user"""
        try:
            # Current user ID lo
            current_user_id = self.current_user.get("id") or self.current_user.get("_id")
            if not current_user_id:
                print("[CHATS] Error: Current user ID nahi mila")
                return
            
            print(f"[CHATS] {user['name']} ke saath new chat start kar rahe hain...")
            
            # Loading indicator
            self.page.dialog.open = False
            loading_snack = ft.SnackBar(
                content=ft.Row([
                    ft.ProgressRing(width=16, height=16, stroke_width=2),
                    ft.Text("Chat ban rahe hain...")
                ], spacing=10),
                duration=30000
            )
            self.page.overlay.append(loading_snack)
            loading_snack.open = True
            self.page.update()
            
            # Private chat create karo
            result = await self.api_client.create_chat(
                name=None,  # Private chats ko name nahi chahiye
                user_ids=[current_user_id, user["id"]],
                chat_type="private"
            )
            
            # Loading hatao
            loading_snack.open = False
            self.page.update()
            
            # Success message
            snack = ft.SnackBar(
                content=ft.Text(f"✅ {user['name']} ke saath chat start ho gaya!"),
                bgcolor=ft.Colors.GREEN
            )
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
            
            print(f"[CHATS] Chat successfully create kiya")
            
            # Chats reload karo naye chat dikhane ke liye
            await self.load_chats()
            
            # Naya chat open karo
            chat_id = result.get("chat_id")
            if chat_id:
                # Chat list mein dhundo
                for chat in self.chats:
                    if chat.get("_id") == chat_id or chat.get("id") == chat_id:
                        self.open_chat(chat)
                        break
            
        except Exception as e:
            error_msg = str(e)
            print(f"[CHATS] New chat start karne mein error: {error_msg}")
            
            # Loading hatao
            if 'loading_snack' in locals():
                loading_snack.open = False
                self.page.update()
            
            # Error message dikhao
            if "401" in error_msg or "Session expired" in error_msg:
                # Session expired - special handling
                from session_manager import SessionManager
                SessionManager.clear_session()
                self.api_client.clear_tokens()
                
                error_snack = ft.SnackBar(
                    content=ft.Text("Session expire ho gaya! Dubara login karo."),
                    bgcolor=ft.Colors.ORANGE
                )
            else:
                error_snack = ft.SnackBar(
                    content=ft.Text(f"Chat start nahi hua: {error_msg[:50]}"),
                    bgcolor=ft.Colors.RED
                )
            
            self.page.overlay.append(error_snack)
            error_snack.open = True
            self.page.update()

    def go_back(self):
        """Go back to previous screen"""
        self.page.go("/")

