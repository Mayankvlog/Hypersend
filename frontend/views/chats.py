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
    def __init__(self, page: ft.Page, api_client: APIClient, current_user: dict, on_logout=None):
        super().__init__("/")
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_logout = on_logout
        
        # Theme colors
        self.primary_color = "#1F8EF1"
        self.bg_color = "#FDFBFB"
        self.card_color = "#FFFFFF"
        self.text_color = "#000000"
        self.text_secondary = "#8e8e93"
        
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
        """Build the chats interface"""
        # AppBar with hamburger menu
        self.page.appbar = ft.AppBar(
            title=ft.Text("Zaply", weight=ft.FontWeight.BOLD, color=ft.Colors.BLACK, size=22),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.Icons.MENU,
                icon_color=ft.Colors.BLACK,
                tooltip="Menu",
                on_click=lambda e: self.open_drawer()
            ),

            actions=[
                ft.IconButton(
                    icon=ft.Icons.SEARCH,
                    tooltip="Search",
                    on_click=lambda e: print("Search coming soon")
                ),
                ft.PopupMenuButton(
                    icon=ft.Icons.MORE_VERT,
                    tooltip="More Options",
                    items=[
                        ft.PopupMenuItem(
                            text="👤 Profile",
                            icon=ft.Icons.PERSON,
                            on_click=lambda e: self.page.go("/profile")
                        ),
                        ft.PopupMenuItem(
                            text="⚙️ Settings",
                            icon=ft.Icons.SETTINGS,
                            on_click=lambda e: self.page.go("/settings")
                        ),
                    ]
                )
            ]
        )
        
        # Chat list
        self.chat_list = ft.ListView(
            expand=True,
            spacing=1,
            padding=ft.padding.symmetric(vertical=8)
        )
        
        # Loading indicator
        self.loading_indicator = ft.Container(
            content=ft.Column(
                [
                    ft.ProgressRing(width=30, height=30, color=self.primary_color),
                    ft.Text("Loading chats...", color=self.text_secondary)
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10
            ),
            alignment=ft.alignment.center,
            expand=True
        )
        
        # Main content
        self.main_content = ft.Container(
            content=self.chat_list,
            bgcolor=self.bg_color,
            expand=True,
            padding=ft.padding.all(16)
        )
        
        # Saved Messages item
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
                                weight=ft.FontWeight.W_500,
                                color=ft.Colors.BLACK
                            ),
                            ft.Text(
                                "Your personal collection",
                                size=13,
                                color=ft.Colors.BLACK54
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
            bgcolor=ft.Colors.WHITE
        )
        
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
        """Update the chat list display"""
        chat_items = []
        
        # Add regular chats
        for chat in self.chats:
            if chat.get("type") == "saved":
                continue
                
            chat_name = chat.get("name") or ("Group Chat" if chat.get("type") == "group" else "Private Chat")
            
            # Determine avatar based on chat type
            if chat.get("type") == "group":
                avatar = ft.Icon(icons.GROUP, size=40)
            elif chat.get("type") == "channel":
                avatar = ft.Icon(icons.CAMPAIGN, size=40)
            else:
                avatar = ft.CircleAvatar(
                    content=ft.Text(
                        (chat_name or "?")[0].upper(),
                        size=20,
                        weight=ft.FontWeight.BOLD
                    ),
                    bgcolor=self.primary_color
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
                                    color=self.text_color
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
                on_click=lambda e, c=chat: self.open_chat(c)
            )
            chat_items.append(chat_item)
            chat_items.append(ft.Divider(height=1, color="#E0E0E0"))
        
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
                                weight=ft.FontWeight.W_500,
                                color=ft.Colors.BLACK
                            ),
                            ft.Text(
                                "Your personal collection",
                                size=13,
                                color=ft.Colors.BLACK54
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
            bgcolor=ft.Colors.WHITE
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
        
        # Update main content
        main_content = ft.Container(
            content=self.chat_list,
            bgcolor=self.bg_color,
            expand=True,
            padding=ft.padding.all(16)
        )
        
        self.update_content(main_content)
    
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
    
    def go_back(self):
        """Go back to previous screen"""
        self.page.go("/")

