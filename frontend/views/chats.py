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
ft.colors = ft.Colors

# dotenv is optional in some Android build environments; import defensively
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):  # type: ignore
        return None

# Load environment variables if available
load_dotenv()

# Default backend URL - use localhost for development
DEFAULT_DEV_URL = "http://localhost:8000"
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
        
        self.build_ui()
    
    def build_ui(self):
        """Build the chats interface"""
        # AppBar
        self.page.appbar = ft.AppBar(
            title=ft.Text("Chats", weight=ft.FontWeight.BOLD, color=ft.colors.BLACK),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=ft.colors.BLACK,
                on_click=lambda e: self.go_back()
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
                on_click=lambda e, c=chat: self.open_chat(c),
                ink=True
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