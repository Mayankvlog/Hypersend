"""
Saved Messages View - Minimal Clean Design
Clean, simple UI for personal message storage
"""

import flet as ft
import asyncio
import sys
import os
from typing import Optional, List, Dict, Any
from datetime import datetime

# Add parent directory to sys.path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from api_client import APIClient
    from theme import ZaplyTheme, LIGHT_COLORS, DARK_COLORS, FONT_SIZES, SPACING, RADIUS
    from emoji_data import EMOJI_CATEGORIES, POPULAR_EMOJIS, UNIQUE_EMOJIS
except ImportError:
    # Fallback for different import contexts
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from api_client import APIClient
    from theme import ZaplyTheme, LIGHT_COLORS, DARK_COLORS, FONT_SIZES, SPACING, RADIUS
    from emoji_data import EMOJI_CATEGORIES, POPULAR_EMOJIS, UNIQUE_EMOJIS



# Compatibility shims
icons = ft.Icons
colors = ft.Colors
ft.Colors = ft.Colors


class SavedMessagesView(ft.View):
    def __init__(self, page: ft.Page, api_client: APIClient, current_user: str, on_back=None, dark_mode: bool = False):
        super().__init__("/saved")
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_back = on_back
        
        # Theme
        self.theme = ZaplyTheme(dark_mode=dark_mode)
        self.dark_mode = dark_mode
        
        # State
        self.messages = []
        self.loading = False
        
        # File picker
        self.file_picker = ft.FilePicker(on_result=lambda e: self.page.run_task(self.handle_file_upload, e))
        self.page.overlay.append(self.file_picker)
        
        self.build_ui()
    
    def build_ui(self):
        """Build the minimal clean saved messages interface"""
        colors_palette = self.theme.colors
        
        # Theme toggle icon
        theme_icon = ft.Icons.LIGHT_MODE if self.dark_mode else ft.Icons.DARK_MODE
        
        # AppBar with chat info
        avatar_color = colors_palette["accent"]
        self.appbar = ft.AppBar(
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=colors_palette["text_primary"],
                on_click=lambda e: self.go_back(),
                tooltip="Back"
            ),
            leading_width=40,
            title_spacing=0,
            title=ft.Row([
                ft.Container(
                    content=ft.Icon(ft.Icons.BOOKMARK, color=ft.Colors.WHITE, size=24),
                    width=42,
                    height=42,
                    bgcolor=avatar_color,
                    border_radius=21,
                    alignment=ft.alignment.center,
                ),
                ft.Container(width=10),
                ft.Column([
                    ft.Text(
                        "Saved Messages",
                        size=16,
                        weight=ft.FontWeight.W_600,
                        color=colors_palette["text_primary"]
                    ),
                    ft.Text(
                        "cloud storage",
                        size=12,
                        color=colors_palette["text_tertiary"]
                    )
                ], spacing=0, alignment=ft.MainAxisAlignment.CENTER)
            ], spacing=0),
            bgcolor=colors_palette["bg_primary"],
            elevation=0.5,
            actions=[
                ft.IconButton(
                    icon=ft.Icons.SEARCH,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Search",
                    on_click=lambda e: self.show_coming_soon("Search")
                ),
                ft.IconButton(
                    icon=ft.Icons.BRIGHTNESS_6,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Toggle Theme",
                    on_click=lambda e: self.toggle_theme()
                ),
                ft.IconButton(
                    icon=ft.Icons.MENU,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Menu",
                    on_click=lambda e: self.open_drawer()
                ),
                ft.PopupMenuButton(
                    icon=ft.Icons.MORE_VERT,
                    icon_color=colors_palette["text_primary"],
                    tooltip="More",
                    items=[
                        ft.PopupMenuItem(text="Clear history", icon=ft.Icons.DELETE_OUTLINE, on_click=lambda e: self.show_coming_soon("Clear")),
                    ]
                )
            ]
        )
        
        # Build drawer
        self.build_drawer()
        self.page.drawer = self.drawer
        
        # Initialize messages list and input area
        self.init_messages_area()

    def build_drawer(self):
        """Build Telegram-style navigation drawer"""
        user_name = "User"
        user_email = ""
        user_initials = "U"

        if isinstance(self.current_user, dict):
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
                    bgcolor=self.theme.colors["accent"],
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
            bgcolor=self.theme.colors["accent"],
        )
        
        # Night mode switch
        self.night_mode_switch = ft.Switch(
            value=self.dark_mode,
            active_color=self.theme.colors["accent"],
            on_change=self.toggle_night_mode
        )
        
        # Drawer menu items
        menu_items = [
            self.drawer_item("👤", "My Profile", lambda e: self.page.go("/profile")),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("👥", "New Group", lambda e: self.page.run_task(self.create_new_group)),
            self.drawer_item("📢", "New Channel", lambda e: self.page.run_task(self.create_new_channel)),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("💾", "Saved Messages", lambda e: self.close_drawer()), # Already here
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("⚙️", "Settings", lambda e: self.open_settings()),
            # Night mode with switch
            ft.Container(
                content=ft.Row([
                    ft.Text("🌙", size=20),
                    ft.Container(width=12),
                    ft.Text("Night Mode", size=16, color=self.theme.colors["text_primary"], expand=True),
                    self.night_mode_switch
                ], spacing=0),
                padding=ft.padding.symmetric(horizontal=20, vertical=12),
                on_click=lambda e: self.toggle_night_mode_click()
            ),
            ft.Divider(),
            self.drawer_item("⬅️", "Back to Chats", lambda e: self.go_back()),
        ]
        
        self.drawer = ft.NavigationDrawer(
            controls=[
                drawer_header,
                ft.Container(
                    content=ft.Column(menu_items, spacing=0),
                    expand=True
                )
            ],
            bgcolor=self.theme.colors["bg_primary"]
        )

    def drawer_item(self, emoji: str, text: str, on_click):
        """Create a drawer menu item"""
        return ft.Container(
            content=ft.Row([
                ft.Text(emoji, size=20),
                ft.Container(width=12),
                ft.Text(text, size=16, color=self.theme.colors["text_primary"])
            ], spacing=0),
            padding=ft.padding.symmetric(horizontal=20, vertical=14),
            on_click=on_click
        )

    def open_drawer(self):
        self.page.drawer = self.drawer
        self.drawer.open = True
        self.page.update()
    
    def close_drawer(self):
        self.drawer.open = False
        self.page.update()

    def open_settings(self):
        """Open settings view"""
        self.close_drawer()
        try:
            from views.settings import SettingsView
            # Capture page reference to avoid NoneType error when view is detached
            page = self.page
            settings_view = SettingsView(
                page=page,
                api_client=self.api_client,
                current_user={"id": self.current_user} if isinstance(self.current_user, str) else self.current_user,
                on_logout=None,
                on_back=lambda: page.run_task(self.return_to_saved, page)
            )
            self.page.views.clear()
            self.page.views.append(settings_view)
            self.page.update()
        except Exception as e:
            print(f"Error opening settings: {e}")
            self.show_error(f"Could not open settings: {e}")
    
    async def return_to_saved(self, page=None):
        """Return from settings to saved messages"""
        if page:
            self.page = page
            # Ensure view is back in views list
            if self not in self.page.views:
                self.page.views.clear()
                self.page.views.append(self)
        
        self.build_ui()
        await self.load_saved_messages()
        self.page.update()

    def toggle_night_mode(self, e):
        """Toggle night/dark mode"""
        self.dark_mode = e.control.value
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        self.toggle_theme() # Updates local UI
        self.page.update()
    
    def toggle_night_mode_click(self):
        """Toggle night mode from row click"""
        self.dark_mode = not self.dark_mode
        self.night_mode_switch.value = self.dark_mode
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        self.toggle_theme()
        self.page.update()

    def show_coming_soon(self, feature: str):
        self.close_drawer()
        snack = ft.SnackBar(content=ft.Text(f"{feature} coming soon!"), duration=2000)
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()

    async def create_new_group(self):
        self.close_drawer()
        name_field = ft.TextField(label="Group Name", autofocus=True)
        
        def create_click(e):
            if not name_field.value:
                name_field.error_text = "Name is required"
                name_field.update()
                return
            self.page.run_task(self.do_create_chat, name_field.value, "group", dialog)
        
        dialog = ft.AlertDialog(
            title=ft.Text("New Group"),
            content=ft.Column([ft.Text("Enter group name:"), name_field], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton("Create", on_click=create_click)
            ]
        )
        self.page.open(dialog)

    async def create_new_channel(self):
        self.close_drawer()
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
                ft.Text("Channels are for broadcasting.", size=12)
            ], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton("Create", on_click=create_click)
            ]
        )
        self.page.open(dialog)

    async def do_create_chat(self, name: str, char_type: str, dialog):
        try:
            # Need to get user ID. If string, use it. If dict, use id/_id
            user_id = self.current_user if isinstance(self.current_user, str) else self.current_user.get("id", self.current_user.get("_id"))
            
            result = await self.api_client.create_chat(name=name, user_ids=[user_id], chat_type=char_type)
            self.page.close(dialog)
            
            # Show success
            snack = ft.SnackBar(content=ft.Text(f"✅ {char_type.capitalize()} '{name}' created!"), bgcolor=ft.Colors.GREEN)
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
            
            # Navigate back to chat list to see the new chat
            if self.on_back:
                self.on_back()
            
        except Exception as e:
            print(f"Error creating {char_type}: {e}")
            self.page.close(dialog)
            error_msg = str(e)
            if "Backend route mismatch" in error_msg or "403" in error_msg: # Specific check
                 self.show_backend_error_dialog()
            elif "401" in error_msg or "Session expired" in error_msg:
                 self.show_session_expired_dialog()
            else:
                 self.show_error(f"Could not create {char_type}: {error_msg}")
    
    def show_session_expired_dialog(self):
        """Show session expired dialog prompting user to re-login"""
        def do_logout(e):
            from session_manager import SessionManager
            SessionManager.clear_session()
            # Clear API client tokens
            self.api_client.clear_tokens()
            # Navigate to login
            self.page.close(expired_dialog)
            if self.on_back:
                self.on_back()
            else:
                # Fallback: try to go to root
                self.page.go("/")
        
        expired_dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(ft.Icons.WARNING, color=ft.Colors.ORANGE),
                ft.Text("Session Expired", weight=ft.FontWeight.BOLD)
            ]),
            content=ft.Column([
                ft.Text("Your session has expired and could not be refreshed."),
                ft.Text("Please log out and log in again to continue.", size=13),
                ft.Container(height=10),
                ft.Text("This usually happens when your login session is old or the backend was restarted.", size=12, color=ft.Colors.GREY)
            ], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(expired_dialog)),
                ft.ElevatedButton("Logout & Re-login", on_click=do_logout, bgcolor=ft.Colors.BLUE, color=ft.Colors.WHITE)
            ]
        )
        self.page.open(expired_dialog)

    def show_backend_error_dialog(self):
        """Show specific dialog for backend mismatch"""
        dialog = ft.AlertDialog(
            title=ft.Text("⚠️ Backend Update Required"),
            content=ft.Column([
                ft.Text("The features are implemented but the VPS backend is outdated.", color=ft.Colors.RED),
                ft.Text("Please update 'backend/routes/chats.py' on your VPS.", size=12),
                ft.Text("Error: 403 Forbidden (Route Mismatch)", weight=ft.FontWeight.BOLD)
            ], tight=True),
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

    def init_messages_area(self):
        """Initialize the messages list and input area"""
        colors_palette = self.theme.colors
        
        # Messages list
        self.messages_list = ft.ListView(
            expand=True,
            spacing=4,
            padding=ft.padding.symmetric(horizontal=10, vertical=10),
            auto_scroll=True
        )
        
        # Message input
        self.message_input = ft.TextField(
            hint_text="Message",
            border=ft.InputBorder.NONE,
            filled=False,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=6,
            text_size=15,
            content_padding=ft.padding.symmetric(vertical=10),
            on_submit=lambda e: self.page.run_task(self.send_message),
            color=colors_palette["text_primary"],
            hint_style=ft.TextStyle(color=colors_palette["text_tertiary"])
        )
        
        # Attach button
        self.attach_btn = ft.IconButton(
            icon=ft.Icons.ATTACH_FILE,
            icon_color=colors_palette["text_tertiary"],
            icon_size=26,
            tooltip="Attach",
            style=ft.ButtonStyle(padding=0),
            on_click=lambda e: self.show_attachment_menu()
        )
        
        # Emoji button
        self.emoji_btn = ft.IconButton(
            icon=ft.Icons.EMOJI_EMOTIONS_OUTLINED,
            icon_color=colors_palette["text_tertiary"],
            icon_size=26,
            tooltip="Emoji",
            style=ft.ButtonStyle(padding=0),
            on_click=lambda e: self.show_emoji_picker()
        )
        
        # Send button
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND,
            icon_color=colors_palette["accent"],
            icon_size=28,
            tooltip="Send",
            on_click=lambda e: self.page.run_task(self.send_message)
        )
        
        # Input area container - Telegram style
        input_row = ft.Row([
            self.attach_btn,
            ft.Container(
                content=ft.Row([
                    self.emoji_btn,
                    self.message_input
                ], spacing=0, alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.END),
                bgcolor=colors_palette["bg_primary"] if self.dark_mode else ft.Colors.WHITE,
                border_radius=20, # Pill shape
                padding=ft.padding.only(left=5, right=15, top=2, bottom=2),
                expand=True,
            ),
            self.send_btn
        ], spacing=10, alignment=ft.MainAxisAlignment.CENTER, vertical_alignment=ft.CrossAxisAlignment.END)

        # Bottom container wrapper
        input_container = ft.Container(
            content=input_row,
            padding=ft.padding.all(10),
            bgcolor=colors_palette["bg_secondary"],
            border=ft.border.only(top=ft.BorderSide(1, colors_palette["divider"] if self.dark_mode else ft.Colors.TRANSPARENT))
        )
        
        # Main content
        main_content = ft.Container(
            content=ft.Column([
                # Messages area
                ft.Container(
                    content=self.messages_list,
                    expand=True,
                    bgcolor=colors_palette["bg_secondary"] if self.dark_mode else "#E6EBEF"
                ),
                # Input area
                input_container
            ], spacing=0),
            expand=True,
            bgcolor=colors_palette["bg_primary"]
        )
        
        # Set view properties
        self.bgcolor = colors_palette["bg_primary"]
        self.controls = [
            self.appbar,
            main_content
        ]
    
    def toggle_theme(self):
        """Toggle between light and dark mode"""
        self.dark_mode = not self.dark_mode
        self.theme = ZaplyTheme(dark_mode=self.dark_mode)
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        
        # Rebuild UI with new theme
        self.build_ui()
        
        # Force update
        self.page.update()
        
        # Show confirmation
        mode_name = "Dark" if self.dark_mode else "Light"
        snack = ft.SnackBar(
            content=ft.Text(f"{mode_name} mode enabled"),
            duration=1500
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def show_emoji_picker(self):
        """Show emoji picker dialog with 3000+ emojis"""
        colors_palette = self.theme.colors
        
        def insert_emoji(emoji):
            """Insert emoji into message input"""
            current_text = self.message_input.value or ""
            self.message_input.value = current_text + emoji
            self.page.update()
        
        def close_dialog(e):
            emoji_dialog.open = False
            self.page.update()
        
        # Create emoji grid for a category
        def create_emoji_grid(emojis, max_items=100):
            return ft.GridView(
                runs_count=8,
                max_extent=45,
                child_aspect_ratio=1,
                spacing=2,
                run_spacing=2,
                controls=[
                    ft.Container(
                        content=ft.Text(emoji, size=22, text_align=ft.TextAlign.CENTER),
                        on_click=lambda e, em=emoji: insert_emoji(em),
                        border_radius=8,
                        padding=4
                    ) for emoji in emojis[:max_items]
                ],
                expand=True,
            )
        
        # Create tabs for each category
        tabs = []
        
        # Popular tab first
        tabs.append(ft.Tab(
            text="⭐",
            content=ft.Container(
                content=create_emoji_grid(POPULAR_EMOJIS, 60),
                padding=10,
            )
        ))
        
        # Category tabs
        category_icons = {
            "😀 Smileys": "😀",
            "👋 Gestures": "👋",
            "🐶 Animals": "🐶",
            "🍔 Food": "🍔",
            "⚽ Sports": "⚽",
            "🚗 Travel": "🚗",
            "💡 Objects": "💡",
            "❤️ Symbols": "❤️",
            "🏳️ Flags": "🏳️",
        }
        
        for category, emojis in EMOJI_CATEGORIES.items():
            icon = category_icons.get(category, category.split()[0])
            tabs.append(ft.Tab(
                text=icon,
                content=ft.Container(
                    content=create_emoji_grid(emojis, 120),
                    padding=10,
                )
            ))
        
        # Emoji dialog
        emoji_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Text("Emojis", size=18, weight=ft.FontWeight.W_600),
                ft.Container(expand=True),
                ft.IconButton(
                    icon=ft.Icons.CLOSE,
                    icon_size=20,
                    on_click=close_dialog
                )
            ]),
            content=ft.Container(
                content=ft.Tabs(
                    tabs=tabs,
                    scrollable=True,
                    expand=True,
                ),
                width=350,
                height=350,
            ),
            actions_alignment=ft.MainAxisAlignment.END,
        )
        
        self.page.dialog = emoji_dialog
        emoji_dialog.open = True
        self.page.update()

    def show_attachment_menu(self):
        """Show beautiful attachment menu with colorful icons"""
        colors_palette = self.theme.colors
        
        def create_attach_option(icon, label, color, on_click):
            """Create a single attachment option button"""
            return ft.Container(
                content=ft.Column([
                    ft.Container(
                        content=ft.Icon(icon, size=28, color=ft.Colors.WHITE),
                        width=56,
                        height=56,
                        bgcolor=color,
                        border_radius=28,
                        alignment=ft.alignment.center,
                    ),
                    ft.Text(label, size=12, color=colors_palette["text_primary"], text_align=ft.TextAlign.CENTER)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8),
                on_click=on_click,
                padding=10,
            )
        
        def close_and_pick(action):
            self.page.close(attach_sheet)
            action()
        
        # Attachment options with beautiful colored icons
        options_row1 = ft.Row([
            create_attach_option(ft.Icons.IMAGE, "Photo", "#4CAF50", lambda e: close_and_pick(self.pick_photo)),
            create_attach_option(ft.Icons.CAMERA_ALT, "Camera", "#2196F3", lambda e: close_and_pick(self.pick_photo)),
            create_attach_option(ft.Icons.DESCRIPTION, "Document", "#FF9800", lambda e: close_and_pick(self.pick_document)),
            create_attach_option(ft.Icons.FOLDER, "File", "#9C27B0", lambda e: close_and_pick(self.pick_file)),
        ], alignment=ft.MainAxisAlignment.SPACE_EVENLY)
        
        options_row2 = ft.Row([
            create_attach_option(ft.Icons.LOCATION_ON, "Location", "#F44336", lambda e: close_and_pick(self.share_location)),
            create_attach_option(ft.Icons.MUSIC_NOTE, "Music", "#E91E63", lambda e: close_and_pick(self.pick_file)),
            create_attach_option(ft.Icons.POLL, "Poll", "#00BCD4", lambda e: self.show_coming_soon("Poll")),
            create_attach_option(ft.Icons.CONTACT_PAGE, "Contact", "#607D8B", lambda e: self.show_coming_soon("Contact")),
        ], alignment=ft.MainAxisAlignment.SPACE_EVENLY)
        
        attach_sheet = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Text("Share", weight=ft.FontWeight.BOLD, size=18),
                ft.Container(expand=True),
                ft.IconButton(icon=ft.Icons.CLOSE, on_click=lambda e: self.page.close(attach_sheet))
            ]),
            content=ft.Container(
                content=ft.Column([
                    options_row1,
                    options_row2,
                ], spacing=16),
                padding=ft.padding.symmetric(vertical=20),
                width=350
            ),
        )
        
        self.page.open(attach_sheet)

    def pick_photo(self):
        """Open file picker for photo"""
        try:
            self.file_picker.pick_files(
                allowed_extensions=["jpg", "jpeg", "png", "gif", "webp"],
                allow_multiple=False,
                dialog_title="Select Photo"
            )
        except Exception as e:
            print(f"Error opening photo picker: {e}")
            self.show_error("Could not open photo picker")
    
    def pick_document(self):
        """Open file picker for document"""
        try:
            self.file_picker.pick_files(
                allowed_extensions=["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"],
                allow_multiple=False,
                dialog_title="Select Document"
            )
        except Exception as e:
            print(f"Error opening document picker: {e}")
            self.show_error("Could not open document picker")
    
    def pick_file(self):
        """Open file picker for any file"""
        try:
            self.file_picker.pick_files(
                allow_multiple=False,
                dialog_title="Select File"
            )
        except Exception as e:
            print(f"Error opening file picker: {e}")
            self.show_error("Could not open file picker")
    
    def share_location(self):
        """Share location"""
        # Show coming soon message
        snack = ft.SnackBar(
            content=ft.Text("📍 Location sharing coming soon!"),
            duration=2000
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    async def handle_file_upload(self, e: ft.FilePickerResultEvent):
        """Handle file upload from picker"""
        if not e.files:
            return
        
        print(f"[SAVED] {len(e.files)} files upload karne hain")
        
        # Progress snackbar
        snack = ft.SnackBar(
            content=ft.Row([
                ft.ProgressRing(width=16, height=16, stroke_width=2),
                ft.Text("Files prepare kar rahe hain...")
            ], spacing=10),
            duration=60000 
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
        
        try:
            # Saved chat lo
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("chat_id") or saved_chat.get("_id")
            
            if not chat_id:
                self.show_error("Saved messages chat nahi mila")
                snack.open = False
                self.page.update()
                return

            # Files process karo
            count = 0
            total_size = 0
            for i, file in enumerate(e.files):
                file_name = file.name
                file_path = file.path
                file_size = file.size if hasattr(file, 'size') else 0
                total_size += file_size
                
                # Progress update karo
                progress_text = f"Uploading {i+1}/{len(e.files)}: {file_name}"
                snack.content.controls[1].value = progress_text
                snack.update()
                
                print(f"[SAVED] Uploading file {i+1}/{len(e.files)}: {file_name}")
                
                try:
                    # File upload karo
                    file_id = await self.api_client.upload_large_file(file_path, chat_id)
                    
                    # File ke saath message send karo
                    await self.api_client.send_message(
                        chat_id=chat_id,
                        file_id=file_id
                    )
                    count += 1
                    print(f"[SAVED] File {file_name} successfully upload ho gaya")
                    
                except Exception as file_e:
                    print(f"[SAVED] File {file_name} upload mein error: {file_e}")
                    # Continue with next file
                    continue

            # Progress snackbar band karo
            snack.open = False
            self.page.update()
            
            # Success message dikhao
            size_mb = total_size / (1024 * 1024)
            success_msg = f"✅ {count} file(s) save ho gaye! ({size_mb:.1f} MB)"
            success_snack = ft.SnackBar(
                content=ft.Text(success_msg), 
                bgcolor=ft.Colors.GREEN
            )
            self.page.overlay.append(success_snack)
            success_snack.open = True
            self.page.update()
            
            print(f"[SAVED] Upload complete: {count}/{len(e.files)} files, {size_mb:.1f} MB")
            
            # Messages reload karo
            await self.load_saved_messages()
            
        except Exception as e:
            snack.open = False
            self.page.update()
            error_str = str(e)
            print(f"[SAVED] File upload mein serious error: {error_str}")
            
            if "403" in error_str:
                self.show_backend_error_dialog()
            elif "401" in error_str or "Session expired" in error_str:
                self.show_session_expired_dialog()
            elif "Failed to load saved messages" in error_str:
                self.show_error("Saved messages chat nahi mila. Pehle saved messages create karo.")
            else:
                self.show_error(f"Upload fail ho gaya: {error_str[:100]}")
    
    async def load_saved_messages(self):
        """Load all saved messages"""
        colors_palette = self.theme.colors
        
        try:
            print("[SAVED] Saved messages load kar rahe hain...")
            
            # Pehle primary endpoint try karo
            try:
                data = await self.api_client.get_saved_messages()
                messages = data.get("messages", [])
                print(f"[SAVED] Primary endpoint se {len(messages)} messages mile")
            except Exception as primary_error:
                print(f"[SAVED] Primary endpoint fail ho gaya: {primary_error}")
                # Fallback: Saved chat lo aur phir messages lo
                try:
                    saved_chat = await self.api_client.get_saved_chat()
                    chat_id = saved_chat.get("chat_id") or saved_chat.get("_id")
                    if chat_id:
                        msg_data = await self.api_client.get_messages(chat_id)
                        messages = msg_data.get("messages", [])
                        print(f"[SAVED] Fallback se {len(messages)} messages mile")
                    else:
                        messages = []
                        print("[SAVED] Koi saved chat nahi mila, creating new one...")
                        # Try to create saved chat
                        try:
                            await self.api_client.get_saved_chat()  # This should create it
                            print("[SAVED] Saved chat created successfully")
                        except Exception as create_error:
                            print(f"[SAVED] Failed to create saved chat: {create_error}")
                except Exception as fallback_error:
                    print(f"[SAVED] Fallback bhi fail ho gaya: {fallback_error}")
                    messages = []
            
            # Messages list clear karo
            self.messages_list.controls.clear()
            
            if not messages:
                # Empty state dikhao
                empty_state = ft.Container(
                    content=ft.Column([
                        ft.Icon(
                            ft.Icons.BOOKMARK_BORDER,
                            size=64,
                            color=colors_palette["text_tertiary"]
                        ),
                        ft.Text(
                            "Koi saved message nahi hai",
                            size=FONT_SIZES["lg"],
                            weight=ft.FontWeight.W_500,
                            color=colors_palette["text_secondary"],
                            text_align=ft.TextAlign.CENTER
                        ),
                        ft.Text(
                            "Jo messages aap save karenge woh yahan dikheinge",
                            size=FONT_SIZES["sm"],
                            color=colors_palette["text_tertiary"],
                            text_align=ft.TextAlign.CENTER
                        ),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=SPACING["md"]),
                    alignment=ft.alignment.center,
                    expand=True
                )
                self.messages_list.controls.append(empty_state)
                print("[SAVED] Empty state dikhaya")
            else:
                # Messages ko cards mein convert karo
                for msg in messages:
                    msg_card = self.create_message_card(msg)
                    self.messages_list.controls.append(msg_card)
                
                print(f"[SAVED] {len(messages)} message cards banaye")
            
            self.page.update()
            print("[SAVED] Saved messages successfully load ho gaye")
            
        except Exception as e:
            error_str = str(e)
            print(f"[SAVED] Saved messages load karne mein serious error: {error_str}")
            
            if "403" in error_str:
                 self.show_backend_error_dialog()
                 return
            elif "401" in error_str or "Session expired" in error_str:
                 self.show_session_expired_dialog()
                 return
            
            # Error state dikhao
            error_state = ft.Container(
                content=ft.Column([
                    ft.Icon(
                        ft.Icons.ERROR_OUTLINE,
                        size=64,
                        color=colors_palette["error"]
                    ),
                    ft.Text(
                        "Messages load nahi ho paye",
                        size=FONT_SIZES["lg"],
                        weight=ft.FontWeight.W_500,
                        color=colors_palette["error"]
                    ),
                    ft.Text(
                        error_str[:100],
                        size=FONT_SIZES["sm"],
                        color=colors_palette["text_secondary"],
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.TextButton(
                        "Dubara try karo",
                        on_click=lambda e: self.page.run_task(self.load_saved_messages)
                    )
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=SPACING["md"]),
                alignment=ft.alignment.center,
                expand=True
            )
            self.messages_list.controls.clear()
            self.messages_list.controls.append(error_state)
            self.page.update()
    
    def create_message_card(self, message):
        """Create Telegram-style message bubble with tails (replaces card)"""
        colors_palette = self.theme.colors
        
        msg_text = message.get("text", "")
        # For saved messages, sender is effectively 'me' or it's a note
        is_mine = True
        
        created_at = message.get("created_at", "")
        message_id = message.get("_id", "")
        
        # Format time
        if isinstance(created_at, str):
            try:
                date_obj = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                time_str = date_obj.strftime("%I:%M %p")
            except:
                time_str = ""
        else:
            time_str = ""
        
        # Check if it's a file message
        is_file = msg_text.startswith(("📎", "🖼️", "🎬", "🎵", "📕", "📘", "📗", "📙", "📦"))
        
        # Bubble Styling
        if self.dark_mode:
            bubble_color = "#2B5278" 
            text_color = ft.Colors.WHITE
        else:
            bubble_color = "#EEFFDE"
            text_color = ft.Colors.BLACK
            
        radius = ft.border_radius.only(
            top_left=16, top_right=16, bottom_left=16, bottom_right=0
        )
        align = ft.MainAxisAlignment.END

        # Message content widgets
        content_widgets = []
        
        # Main content (Text or File)
        if is_file:
            # File representation
            parts = msg_text.split(" ", 1)
            emoji_icon = parts[0]
            filename = parts[1] if len(parts) > 1 else "File"
            
            content_widgets.append(
                ft.Container(
                    content=ft.Row([
                        ft.Container(
                            content=ft.Text(emoji_icon, size=24),
                            bgcolor=ft.Colors.with_opacity(0.1, text_color),
                            width=40, height=40, border_radius=20,
                            alignment=ft.alignment.center
                        ),
                        ft.Column([
                            ft.Text(filename, color=text_color, weight=ft.FontWeight.W_500, size=14, overflow=ft.TextOverflow.ELLIPSIS),
                            ft.Text("Download", color=colors_palette["accent"], size=12)
                        ], spacing=2, alignment=ft.MainAxisAlignment.CENTER)
                    ], spacing=10),
                    padding=ft.padding.all(5)
                )
            )
        else:
            content_widgets.append(
                ft.Text(msg_text, color=text_color, size=15, selectable=True)
            )
        
        # Footer: Time + Status checks
        status_row = ft.Row(
            controls=[
                ft.Text(time_str, size=11, color=ft.Colors.with_opacity(0.6, text_color)),
                # Check marks (always done for saved)
                ft.Icon(ft.Icons.DONE_ALL, size=14, color=ft.Colors.BLUE_400)
            ],
            spacing=4,
            alignment=ft.MainAxisAlignment.END,
        )
        
        # Popover menu
        def show_menu(e):
            menu = ft.AlertDialog(
                title=ft.Text("Options"),
                actions=[
                    ft.TextButton("Copy", on_click=lambda e: self.copy_message(msg_text)),
                    ft.TextButton("Delete", on_click=lambda e: self.page.run_task(self.unsave_message, message_id), style=ft.ButtonStyle(color=ft.Colors.RED))
                ]
            )
            self.page.dialog = menu
            menu.open = True
            self.page.update()

        # Combine
        final_content = ft.Column(
            controls=content_widgets + [status_row],
            spacing=2,
            tight=True,
            horizontal_alignment=ft.CrossAxisAlignment.END 
        )
        
        bubble = ft.Container(
            content=final_content,
            bgcolor=bubble_color,
            border_radius=radius,
            padding=ft.padding.symmetric(horizontal=12, vertical=6),
            constraints=ft.BoxConstraints(max_width=300),
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=1,
                color=ft.Colors.with_opacity(0.1, ft.Colors.BLACK),
                offset=ft.Offset(0, 1),
            ),
            on_long_press=show_menu
        )
        
        return ft.Row([bubble], alignment=align)
    
    def copy_message(self, text: str):
        """Copy message text to clipboard"""
        try:
            self.page.set_clipboard(text)
            # Simple snackbar
            snack = ft.SnackBar(
                content=ft.Text("Copied to clipboard"),
                duration=2000
            )
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
        except Exception as e:
            print(f"Error copying message: {e}")
    
    async def send_message(self):
        """Send a message to saved messages"""
        if not self.message_input.value or not self.message_input.value.strip():
            return
        
        try:
            message_text = self.message_input.value.strip()
            self.message_input.value = ""
            self.page.update()
            
            print(f"[SAVED] Message send kar rahe hain: {message_text[:50]}...")
            
            # Loading indicator
            self.send_btn.icon = ft.Icons.HOURGLASS_EMPTY
            self.send_btn.disabled = True
            self.page.update()
            
            # Get ya create saved messages chat
            try:
                saved_chat = await self.api_client.get_saved_chat()
                chat_id = saved_chat.get("chat_id") or saved_chat.get("_id")
                
                if not chat_id:
                    self.show_error("Saved messages chat nahi mila")
                    self.message_input.value = message_text
                    self.send_btn.icon = ft.Icons.SEND
                    self.send_btn.disabled = False
                    self.page.update()
                    return
            except Exception as chat_error:
                print(f"[SAVED] Error getting saved chat: {chat_error}")
                self.show_error("Saved messages chat create nahi ho paya")
                self.message_input.value = message_text
                self.send_btn.icon = ft.Icons.SEND
                self.send_btn.disabled = False
                self.page.update()
                return
            
            # Message send karo
            result = await self.api_client.send_message(
                chat_id=chat_id,
                text=message_text
            )
            
            print(f"[SAVED] Message successfully send kiya")
            
            # Success message dikhao
            snack = ft.SnackBar(
                content=ft.Text("Message save ho gaya!"),
                bgcolor=ft.Colors.GREEN,
                duration=2000
            )
            self.page.overlay.append(snack)
            snack.open = True
            
            # Messages reload karo
            await self.load_saved_messages()
            
        except Exception as e:
            error_msg = str(e)
            print(f"[SAVED] Message send karne mein error: {error_msg}")
            
            # Button restore karo
            self.send_btn.icon = ft.Icons.SEND
            self.send_btn.disabled = False
            self.page.update()
            
            # Error dikhao
            if "401" in error_msg or "Session expired" in error_msg:
                self.show_session_expired_dialog()
            else:
                self.show_error(f"Message save nahi hua: {error_msg[:50]}")
            
        finally:
            # Button hamesha restore karo
            self.send_btn.icon = ft.Icons.SEND
            self.send_btn.disabled = False
            self.page.update()
    
    async def unsave_message(self, message_id: str):
        """Remove a message from saved"""
        try:
            await self.api_client.unsave_message(message_id)
            
            # Show success
            snack = ft.SnackBar(
                content=ft.Text("Message removed"),
                duration=2000
            )
            self.page.overlay.append(snack)
            snack.open = True
            
            await self.load_saved_messages()
        except Exception as e:
            error_msg = str(e)
            print(f"Error unsaving message: {error_msg}")
            self.show_error(f"Failed to remove: {error_msg[:50]}")
    
    def show_error(self, message: str):
        """Show error snackbar"""
        snack = ft.SnackBar(
            content=ft.Text(message),
            bgcolor=ft.Colors.ERROR
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def go_back(self):
        """Go back to previous screen"""
        if self.on_back:
            self.on_back()
        else:
            self.page.go("/")

