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
ft.colors = ft.Colors


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
        
        # Simple AppBar
        self.appbar = ft.AppBar(
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=colors_palette["text_primary"],
                on_click=lambda e: self.go_back(),
                tooltip="Back"
            ),
            title=ft.Text(
                "Saved Messages",
                size=FONT_SIZES["xl"],
                weight=ft.FontWeight.W_600,
                color=colors_palette["text_primary"]
            ),
            bgcolor=colors_palette["bg_primary"],
            elevation=0,
            actions=[
                # Theme toggle button
                ft.IconButton(
                    icon=theme_icon,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Toggle theme",
                    on_click=lambda e: self.toggle_theme()
                ),
                # Hamburger menu
                ft.IconButton(
                     icon=ft.Icons.MENU,
                     icon_color=colors_palette["text_primary"],
                     tooltip="Menu",
                     on_click=lambda e: self.open_drawer()
                )
            ]
        )
        
        # Build drawer
        self.build_drawer()
        self.page.drawer = self.drawer

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
            self.drawer_item("👥", "New Group", lambda e: self.create_new_group()),
            self.drawer_item("📢", "New Channel", lambda e: self.create_new_channel()),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("📇", "Contacts", lambda e: self.show_coming_soon("Contacts")),
            self.drawer_item("📞", "Calls", lambda e: self.show_coming_soon("Calls")),
            self.drawer_item("💾", "Saved Messages", lambda e: self.close_drawer()), # Already here
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("⚙️", "Settings", lambda e: self.page.go("/settings")),
            # Night mode with switch
            ft.Container(
                content=ft.Row([
                    ft.Text("🌙", size=20),
                    ft.Container(width=12),
                    ft.Text("Night Mode", size=16, color=self.theme.colors["text_primary"], expand=True),
                    self.night_mode_switch
                ], spacing=0),
                padding=ft.padding.symmetric(horizontal=20, vertical=12),
                on_click=lambda e: self.toggle_night_mode_click(),
                ink=True
            ),
            ft.Divider(height=1, color="#E0E0E0"),
            self.drawer_item("❓", "Zaply FAQ", lambda e: self.show_coming_soon("FAQ")),
            self.drawer_item("💬", "Zaply Features", lambda e: self.show_coming_soon("Features")),
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
            on_click=on_click,
            ink=True
        )

    def open_drawer(self):
        self.page.drawer = self.drawer
        self.drawer.open = True
        self.page.update()
    
    def close_drawer(self):
        self.drawer.open = False
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
                ft.TextButton("Cancel", on_click=lambda e: setattr(dialog, 'open', False)),
                ft.ElevatedButton("Create", on_click=create_click)
            ]
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

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
                ft.TextButton("Cancel", on_click=lambda e: setattr(dialog, 'open', False)),
                ft.ElevatedButton("Create", on_click=create_click)
            ]
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

    async def do_create_chat(self, name: str, char_type: str, dialog):
        try:
            # Need to get user ID. If string, use it. If dict, use id/_id
            user_id = self.current_user if isinstance(self.current_user, str) else self.current_user.get("id", self.current_user.get("_id"))
            
            await self.api_client.create_chat(name=name, user_ids=[user_id], chat_type=char_type)
            dialog.open = False
            self.page.update()
            
            # Show success and maybe navigate back to chats to see it?
            # Since we are in Saved Messages, we might want to stay here or go to the new chat.
            # For now, just show success.
            snack = ft.SnackBar(content=ft.Text(f"{char_type.capitalize()} '{name}' created!"), bgcolor=ft.Colors.GREEN)
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
            
        except Exception as e:
            print(f"Error creating {char_type}: {e}")
            dialog.open = False
            self.page.update()
            self.show_error(f"Could not create {char_type}")

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


        
        # Messages list with simple design
        self.messages_list = ft.ListView(
            expand=True,
            spacing=SPACING["sm"],
            padding=ft.padding.all(SPACING["md"])
        )
        
        # Simple input field
        self.message_input = ft.TextField(
            hint_text="Message yourself...",
            border=ft.InputBorder.OUTLINE,
            border_radius=RADIUS["full"],
            filled=True,
            fill_color=colors_palette["bg_secondary"],
            expand=True,
            multiline=False,
            max_lines=1,
            text_size=FONT_SIZES["base"],
            on_submit=lambda e: self.page.run_task(self.send_message),
            border_color=colors_palette["border"],
            focused_border_color=colors_palette["accent"],
            color=colors_palette["text_primary"],
            hint_style=ft.TextStyle(color=colors_palette["text_tertiary"])
        )
        
        # Send button
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND_ROUNDED,
            icon_color=colors_palette["accent"],
            on_click=lambda e: self.page.run_task(self.send_message),
            tooltip="Send"
        )
        
        # Attach button with popup menu
        self.attach_btn = ft.PopupMenuButton(
            icon=ft.Icons.ATTACH_FILE,
            icon_color=colors_palette["text_secondary"],
            tooltip="Attach",
            items=[
                ft.PopupMenuItem(
                    icon=ft.Icons.IMAGE,
                    text="Photo",
                    on_click=lambda e: self.pick_photo()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.DESCRIPTION,
                    text="Document",
                    on_click=lambda e: self.pick_document()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.INSERT_DRIVE_FILE,
                    text="File",
                    on_click=lambda e: self.pick_file()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.LOCATION_ON,
                    text="Location",
                    on_click=lambda e: self.share_location()
                ),
            ]
        )
        
        # Emoji button
        self.emoji_btn = ft.IconButton(
            icon=ft.Icons.EMOJI_EMOTIONS,
            icon_color=colors_palette["text_secondary"],
            tooltip="Emoji",
            on_click=lambda e: self.show_emoji_picker()
        )
        
        # Main layout - Minimal and Clean
        main_content = ft.Container(
            content=ft.Column([
                # Messages area
                ft.Container(
                    content=self.messages_list,
                    expand=True,
                    bgcolor=colors_palette["bg_primary"],
                ),
                # Input area - Simple bottom bar with emoji, attach, input, send
                ft.Container(
                    content=ft.Row([
                        self.attach_btn,
                        self.emoji_btn,
                        self.message_input,
                        self.send_btn
                    ], spacing=SPACING["sm"]),
                    padding=ft.padding.all(SPACING["md"]),
                    bgcolor=colors_palette["bg_primary"],
                    border=ft.border.only(top=ft.BorderSide(1, colors_palette["divider"]))
                )

            ], spacing=0),
            bgcolor=colors_palette["bg_primary"],
            expand=True
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
                        padding=4,
                        ink=True,
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
        
        try:
            file = e.files[0]
            file_name = file.name
            file_path = file.path
            
            print(f"Selected file: {file_name}")
            
            # Show uploading message
            snack = ft.SnackBar(
                content=ft.Row([
                    ft.ProgressRing(width=16, height=16, stroke_width=2),
                    ft.Text(f"Uploading {file_name}...")
                ], spacing=10),
                duration=10000
            )
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
            
            # Get saved chat
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("chat_id") or saved_chat.get("_id")
            
            if not chat_id:
                self.show_error("Could not find saved messages chat")
                return
            
            # For now, send as text message with file info
            # Full file upload requires backend file storage
            file_emoji = "📎"
            if file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp')):
                file_emoji = "🖼️"
            elif file_name.lower().endswith(('.pdf', '.doc', '.docx')):
                file_emoji = "📄"
            elif file_name.lower().endswith(('.mp4', '.avi', '.mov')):
                file_emoji = "🎬"
            
            # Fallback for now: Send as text message with emoji prefix
            # This is because the backend might not support file uploads yet or has routing issues
            # Re-fetch chat_id in case it was not found initially or for robustness
            saved_chat_for_fallback = await self.api_client.get_saved_chat()
            chat_id_for_fallback = saved_chat_for_fallback.get("chat_id") or saved_chat_for_fallback.get("_id")
            if not chat_id_for_fallback:
                raise Exception("Could not access Saved Messages chat for fallback")

            await self.api_client.send_message(
                 chat_id=chat_id_for_fallback,
                 text=f"{file_emoji} {file_name}" # Using file_emoji as defined earlier
            )
             
            # Close snackbar
            snack.open = False
            self.page.update()
             
            # Reload messages
            await self.load_saved_messages()
             
        except Exception as e:
            print(f"Error uploading file: {e}")
            snack.open = False # Close snackbar on error too
            self.page.update()
            
            error_msg = str(e)
            if "403" in error_msg or "401" in error_msg:
                 self.show_backend_error_dialog()
            else:
                 self.show_error(f"Upload failed: {error_msg[:50]}")
    
    async def load_saved_messages(self):
        """Load all saved messages"""
        colors_palette = self.theme.colors
        
        try:
            # Try primary endpoint first
            try:
                data = await self.api_client.get_saved_messages()
                messages = data.get("messages", [])
            except Exception as primary_error:
                print(f"Primary endpoint failed: {primary_error}")
                # Fallback: Get saved chat and then fetch its messages
                try:
                    saved_chat = await self.api_client.get_saved_chat()
                    chat_id = saved_chat.get("chat_id") or saved_chat.get("_id")
                    if chat_id:
                        msg_data = await self.api_client.get_messages(chat_id)
                        messages = msg_data.get("messages", [])
                    else:
                        messages = []
                except Exception as fallback_error:
                    print(f"Fallback also failed: {fallback_error}")
                    messages = []
            
            self.messages_list.controls.clear()
            
            if not messages:
                # Simple empty state
                empty_state = ft.Container(
                    content=ft.Column([
                        ft.Icon(
                            ft.Icons.BOOKMARK_BORDER,
                            size=64,
                            color=colors_palette["text_tertiary"]
                        ),
                        ft.Text(
                            "No saved messages yet",
                            size=FONT_SIZES["lg"],
                            weight=ft.FontWeight.W_500,
                            color=colors_palette["text_secondary"],
                            text_align=ft.TextAlign.CENTER
                        ),
                        ft.Text(
                            "Messages you save will appear here",
                            size=FONT_SIZES["sm"],
                            color=colors_palette["text_tertiary"],
                            text_align=ft.TextAlign.CENTER
                        ),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=SPACING["md"]),
                    alignment=ft.alignment.center,
                    expand=True
                )
                self.messages_list.controls.append(empty_state)
            else:
                for msg in messages:
                    msg_card = self.create_message_card(msg)
                    self.messages_list.controls.append(msg_card)
            
            self.page.update()
        except Exception as e:
            error_str = str(e)
            print(f"Error loading saved messages: {error_str}")
            
            if "403" in error_str or "401" in error_str:
                 self.show_backend_error_dialog()
            
            # Simple error state
            error_state = ft.Container(
                content=ft.Column([
                    ft.Icon(
                        ft.Icons.ERROR_OUTLINE,
                        size=64,
                        color=colors_palette["error"]
                    ),
                    ft.Text(
                        "Failed to load messages",
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
                        "Try again",
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
        """Create a simple, clean message card"""
        colors_palette = self.theme.colors
        
        msg_text = message.get("text", "")
        created_at = message.get("created_at", "")
        message_id = message.get("_id", "")
        
        # Format timestamp
        if isinstance(created_at, str):
            try:
                date_obj = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                timestamp = date_obj.strftime("%b %d, %I:%M %p")
            except:
                timestamp = created_at
        else:
            timestamp = str(created_at)
        
        # Simple card design
        card = ft.Container(
            content=ft.Column([
                # Message text
                ft.Text(
                    msg_text,
                    size=FONT_SIZES["base"],
                    color=colors_palette["text_primary"],
                    selectable=True
                ),
                # Footer with timestamp and actions
                ft.Row([
                    ft.Text(
                        timestamp,
                        size=FONT_SIZES["xs"],
                        color=colors_palette["text_tertiary"]
                    ),
                    ft.Container(expand=True),
                    # Action buttons
                    ft.IconButton(
                        icon=ft.Icons.COPY,
                        icon_size=16,
                        icon_color=colors_palette["text_secondary"],
                        tooltip="Copy",
                        on_click=lambda e, t=msg_text: self.copy_message(t)
                    ),
                    ft.IconButton(
                        icon=ft.Icons.DELETE_OUTLINE,
                        icon_size=16,
                        icon_color=colors_palette["text_secondary"],
                        tooltip="Delete",
                        on_click=lambda e, mid=message_id: self.page.run_task(self.unsave_message, mid)
                    )
                ], spacing=SPACING["xs"])
            ], spacing=SPACING["sm"]),
            padding=ft.padding.all(SPACING["md"]),
            bgcolor=colors_palette["bg_secondary"],
            border_radius=RADIUS["lg"],
            border=ft.border.all(1, colors_palette["border"])
        )
        
        return card
    
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
            message_text = self.message_input.value
            self.message_input.value = ""
            self.page.update()
            
            # Get or create saved messages chat
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("chat_id") or saved_chat.get("_id")
            
            if not chat_id:
                self.show_error("Could not find saved messages chat")
                self.message_input.value = message_text
                self.page.update()
                return
            
            # Send the message
            await self.api_client.send_message(
                chat_id=chat_id,
                text=message_text
            )
            
            # Show success
            snack = ft.SnackBar(
                content=ft.Text("Message saved"),
                duration=2000
            )
            self.page.overlay.append(snack)
            snack.open = True
            
            # Reload messages
            await self.load_saved_messages()
            
        except Exception as e:
            error_msg = str(e)
            print(f"Error sending message: {error_msg}")
            self.show_error(f"Failed to save message: {error_msg[:50]}")
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