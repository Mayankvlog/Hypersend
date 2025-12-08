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
                )
            ]
        )
        
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
            
            # Send message with file info
            await self.api_client.send_message(
                chat_id=chat_id,
                text=f"{file_emoji} {file_name}"
            )
            
            # Close previous snackbar and show success
            snack.open = False
            self.page.update()
            
            success_snack = ft.SnackBar(
                content=ft.Text(f"✅ {file_name} sent!"),
                bgcolor=ft.Colors.GREEN_600,
                duration=2000
            )
            self.page.overlay.append(success_snack)
            success_snack.open = True
            self.page.update()
            
            # Reload messages
            await self.load_saved_messages()
            
        except Exception as e:
            print(f"Error uploading file: {e}")
            self.show_error(f"Upload failed: {str(e)[:50]}")
    
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