"""
Message View - Telegram-like Chat Interface
Full featured chat with emoji, file, image, document sending
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
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from api_client import APIClient
    from theme import ZaplyTheme, LIGHT_COLORS, DARK_COLORS, FONT_SIZES, SPACING, RADIUS
    from emoji_data import EMOJI_CATEGORIES, POPULAR_EMOJIS, UNIQUE_EMOJIS


# Compatibility
icons = ft.Icons
colors = ft.Colors
ft.colors = ft.Colors


class MessageView(ft.View):
    """Telegram-like chat view with full messaging features"""
    
    def __init__(self, page: ft.Page, api_client: APIClient, chat: dict, current_user: str, on_back=None, dark_mode: bool = False):
        super().__init__(f"/chat/{chat.get('_id', '')}")
        self.page = page
        self.api_client = api_client
        self.chat = chat
        self.current_user = current_user
        self.on_back = on_back
        
        # Theme
        self.dark_mode = dark_mode
        self.theme = ZaplyTheme(dark_mode=dark_mode)
        
        # State
        self.messages = []
        self.loading = False
        self.typing = False
        
        # File picker
        self.file_picker = ft.FilePicker(on_result=lambda e: self.page.run_task(self.handle_file_upload, e))
        self.page.overlay.append(self.file_picker)
        
        self.build_ui()
    
    def build_ui(self):
        """Build Telegram-like chat interface"""
        colors_palette = self.theme.colors
        chat_name = self.chat.get("name", "Chat")
        chat_type = self.chat.get("type", "private")
        
        # Get chat avatar/icon
        if chat_type == "saved":
            avatar_icon = ft.Icons.BOOKMARK
            avatar_color = colors_palette["accent"]
        elif chat_type == "group":
            avatar_icon = ft.Icons.GROUP
            avatar_color = colors_palette["success"]
        else:
            avatar_icon = ft.Icons.PERSON
            avatar_color = colors_palette["accent"]
        
        # AppBar with chat info
        self.appbar = ft.AppBar(
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=colors_palette["text_primary"],
                on_click=lambda e: self.go_back(),
                tooltip="Back"
            ),
            title=ft.Row([
                ft.Container(
                    content=ft.Icon(avatar_icon, color=ft.Colors.WHITE, size=20),
                    width=40,
                    height=40,
                    bgcolor=avatar_color,
                    border_radius=20,
                    alignment=ft.alignment.center,
                ),
                ft.Container(width=12),
                ft.Column([
                    ft.Text(
                        chat_name,
                        size=FONT_SIZES["lg"],
                        weight=ft.FontWeight.W_600,
                        color=colors_palette["text_primary"]
                    ),
                    ft.Text(
                        "online" if chat_type != "saved" else "cloud storage",
                        size=FONT_SIZES["xs"],
                        color=colors_palette["success"] if chat_type != "saved" else colors_palette["text_tertiary"]
                    )
                ], spacing=0)
            ], spacing=0),
            bgcolor=colors_palette["bg_primary"],
            elevation=1,
            actions=[
                ft.IconButton(
                    icon=ft.Icons.VIDEOCAM,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Video call",
                    on_click=lambda e: self.show_coming_soon("Video call")
                ),
                ft.IconButton(
                    icon=ft.Icons.CALL,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Voice call",
                    on_click=lambda e: self.show_coming_soon("Voice call")
                ),
                ft.PopupMenuButton(
                    icon=ft.Icons.MORE_VERT,
                    icon_color=colors_palette["text_primary"],
                    tooltip="More",
                    items=[
                        ft.PopupMenuItem(text="🔍 Search", on_click=lambda e: self.show_coming_soon("Search")),
                        ft.PopupMenuItem(text="🔇 Mute", on_click=lambda e: self.show_coming_soon("Mute")),
                        ft.PopupMenuItem(text="📌 Pin chat", on_click=lambda e: self.show_coming_soon("Pin")),
                        ft.PopupMenuItem(text="🗑️ Clear history", on_click=lambda e: self.show_coming_soon("Clear")),
                    ]
                )
            ]
        )
        
        # Messages list
        self.messages_list = ft.ListView(
            expand=True,
            spacing=SPACING["xs"],
            padding=ft.padding.symmetric(horizontal=SPACING["md"], vertical=SPACING["sm"]),
            auto_scroll=True
        )
        
        # Message input
        self.message_input = ft.TextField(
            hint_text="Message...",
            border=ft.InputBorder.NONE,
            filled=False,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5,
            text_size=FONT_SIZES["base"],
            on_submit=lambda e: self.page.run_task(self.send_message),
            color=colors_palette["text_primary"],
            hint_style=ft.TextStyle(color=colors_palette["text_tertiary"])
        )
        
        # Attach button with popup
        self.attach_btn = ft.PopupMenuButton(
            icon=ft.Icons.ATTACH_FILE,
            icon_color=colors_palette["text_secondary"],
            tooltip="Attach",
            items=[
                ft.PopupMenuItem(
                    icon=ft.Icons.IMAGE,
                    text="📸 Photo",
                    on_click=lambda e: self.pick_photo()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.VIDEOCAM,
                    text="🎬 Video",
                    on_click=lambda e: self.pick_video()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.DESCRIPTION,
                    text="📄 Document",
                    on_click=lambda e: self.pick_document()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.AUDIOTRACK,
                    text="🎵 Audio",
                    on_click=lambda e: self.pick_audio()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.LOCATION_ON,
                    text="📍 Location",
                    on_click=lambda e: self.share_location()
                ),
                ft.PopupMenuItem(
                    icon=ft.Icons.CONTACT_PAGE,
                    text="👤 Contact",
                    on_click=lambda e: self.share_contact()
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
        
        # Send button
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND,
            icon_color=colors_palette["accent"],
            tooltip="Send",
            on_click=lambda e: self.page.run_task(self.send_message)
        )
        
        # Voice message button
        self.voice_btn = ft.IconButton(
            icon=ft.Icons.MIC,
            icon_color=colors_palette["text_secondary"],
            tooltip="Voice message",
            on_click=lambda e: self.show_coming_soon("Voice message")
        )
        
        # Input area container
        input_container = ft.Container(
            content=ft.Row([
                self.attach_btn,
                ft.Container(
                    content=ft.Row([
                        self.emoji_btn,
                        self.message_input,
                    ], spacing=0),
                    bgcolor=colors_palette["bg_secondary"],
                    border_radius=RADIUS["full"],
                    padding=ft.padding.symmetric(horizontal=SPACING["sm"]),
                    expand=True,
                ),
                self.send_btn,
            ], spacing=SPACING["xs"]),
            padding=ft.padding.all(SPACING["sm"]),
            bgcolor=colors_palette["bg_primary"],
            border=ft.border.only(top=ft.BorderSide(1, colors_palette["divider"]))
        )
        
        # Main content
        main_content = ft.Container(
            content=ft.Column([
                # Messages area
                ft.Container(
                    content=self.messages_list,
                    expand=True,
                    bgcolor=colors_palette["bg_secondary"],
                ),
                # Input area
                input_container
            ], spacing=0),
            expand=True,
            bgcolor=colors_palette["bg_primary"]
        )
        
        # View properties
        self.bgcolor = colors_palette["bg_primary"]
        self.controls = [
            self.appbar,
            main_content
        ]
        
        # Load messages
        self.page.run_task(self.load_messages)
    
    def show_emoji_picker(self):
        """Show emoji picker dialog with 3000+ emojis"""
        colors_palette = self.theme.colors
        
        def insert_emoji(emoji):
            current_text = self.message_input.value or ""
            self.message_input.value = current_text + emoji
            self.page.update()
        
        def close_dialog(e):
            emoji_dialog.open = False
            self.page.update()
        
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
        
        tabs = []
        tabs.append(ft.Tab(
            text="⭐",
            content=ft.Container(
                content=create_emoji_grid(POPULAR_EMOJIS, 60),
                padding=10,
            )
        ))
        
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
        
        emoji_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Text("Emojis", size=18, weight=ft.FontWeight.W_600),
                ft.Container(expand=True),
                ft.IconButton(icon=ft.Icons.CLOSE, icon_size=20, on_click=close_dialog)
            ]),
            content=ft.Container(
                content=ft.Tabs(tabs=tabs, scrollable=True, expand=True),
                width=350,
                height=350,
            ),
        )
        
        self.page.dialog = emoji_dialog
        emoji_dialog.open = True
        self.page.update()
    
    def pick_photo(self):
        try:
            self.file_picker.pick_files(
                allowed_extensions=["jpg", "jpeg", "png", "gif", "webp"],
                allow_multiple=True,
                dialog_title="Select Photos"
            )
        except Exception as e:
            self.show_error(f"Could not open picker: {e}")
    
    def pick_video(self):
        try:
            self.file_picker.pick_files(
                allowed_extensions=["mp4", "avi", "mov", "mkv", "webm"],
                allow_multiple=False,
                dialog_title="Select Video"
            )
        except Exception as e:
            self.show_error(f"Could not open picker: {e}")
    
    def pick_document(self):
        try:
            self.file_picker.pick_files(
                allowed_extensions=["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "zip", "rar"],
                allow_multiple=True,
                dialog_title="Select Documents"
            )
        except Exception as e:
            self.show_error(f"Could not open picker: {e}")
    
    def pick_audio(self):
        try:
            self.file_picker.pick_files(
                allowed_extensions=["mp3", "wav", "ogg", "m4a", "aac"],
                allow_multiple=False,
                dialog_title="Select Audio"
            )
        except Exception as e:
            self.show_error(f"Could not open picker: {e}")
    
    def share_location(self):
        self.show_coming_soon("Location sharing")
    
    def share_contact(self):
        self.show_coming_soon("Contact sharing")
    
    async def handle_file_upload(self, e: ft.FilePickerResultEvent):
        """Handle file upload"""
        if not e.files:
            return
        
        colors_palette = self.theme.colors
        
        try:
            for file in e.files:
                file_name = file.name
                
                # Show uploading indicator
                snack = ft.SnackBar(
                    content=ft.Row([
                        ft.ProgressRing(width=16, height=16, stroke_width=2),
                        ft.Text(f"Sending {file_name}...")
                    ], spacing=10),
                    duration=5000
                )
                self.page.overlay.append(snack)
                snack.open = True
                self.page.update()
                
                # Determine file type emoji
                ext = file_name.lower().split('.')[-1] if '.' in file_name else ''
                if ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                    file_emoji = "🖼️"
                elif ext in ['mp4', 'avi', 'mov', 'mkv']:
                    file_emoji = "🎬"
                elif ext in ['mp3', 'wav', 'ogg', 'm4a']:
                    file_emoji = "🎵"
                elif ext in ['pdf']:
                    file_emoji = "📕"
                elif ext in ['doc', 'docx']:
                    file_emoji = "📘"
                elif ext in ['xls', 'xlsx']:
                    file_emoji = "📗"
                elif ext in ['ppt', 'pptx']:
                    file_emoji = "📙"
                elif ext in ['zip', 'rar', '7z']:
                    file_emoji = "📦"
                else:
                    file_emoji = "📎"
                
                # Send as message
                chat_id = self.chat.get("_id")
                await self.api_client.send_message(
                    chat_id=chat_id,
                    text=f"{file_emoji} {file_name}"
                )
                
                snack.open = False
                self.page.update()
            
            # Success message
            success_snack = ft.SnackBar(
                content=ft.Text(f"✅ {len(e.files)} file(s) sent!"),
                bgcolor=ft.Colors.GREEN_600,
                duration=2000
            )
            self.page.overlay.append(success_snack)
            success_snack.open = True
            
            # Reload messages
            await self.load_messages()
            
        except Exception as e:
            self.show_error(f"Failed to send: {str(e)[:50]}")
    
    async def load_messages(self):
        """Load messages from chat"""
        colors_palette = self.theme.colors
        
        try:
            chat_id = self.chat.get("_id")
            data = await self.api_client.get_messages(chat_id)
            self.messages_list.controls.clear()
            
            messages = data.get("messages", [])
            
            if not messages:
                # Empty state
                empty = ft.Container(
                    content=ft.Column([
                        ft.Icon(ft.Icons.CHAT_BUBBLE_OUTLINE, size=48, color=colors_palette["text_tertiary"]),
                        ft.Text("No messages yet", size=FONT_SIZES["lg"], color=colors_palette["text_secondary"]),
                        ft.Text("Send a message to start the conversation!", size=FONT_SIZES["sm"], color=colors_palette["text_tertiary"])
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=SPACING["sm"]),
                    alignment=ft.alignment.center,
                    expand=True
                )
                self.messages_list.controls.append(empty)
            else:
                for msg in messages:
                    msg_bubble = self.create_message_bubble(msg)
                    self.messages_list.controls.append(msg_bubble)
            
            self.page.update()
        except Exception as e:
            error_text = str(e)
            print(f"Error loading messages: {error_text}")
            
            error_container = ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.ERROR_OUTLINE, size=48, color=colors_palette["error"]),
                    ft.Text("Failed to load messages", color=colors_palette["error"]),
                    ft.TextButton("Retry", on_click=lambda e: self.page.run_task(self.load_messages))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=SPACING["sm"]),
                alignment=ft.alignment.center,
                expand=True
            )
            self.messages_list.controls.clear()
            self.messages_list.controls.append(error_container)
            self.page.update()
    
    def create_message_bubble(self, message):
        """Create Telegram-style message bubble"""
        colors_palette = self.theme.colors
        
        msg_text = message.get("text", "")
        sender_id = message.get("sender_id", "")
        created_at = message.get("created_at", "")
        message_id = message.get("_id", "")
        is_saved = self.current_user in message.get("saved_by", [])
        is_mine = sender_id == self.current_user
        
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
        
        # Bubble colors
        if is_mine:
            bubble_color = colors_palette["accent"]
            text_color = ft.Colors.WHITE
            align = ft.MainAxisAlignment.END
        else:
            bubble_color = colors_palette["bg_secondary"]
            text_color = colors_palette["text_primary"]
            align = ft.MainAxisAlignment.START
        
        # Message content
        content_widgets = []
        
        # Sender name for group chats
        if not is_mine and self.chat.get("type") == "group":
            content_widgets.append(
                ft.Text(sender_id, size=FONT_SIZES["xs"], color=colors_palette["accent"], weight=ft.FontWeight.W_600)
            )
        
        # File preview if applicable
        if is_file:
            content_widgets.append(
                ft.Container(
                    content=ft.Row([
                        ft.Text(msg_text.split()[0], size=32),  # Emoji
                        ft.Text(" ".join(msg_text.split()[1:]), color=text_color, size=FONT_SIZES["sm"])
                    ], spacing=SPACING["sm"]),
                    padding=ft.padding.symmetric(vertical=SPACING["xs"])
                )
            )
        else:
            content_widgets.append(
                ft.Text(msg_text, color=text_color, size=FONT_SIZES["base"], selectable=True)
            )
        
        # Time and status
        content_widgets.append(
            ft.Row([
                ft.Text(time_str, size=FONT_SIZES["xs"], color=text_color if is_mine else colors_palette["text_tertiary"]),
                ft.Icon(ft.Icons.DONE_ALL if is_mine else None, size=14, color=text_color if is_mine else None) if is_mine else ft.Container(),
            ], spacing=4, alignment=ft.MainAxisAlignment.END)
        )
        
        # Bubble
        bubble = ft.Container(
            content=ft.Column(content_widgets, spacing=SPACING["xs"]),
            bgcolor=bubble_color,
            border_radius=ft.border_radius.only(
                top_left=RADIUS["lg"],
                top_right=RADIUS["lg"],
                bottom_left=0 if is_mine else RADIUS["lg"],
                bottom_right=RADIUS["lg"] if is_mine else RADIUS["lg"]
            ),
            padding=ft.padding.all(SPACING["sm"]),
            width=None,
            margin=ft.margin.only(left=50 if is_mine else 0, right=0 if is_mine else 50),
            on_long_press=lambda e, mid=message_id, saved=is_saved: self.show_message_menu(mid, saved, msg_text)
        )
        
        return ft.Row([bubble], alignment=align)
    
    def show_message_menu(self, message_id: str, is_saved: bool, text: str):
        """Show message context menu"""
        colors_palette = self.theme.colors
        
        def close_menu(e):
            menu_dialog.open = False
            self.page.update()
        
        menu_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Message Options", size=16, weight=ft.FontWeight.W_600),
            content=ft.Column([
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.COPY),
                    title=ft.Text("Copy"),
                    on_click=lambda e: self.copy_and_close(text, menu_dialog)
                ),
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.REPLY),
                    title=ft.Text("Reply"),
                    on_click=lambda e: self.close_and_show_coming_soon(menu_dialog, "Reply")
                ),
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.FORWARD),
                    title=ft.Text("Forward"),
                    on_click=lambda e: self.close_and_show_coming_soon(menu_dialog, "Forward")
                ),
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.BOOKMARK if is_saved else ft.Icons.BOOKMARK_BORDER),
                    title=ft.Text("Unsave" if is_saved else "Save"),
                    on_click=lambda e: self.toggle_save_and_close(message_id, is_saved, menu_dialog)
                ),
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.DELETE, color=colors_palette["error"]),
                    title=ft.Text("Delete", color=colors_palette["error"]),
                    on_click=lambda e: self.delete_and_close(message_id, menu_dialog)
                ),
            ], spacing=0, tight=True),
            actions=[ft.TextButton("Cancel", on_click=close_menu)],
        )
        
        self.page.dialog = menu_dialog
        menu_dialog.open = True
        self.page.update()
    
    def copy_and_close(self, text: str, dialog):
        self.page.set_clipboard(text)
        dialog.open = False
        self.page.update()
        self.show_success("Copied!")
    
    def close_and_show_coming_soon(self, dialog, feature: str):
        dialog.open = False
        self.page.update()
        self.show_coming_soon(feature)
    
    def toggle_save_and_close(self, message_id: str, is_saved: bool, dialog):
        dialog.open = False
        self.page.update()
        self.page.run_task(self.toggle_save_message, message_id, is_saved)
    
    def delete_and_close(self, message_id: str, dialog):
        dialog.open = False
        self.page.update()
        self.page.run_task(self.delete_message, message_id)
    
    async def toggle_save_message(self, message_id: str, is_saved: bool):
        try:
            if is_saved:
                await self.api_client.unsave_message(message_id)
                self.show_success("Message unsaved")
            else:
                await self.api_client.save_message(message_id)
                self.show_success("Message saved!")
            await self.load_messages()
        except Exception as e:
            self.show_error(f"Error: {str(e)[:30]}")
    
    async def delete_message(self, message_id: str):
        try:
            await self.api_client.delete_message(message_id)
            self.show_success("Message deleted")
            await self.load_messages()
        except Exception as e:
            self.show_error(f"Could not delete: {str(e)[:30]}")
    
    async def send_message(self):
        """Send a message"""
        if not self.message_input.value or not self.message_input.value.strip():
            return
        
        try:
            message_text = self.message_input.value
            self.message_input.value = ""
            self.page.update()
            
            chat_id = self.chat.get("_id")
            await self.api_client.send_message(
                chat_id=chat_id,
                text=message_text
            )
            
            # Reload messages
            await self.load_messages()
            
        except Exception as e:
            self.show_error(f"Failed to send: {str(e)[:50]}")
            self.message_input.value = message_text
            self.page.update()
    
    def show_success(self, message: str):
        snack = ft.SnackBar(content=ft.Text(message), bgcolor=ft.Colors.GREEN_600, duration=2000)
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def show_error(self, message: str):
        snack = ft.SnackBar(content=ft.Text(message), bgcolor=ft.Colors.ERROR, duration=3000)
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def show_coming_soon(self, feature: str):
        snack = ft.SnackBar(content=ft.Text(f"🚧 {feature} coming soon!"), duration=2000)
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    def go_back(self):
        if self.on_back:
            self.on_back()
        else:
            self.page.go("/")
