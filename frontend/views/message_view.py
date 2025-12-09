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
ft.Colors = ft.Colors


class MessageView(ft.View):
    """Telegram-like chat view with full messaging features"""
    
    def __init__(self, page: ft.Page, api_client: APIClient, chat: dict, current_user: str, on_back=None, dark_mode: bool = False):
        super().__init__(f"/chat/{chat.get('_id', '')}")
        self.page = page
        self.api_client = api_client
        self.chat = chat
        self.current_user = current_user
        self.on_back = on_back
        
        # Theme - Light blue themed
        self.dark_mode = dark_mode
        self.theme = ZaplyTheme(dark_mode=dark_mode)
        
        # Use exact Telegram colors
        self.theme.colors["accent"] = "#0088CC"
        self.theme.colors["accent_light"] = "#E7F5FF"
        self.theme.colors["accent_hover"] = "#0077B5"
        self.theme.colors["message_sent"] = "#E8F5E8"
        self.theme.colors["message_received"] = "#FFFFFF"
        self.theme.colors["chat_selected"] = "#F0F2F5"
        
        # State
        self.messages = []
        self.loading = False
        self.typing = False
        self.connection_status = "connecting"  # connecting, connected, disconnected
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 1
        
        # File picker
        self.file_picker = ft.FilePicker(on_result=lambda e: self.page.run_task(self.handle_file_upload, e))
        self.page.overlay.append(self.file_picker)
        
        self.build_ui()
    
    def build_ui(self):
        """Build Telegram-like chat interface"""
        colors_palette = self.theme.colors
        chat_name = self.chat.get("name", "Chat")
        chat_type = self.chat.get("type", "private")
        
        # Get chat avatar/icon with light-blue theme
        if chat_type == "saved":
            avatar_icon = ft.Icons.BOOKMARK
            avatar_color = "#0088CC"
            status_text = "cloud storage"
        elif chat_type == "group":
            avatar_icon = ft.Icons.GROUP
            avatar_color = colors_palette["success"]
            status_text = "members" # placeholder
        else:
            avatar_icon = ft.Icons.PERSON
            avatar_color = "#0088CC"
            status_text = "online"

        # AppBar with chat info - cleaner look
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
                    content=ft.Icon(avatar_icon, color=ft.Colors.WHITE, size=24),
                    width=42,
                    height=42,
                    bgcolor=avatar_color,
                    border_radius=21,
                    alignment=ft.alignment.center,
                ),
                ft.Container(width=10),
                ft.Column([
                    ft.Text(
                        chat_name,
                        size=16,
                        weight=ft.FontWeight.W_600,
                        color=colors_palette["text_primary"]
                    ),
                    ft.Text(
                        status_text,
                        size=12,
                        color="#0088CC" if status_text == "online" else colors_palette["text_tertiary"]
                    )
                ], spacing=0, alignment=ft.MainAxisAlignment.CENTER)
            ], spacing=0),
            bgcolor=colors_palette["bg_primary"],
            elevation=0.5,
            actions=[
                # Connection status indicator
                ft.Container(
                    content=ft.Icon(
                        ft.Icons.WIFI_OFF if self.connection_status == "disconnected" else 
                        ft.Icons.SYNC if self.connection_status == "connecting" else 
                        ft.Icons.WIFI,
                        size=20,
                        color=ft.Colors.RED if self.connection_status == "disconnected" else 
                              ft.Colors.ORANGE if self.connection_status == "connecting" else 
                              "#0088CC"
                    ),
                    tooltip=f"Connection: {self.connection_status}",
                    margin=ft.margin.only(right=8)
                ),
                ft.IconButton(
                    icon=ft.Icons.CALL,
                    icon_color=colors_palette["text_primary"],
                    tooltip="Call",
                    on_click=lambda e: self.show_coming_soon("Call")
                ),
                ft.PopupMenuButton(
                    icon=ft.Icons.MORE_VERT,
                    icon_color=colors_palette["text_primary"],
                    tooltip="More",
                    items=[
                        ft.PopupMenuItem(text="Search", icon=ft.Icons.SEARCH, on_click=lambda e: self.show_message_search()),
                        ft.PopupMenuItem(text="Mute", icon=ft.Icons.VOLUME_OFF, on_click=lambda e: self.show_coming_soon("Mute")),
                        ft.PopupMenuItem(text="Clear history", icon=ft.Icons.DELETE_OUTLINE, on_click=lambda e: self.show_coming_soon("Clear")),
                        ft.PopupMenuItem(text="Reconnect", icon=ft.Icons.REFRESH, on_click=lambda e: self.force_reconnect()),
                    ]
                )
            ]
        )
        
        # Telegram-style messages list
        self.messages_list = ft.ListView(
            expand=True,
            spacing=8, # Telegram spacing
            padding=ft.padding.symmetric(horizontal=8, vertical=8),
            auto_scroll=True,
            reverse=True  # New messages at bottom
        )
        
        # Telegram-style message input
        self.message_input = ft.TextField(
            hint_text="Message",
            border=ft.InputBorder.NONE,
            filled=True,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5,
            text_size=15,
            content_padding=ft.padding.symmetric(horizontal=12, vertical=8),
            on_submit=lambda e: self.page.run_task(self.send_message),
            color=colors_palette["text_primary"],
            hint_style=ft.TextStyle(color=colors_palette["text_tertiary"]),
            bgcolor=colors_palette["bg_primary"],
            border_radius=22
        )
        
        # Attach button with light-blue theme
        self.attach_btn = ft.IconButton(
            icon=ft.Icons.ATTACH_FILE,
            icon_color="#0088CC",
            icon_size=26,
            tooltip="Attach",
            style=ft.ButtonStyle(
                padding=0,
                overlay_color="#E7F5FF"
            ),
            on_click=lambda e: self.show_attachment_menu()
        )
        
        # Emoji button with light-blue theme
        self.emoji_btn = ft.IconButton(
            icon=ft.Icons.EMOJI_EMOTIONS_OUTLINED,
            icon_color="#0088CC",
            icon_size=26,
            tooltip="Emoji",
            style=ft.ButtonStyle(
                padding=0,
                overlay_color="#E7F5FF"
            ),
            on_click=lambda e: self.show_emoji_picker()
        )
        
        # Send button with light-blue theme
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND,
            icon_color="#0088CC", # Light blue
            icon_size=28,
            tooltip="Send",
            style=ft.ButtonStyle(
                bgcolor="#E7F5FF",
                overlay_color="#0077B5",
                shape=ft.CircleBorder()
            ),
            on_click=lambda e: self.page.run_task(self.send_message)
        )
        
        # Telegram-style input area
        input_row = ft.Row([
            ft.IconButton(
                icon=icons.ATTACH_FILE,
                icon_color=colors_palette["text_secondary"],
                icon_size=24,
                tooltip="Attach file",
                on_click=lambda e: self.show_attachment_menu()
            ),
            ft.Container(
                content=self.message_input,
                expand=True,
                bgcolor=colors_palette["bg_primary"],
                border_radius=22,
                border=ft.border.all(1, colors_palette["border"])
            ),
            ft.IconButton(
                icon=icons.EMOJI_EMOTIONS_OUTLINED,
                icon_color=colors_palette["text_secondary"],
                icon_size=24,
                tooltip="Emoji",
                on_click=lambda e: self.show_emoji_picker()
            ),
            ft.Container(width=8),
            ft.IconButton(
                icon=icons.SEND,
                icon_color=ft.Colors.WHITE,
                icon_size=24,
                tooltip="Send",
                bgcolor=colors_palette["accent"],
                border_radius=20,
                on_click=lambda e: self.page.run_task(self.send_message)
            )
        ], spacing=8, alignment=ft.MainAxisAlignment.CENTER, vertical_alignment=ft.CrossAxisAlignment.END)

        # Telegram-style input container
        input_container = ft.Container(
            content=input_row,
            padding=ft.padding.symmetric(horizontal=8, vertical=8),
            bgcolor=colors_palette["bg_primary"],
            border=ft.border.only(top=ft.BorderSide(1, colors_palette["divider"]))
        )
        
        # Main content
        main_content = ft.Container(
            content=ft.Column([
                # Messages area - Telegram style background
                ft.Container(
                    content=self.messages_list,
                    expand=True,
                    bgcolor=colors_palette["bg_secondary"] if self.dark_mode else "#DFEAEF",
                    padding=ft.padding.symmetric(horizontal=0, vertical=8),
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
        
        # Attachment options with light-blue themed icons
        options_row1 = ft.Row([
            create_attach_option(ft.Icons.IMAGE, "Photo", "#0088CC", lambda e: close_and_pick(self.pick_photo)),
            create_attach_option(ft.Icons.VIDEOCAM, "Video", "#0077B5", lambda e: close_and_pick(self.pick_video)),
            create_attach_option(ft.Icons.DESCRIPTION, "Document", "#E7F5FF", lambda e: close_and_pick(self.pick_document)),
            create_attach_option(ft.Icons.FOLDER, "File", "#B3E5FC", lambda e: close_and_pick(self.pick_document)),
        ], alignment=ft.MainAxisAlignment.SPACE_EVENLY)
        
        options_row2 = ft.Row([
            create_attach_option(ft.Icons.LOCATION_ON, "Location", "#0277BD", lambda e: close_and_pick(self.share_location)),
            create_attach_option(ft.Icons.MUSIC_NOTE, "Audio", "#0288D1", lambda e: close_and_pick(self.pick_audio)),
            create_attach_option(ft.Icons.CONTACT_PAGE, "Contact", "#039BE5", lambda e: close_and_pick(self.share_contact)),
            create_attach_option(ft.Icons.POLL, "Poll", "#03A9F4", lambda e: self.show_coming_soon("Poll")),
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
        """Handle file upload with progress indicator"""
        if not e.files:
            return
        
        # Create progress indicator
        progress_ring = ft.ProgressRing(width=16, height=16, stroke_width=2, color="#0088CC")
        progress_text = ft.Text("Preparing upload...", size=14)
        progress_bar = ft.ProgressBar(height=4, visible=False)
        
        # Show uploading indicator with light-blue theme
        snack = ft.SnackBar(
            content=ft.Container(
                content=ft.Column([
                    ft.Row([progress_ring, progress_text], spacing=10),
                    progress_bar
                ], spacing=8, tight=True),
                padding=ft.padding.all(12),
                bgcolor="#E7F5FF",
                border_radius=8
            ),
            duration=60000
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
        
        try:
            chat_id = self.chat.get("_id")
            if not chat_id:
                self.show_error("Chat ID not found for file upload")
                snack.open = False
                self.page.update()
                return
            
            count = 0
            total_files = len(e.files)
            
            for i, file in enumerate(e.files):
                file_name = file.name
                file_path = file.path
                
                if not file_path:
                    progress_text.value = f"❌ Could not access {file_name}"
                    snack.update()
                    continue
                
                # Update progress
                progress_text.value = f"Uploading {file_name} ({i+1}/{total_files})..."
                progress_bar.visible = True
                progress_bar.value = (i) / total_files
                snack.update()
                
                print(f"[UPLOAD] Uploading {file_name} to chat {chat_id}")
                
                # Upload with progress callback
                def update_progress(progress):
                    progress_bar.value = progress
                    snack.update()
                
                try:
                    # Upload
                    file_id = await self.api_client.upload_large_file(
                        file_path, 
                        chat_id, 
                        progress_callback=update_progress
                    )
                    
                    print(f"[UPLOAD] File uploaded successfully: {file_id}")
                    
                    # Send message
                    await self.api_client.send_message(
                        chat_id=chat_id,
                        file_id=file_id
                    )
                    
                    print(f"[UPLOAD] Message sent with file: {file_id}")
                    count += 1
                    
                except Exception as upload_e:
                    print(f"[UPLOAD] Upload failed for {file_name}: {upload_e}")
                    progress_text.value = f"❌ Failed to upload {file_name}"
                    snack.update()
                    continue
                
                # Update final progress
                progress_bar.value = (i + 1) / total_files
                snack.update()
            
            # Success
            if count > 0:
                progress_text.value = f"✅ {count} file(s) sent successfully!"
                progress_ring.visible = False
                progress_bar.visible = False
                snack.bgcolor = ft.Colors.GREEN_100
                snack.update()
                
                # Auto-hide after success
                await asyncio.sleep(2)
                
                # Reload messages
                await self.load_messages()
            else:
                progress_text.value = "❌ No files were uploaded"
                progress_ring.visible = False
                progress_bar.visible = False
                snack.bgcolor = ft.Colors.RED_100
                snack.update()
                
                # Auto-hide after error
                await asyncio.sleep(3)
            
            snack.open = False
            self.page.update()
            
        except Exception as e:
            error_msg = str(e)
            print(f"[UPLOAD] Upload error: {error_msg}")
            progress_text.value = f"❌ Upload failed: {error_msg[:30]}"
            progress_ring.visible = False
            progress_bar.visible = False
            snack.bgcolor = ft.Colors.RED_100
            snack.update()
            
            # Auto-hide after error
            await asyncio.sleep(3)
            snack.open = False
            self.page.update()
    
    async def load_messages(self):
        """Load messages from chat with auto-refresh for real-time updates"""
        colors_palette = self.theme.colors
        
        try:
            chat_id = self.chat.get("_id")
            if not chat_id:
                self.show_error("Chat ID not found")
                return
            
            print(f"[MESSAGE] Loading messages for chat {chat_id}")
            
            # Mark chat as read
            try:
                await self.api_client.mark_as_read(chat_id)
                print(f"[MESSAGE] Chat {chat_id} marked as read")
            except Exception as read_e:
                print(f"[MESSAGE] Mark as read failed: {read_e}")
                # Continue even if mark as read fails
            
            # Load initial messages
            try:
                data = await self.api_client.get_messages(chat_id)
                self.messages = data.get("messages", [])
                print(f"[MESSAGE] Loaded {len(self.messages)} messages")
                self.update_message_display()
            except Exception as msg_e:
                print(f"[MESSAGE] Failed to load messages: {msg_e}")
                self.messages = []
                self.update_message_display()
            
            # Start real-time updates using WebSocket or polling
            await self.start_realtime_updates(chat_id)
            
        except Exception as e:
            error_text = str(e)
            print(f"[MESSAGE] Error loading messages: {error_text}")
            self.show_error_state(error_text)
    
    async def start_realtime_updates(self, chat_id: str):
        """Start real-time message updates with WebSocket and reconnection"""
        self.connection_status = "connecting"
        self.update_connection_status()
        
        try:
            await self.connect_websocket_with_retry(chat_id)
        except Exception as e:
            print(f"[MESSAGE] Real-time updates error: {e}")
            self.connection_status = "disconnected"
            self.update_connection_status()
            # Fallback to polling
            self.start_polling_fallback(chat_id)
    
    def update_connection_status(self):
        """Update connection status indicator in app bar"""
        try:
            # Update the connection status icon
            if hasattr(self, 'appbar') and self.appbar:
                # Find and update the connection status icon
                for action in self.appbar.actions:
                    if hasattr(action, 'content') and hasattr(action.content, 'content'):
                        # This is our connection status container
                        icon = action.content.content
                        if self.connection_status == "connected":
                            icon.icon = ft.Icons.WIFI
                            icon.color = "#0088CC"
                            action.tooltip = "Connection: Connected"
                        elif self.connection_status == "connecting":
                            icon.icon = ft.Icons.SYNC
                            icon.color = ft.Colors.ORANGE
                            action.tooltip = "Connection: Connecting..."
                        else:
                            icon.icon = ft.Icons.WIFI_OFF
                            icon.color = ft.Colors.RED
                            action.tooltip = "Connection: Disconnected"
                        break
            self.page.update()
        except Exception as e:
            print(f"[MESSAGE] Error updating connection status: {e}")
    
    def force_reconnect(self):
        """Force reconnection to WebSocket"""
        chat_id = self.chat.get("_id")
        if chat_id:
            self.reconnect_attempts = 0
            self.connection_status = "connecting"
            self.update_connection_status()
            self.page.run_task(self.connect_websocket_with_retry, chat_id)
    
    async def connect_websocket_with_retry(self, chat_id: str):
        """Connect to WebSocket with retry logic"""
        while self.reconnect_attempts < self.max_reconnect_attempts:
            try:
                print(f"[MESSAGE] WebSocket connection attempt {self.reconnect_attempts + 1}")
                
                # Try to use subscribe_to_chat (WebSocket with polling fallback)
                await self.api_client.subscribe_to_chat(
                    chat_id,
                    on_message_callback=lambda data: self.handle_new_message(data),
                    on_error_callback=lambda e: self.handle_websocket_error(e, chat_id)
                )
                
                # If successful, reset reconnect attempts
                self.reconnect_attempts = 0
                self.connection_status = "connected"
                self.update_connection_status()
                print("[MESSAGE] ✅ WebSocket connected successfully")
                break
                
            except Exception as e:
                self.reconnect_attempts += 1
                print(f"[MESSAGE] WebSocket connection failed: {e}")
                
                if self.reconnect_attempts < self.max_reconnect_attempts:
                    # Show reconnection indicator
                    self.show_reconnect_indicator()
                    
                    # Exponential backoff
                    delay = self.reconnect_delay * (2 ** (self.reconnect_attempts - 1))
                    print(f"[MESSAGE] Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    print("[MESSAGE] Max reconnection attempts reached, falling back to polling")
                    self.connection_status = "disconnected"
                    self.update_connection_status()
                    self.start_polling_fallback(chat_id)
                    break
    
    def start_polling_fallback(self, chat_id: str):
        """Start polling fallback when WebSocket fails"""
        print("[MESSAGE] Starting polling fallback for real-time updates")
        
        async def poll_messages():
            try:
                while True:
                    # Poll for new messages every 3 seconds
                    await asyncio.sleep(3)
                    
                    try:
                        data = await self.api_client.get_messages(chat_id, limit=10)
                        new_messages = data.get("messages", [])
                        
                        # Check for new messages
                        if new_messages and len(new_messages) > len(self.messages):
                            self.handle_new_message({"messages": new_messages})
                            
                    except Exception as poll_e:
                        print(f"[MESSAGE] Polling error: {poll_e}")
                        # Continue polling even if one request fails
                        
            except Exception as e:
                print(f"[MESSAGE] Polling loop error: {e}")
        
        # Start polling in background
        self.page.run_task(poll_messages)
    
    def handle_websocket_error(self, error, chat_id: str):
        """Handle WebSocket errors and attempt reconnection"""
        print(f"[MESSAGE] WebSocket error: {error}")
        
        # Attempt to reconnect
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.page.run_task(self.connect_websocket_with_retry, chat_id)
        else:
            # Fallback to polling
            self.start_polling_fallback(chat_id)
    
    def show_reconnect_indicator(self):
        """Show reconnection indicator to user"""
        reconnect_snack = ft.SnackBar(
            content=ft.Row([
                ft.ProgressRing(width=16, height=16, stroke_width=2, color="#0088CC"),
                ft.Text("Reconnecting...", size=14, color="#0088CC")
            ], spacing=10),
            bgcolor="#E7F5FF",
            duration=5000
        )
        self.page.overlay.append(reconnect_snack)
        reconnect_snack.open = True
        self.page.update()
    
    def handle_new_message(self, data: dict):
        """Handle incoming real-time message"""
        try:
            messages = data.get("messages", [])
            if messages:
                # Add new messages
                for msg in messages:
                    # Check if message already exists
                    if not any(m.get("_id") == msg.get("_id") for m in self.messages):
                        self.messages.append(msg)
                
                # Update display
                self.update_message_display()
                
                # Auto-scroll to bottom
                if self.messages_list:
                    self.page.run_task(self.auto_scroll_to_bottom)
        except Exception as e:
            print(f"[MESSAGE] Error handling new message: {e}")
    
    def handle_realtime_error(self, error):
        """Handle real-time connection errors"""
        print(f"[MESSAGE] Real-time error: {error}")
    
    async def auto_scroll_to_bottom(self):
        """Auto-scroll to the latest message"""
        try:
            if self.messages_list and self.messages_list.controls:
                await asyncio.sleep(0.1)
                self.messages_list.scroll_to(offset=-1, duration=300)
        except:
            pass
    
    def update_message_display(self):
        """Update the message list display with date separators (Telegram style)"""
        colors_palette = self.theme.colors
        self.messages_list.controls.clear()
        
        if not self.messages:
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
            from datetime import datetime
            last_date = None
            
            for msg in self.messages:
                # Add date separator if date changed
                try:
                    msg_date_str = msg.get("created_at", "")
                    if msg_date_str:
                        msg_date = datetime.fromisoformat(msg_date_str.replace("Z", "+00:00"))
                        current_date = msg_date.strftime("%B %d, %Y")
                        
                        if current_date != last_date:
                            # Add date separator
                            date_separator = ft.Container(
                                content=ft.Text(
                                    current_date,
                                    size=11,
                                    color=colors_palette["text_tertiary"],
                                    weight=ft.FontWeight.NORMAL
                                ),
                                padding=ft.padding.symmetric(vertical=12),
                                alignment=ft.alignment.center
                            )
                            self.messages_list.controls.append(date_separator)
                            last_date = current_date
                except:
                    pass
                
                msg_bubble = self.create_message_bubble(msg)
                self.messages_list.controls.append(msg_bubble)
        
        self.page.update()
    
    def show_error_state(self, error_text: str):
        """Show error state with retry button"""
        colors_palette = self.theme.colors
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
        """Create Telegram-style message bubble with tails"""
        colors_palette = self.theme.colors
        
        msg_text = message.get("text") or ""
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
        is_file = msg_text.startswith(("📎", "🖼️", "🎬", "🎵", "📕", "📘", "📗", "📙", "📦")) or "file_id" in message
        
        # Telegram-style bubble colors
        if self.dark_mode:
            bubble_color = "#2B5278" if is_mine else "#182533" # Dark mode bubble colors
            text_color = ft.Colors.WHITE
        else:
            bubble_color = colors_palette["message_sent"] if is_mine else colors_palette["message_received"] # Telegram colors
            text_color = colors_palette["text_primary"]
        
        # Telegram-style bubble radius
        if is_mine:
            radius = ft.border_radius.only(
                top_left=18, top_right=18, bottom_left=18, bottom_right=4
            )
            align = ft.MainAxisAlignment.END
        else:
            radius = ft.border_radius.only(
                top_left=4, top_right=18, bottom_left=18, bottom_right=18
            )
            align = ft.MainAxisAlignment.START

        # Message content widgets
        content_widgets = []
        
        # Sender name for group chats (only for others)
        if not is_mine and self.chat.get("type") == "group":
            # Use light blue for sender names
            name_color = "#0088CC"
            content_widgets.append(
                ft.Text(sender_id, size=12, color=name_color, weight=ft.FontWeight.BOLD)
            )
        
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
                             ft.Text("Download", color="#0088CC", size=12, weight=ft.FontWeight.W_500)
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
                # Check marks for my messages with light blue
                ft.Icon(ft.Icons.DONE_ALL, size=14, color="#0088CC") if is_mine else ft.Container()
            ],
            spacing=4,
            alignment=ft.MainAxisAlignment.END,
        )
        
        # Combine Text and Footer
        # We put them in a Column (or Stack for overlay, but Column is safer for variable length)
        final_content = ft.Column(
            controls=content_widgets + [status_row],
            spacing=2,
            tight=True,
            horizontal_alignment=ft.CrossAxisAlignment.END if is_mine else ft.CrossAxisAlignment.START # Keep content aligned
            # Actually better to let text expand and footer align right always?
            # Let's align CrossAxisAlignment.END so timestamp is always right
        )
        
        # Add slight padding for the "tail" visual if needed, but border radius does most work
        
        bubble = ft.Container(
            content=final_content,
            bgcolor=bubble_color,
            border_radius=radius,
            padding=ft.padding.symmetric(horizontal=12, vertical=6),
            width=None,
            constraints=ft.BoxConstraints(max_width=280),
            ink=True,
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
            if not chat_id:
                self.show_error("Chat ID not found")
                self.message_input.value = message_text
                self.page.update()
                return
            
            print(f"[MESSAGE] Sending message to chat {chat_id}: {message_text}")
            
            result = await self.api_client.send_message(
                chat_id=chat_id,
                text=message_text
            )
            
            print(f"[MESSAGE] Message sent successfully: {result}")
            
            # Reload messages
            await self.load_messages()
            
        except Exception as e:
            error_msg = str(e)
            print(f"[MESSAGE] Send message error: {error_msg}")
            self.show_error(f"Failed to send: {error_msg[:50]}")
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
    
    def show_message_search(self):
        """Show message search dialog"""
        search_field = ft.TextField(
            label="Search messages...",
            autofocus=True
        )
        
        search_results = ft.ListView(expand=True, spacing=1)
        
        def update_search(e):
            """Update search results as user types"""
            query = search_field.value.lower().strip()
            search_results.controls.clear()
            
            if not query:
                search_results.controls.append(
                    ft.Container(
                        content=ft.Text(
                            "Type to search messages",
                            color=self.theme.colors["text_secondary"],
                            text_align=ft.TextAlign.CENTER
                        ),
                        padding=20,
                        alignment=ft.alignment.center
                    )
                )
            else:
                found = False
                for msg in self.messages:
                    msg_text = msg.get("text", "").lower()
                    if query in msg_text:
                        found = True
                        # Format message preview
                        sender = "You" if msg.get("sender_id") == self.current_user else "Them"
                        preview = msg.get("text", "")[:100]
                        timestamp = msg.get("created_at", "")
                        
                        msg_item = ft.Container(
                            content=ft.Column([
                                ft.Text(f"{sender}: {preview}", weight=ft.FontWeight.W_500, size=13),
                                ft.Text(timestamp, size=11, color=self.theme.colors["text_secondary"])
                            ], spacing=4),
                            padding=12
                        )
                        search_results.controls.append(msg_item)
                        search_results.controls.append(ft.Divider(height=1))
                
                if not found:
                    search_results.controls.append(
                        ft.Container(
                            content=ft.Text(
                                "No messages found",
                                color=self.theme.colors["text_secondary"],
                                text_align=ft.TextAlign.CENTER
                            ),
                            padding=20,
                            alignment=ft.alignment.center
                        )
                    )
            
            self.page.update()
        
        search_field.on_change = update_search
        
        # Initial message
        search_results.controls.append(
            ft.Container(
                content=ft.Text(
                    "Type to search messages",
                    color=self.theme.colors["text_secondary"],
                    text_align=ft.TextAlign.CENTER
                ),
                padding=20,
                alignment=ft.alignment.center
            )
        )
        
        dialog = ft.AlertDialog(
            title=ft.Text("Search Messages", weight=ft.FontWeight.BOLD),
            content=ft.Container(
                content=ft.Column([
                    search_field,
                    ft.Divider(),
                    search_results
                ], spacing=10, expand=True),
                width=400,
                height=500
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))
            ]
        )
        
        self.page.open(dialog)
    
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


