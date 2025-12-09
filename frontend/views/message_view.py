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
            status_text = "cloud storage"
        elif chat_type == "group":
            avatar_icon = ft.Icons.GROUP
            avatar_color = colors_palette["success"]
            status_text = "members" # placeholder
        else:
            avatar_icon = ft.Icons.PERSON
            avatar_color = colors_palette["accent"]
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
                        color=colors_palette["accent"] if status_text == "online" else colors_palette["text_tertiary"]
                    )
                ], spacing=0, alignment=ft.MainAxisAlignment.CENTER)
            ], spacing=0),
            bgcolor=colors_palette["bg_primary"],
            elevation=0.5,
            actions=[
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
                    ]
                )
            ]
        )
        
        # Messages list background
        # Use a subtle pattern or color? For now solid color but distinct from input
        
        self.messages_list = ft.ListView(
            expand=True,
            spacing=4, # Tighter spacing for bubbles
            padding=ft.padding.symmetric(horizontal=10, vertical=10),
            auto_scroll=True
        )
        
        # Message input styling
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
        
        # Send button (Floating style)
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND,
            icon_color=colors_palette["accent"], # Telegram blue
            icon_size=28,
            tooltip="Send",
            on_click=lambda e: self.page.run_task(self.send_message)
        )
        
        # Input area container - Telegram style
        # Attach Icon -> [Emoji Icon | Input Field] -> Send Icon
        input_row = ft.Row([
            self.attach_btn,
            ft.Container(
                content=ft.Row([
                    self.emoji_btn,
                    self.message_input
                ], spacing=0, alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.END), # Align bottom for multiline
                bgcolor=colors_palette["bg_primary"] if self.dark_mode else ft.Colors.WHITE,
                border_radius=20, # Pill shape
                padding=ft.padding.only(left=5, right=15, top=2, bottom=2),
                expand=True,
                # Add shadow for depth if needed
            ),
            self.send_btn
        ], spacing=10, alignment=ft.MainAxisAlignment.CENTER, vertical_alignment=ft.CrossAxisAlignment.END)

        # Bottom container wrapper
        input_container = ft.Container(
            content=input_row,
            padding=ft.padding.all(10),
            bgcolor=colors_palette["bg_secondary"], # Slightly different from message list bg
            border=ft.border.only(top=ft.BorderSide(1, colors_palette["divider"] if self.dark_mode else ft.Colors.TRANSPARENT))
        )
        
        # Main content
        main_content = ft.Container(
            content=ft.Column([
                # Messages area
                ft.Container(
                    content=self.messages_list,
                    expand=True,
                    # Background image or color
                    bgcolor=colors_palette["bg_secondary"] if self.dark_mode else "#E6EBEF", # Telegram-ish light bg
                    image_src="https://web.telegram.org/img/bg_0.png" if not self.dark_mode else None, # Optional: pattern
                    image_fit=ft.ImageFit.COVER,
                    image_opacity=0.5
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
        
        # Attachment options with beautiful colored icons
        options_row1 = ft.Row([
            create_attach_option(ft.Icons.IMAGE, "Photo", "#4CAF50", lambda e: close_and_pick(self.pick_photo)),
            create_attach_option(ft.Icons.VIDEOCAM, "Video", "#2196F3", lambda e: close_and_pick(self.pick_video)),
            create_attach_option(ft.Icons.DESCRIPTION, "Document", "#FF9800", lambda e: close_and_pick(self.pick_document)),
            create_attach_option(ft.Icons.FOLDER, "File", "#9C27B0", lambda e: close_and_pick(self.pick_document)),
        ], alignment=ft.MainAxisAlignment.SPACE_EVENLY)
        
        options_row2 = ft.Row([
            create_attach_option(ft.Icons.LOCATION_ON, "Location", "#F44336", lambda e: close_and_pick(self.share_location)),
            create_attach_option(ft.Icons.MUSIC_NOTE, "Audio", "#E91E63", lambda e: close_and_pick(self.pick_audio)),
            create_attach_option(ft.Icons.CONTACT_PAGE, "Contact", "#607D8B", lambda e: close_and_pick(self.share_contact)),
            create_attach_option(ft.Icons.POLL, "Poll", "#00BCD4", lambda e: self.show_coming_soon("Poll")),
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
        """Handle file upload"""
        if not e.files:
            return
        
        # Show uploading indicator
        snack = ft.SnackBar(
            content=ft.Row([
                ft.ProgressRing(width=16, height=16, stroke_width=2),
                ft.Text("Preparing upload...")
            ], spacing=10),
            duration=60000
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
        
        try:
            chat_id = self.chat.get("_id")
            
            count = 0
            for file in e.files:
                file_name = file.name
                file_path = file.path
                
                # Update snackbar
                snack.content.controls[1].value = f"Sending {file_name}..."
                snack.update()
                
                # Upload
                file_id = await self.api_client.upload_large_file(file_path, chat_id)
                
                # Send message
                await self.api_client.send_message(
                    chat_id=chat_id,
                    file_id=file_id
                )
                count += 1
            
            snack.open = False
            self.page.update()
            
            # Success message
            success_snack = ft.SnackBar(
                content=ft.Text(f"✅ {count} file(s) sent!"),
                bgcolor=ft.Colors.GREEN_600,
                duration=2000
            )
            self.page.overlay.append(success_snack)
            success_snack.open = True
            
            # Reload messages
            await self.load_messages()
            
        except Exception as e:
            snack.open = False
            self.page.update()
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
        """Create Telegram-style message bubble with tails"""
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
        
        # Bubble Styling - Telegram Colors
        if self.dark_mode:
            search_bg = "#2B5278" if is_mine else "#182533" # Dark mode bubble colors
            text_color = ft.Colors.WHITE
        else:
            search_bg = "#EEFFDE" if is_mine else ft.Colors.WHITE # Telegram Light Green for self, White for others
            text_color = ft.Colors.BLACK
            
        bubble_color = search_bg
        
        # Border Radius for Tail Effect
        if is_mine:
            radius = ft.border_radius.only(
                top_left=16, top_right=16, bottom_left=16, bottom_right=0
            )
            align = ft.MainAxisAlignment.END
        else:
            radius = ft.border_radius.only(
                top_left=0, top_right=16, bottom_left=16, bottom_right=16
            )
            align = ft.MainAxisAlignment.START

        # Message content widgets
        content_widgets = []
        
        # Sender name for group chats (only for others)
        if not is_mine and self.chat.get("type") == "group":
            # Deterministic color based on sender_id length or hash could be cool
            name_color = colors_palette["accent"]
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
                # Check marks for my messages
                ft.Icon(ft.Icons.DONE_ALL, size=14, color=ft.Colors.BLUE_400) if is_mine else ft.Container()
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
            constraints=ft.BoxConstraints(max_width=300), # Limit width
            # Shadow for depth
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=1,
                color=ft.Colors.with_opacity(0.1, ft.Colors.BLACK),
                offset=ft.Offset(0, 1),
            ),
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


