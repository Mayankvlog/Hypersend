"""
Saved Messages View - Enhanced UI for personal message storage
Users can save important messages, files, and media for later reference
"""

import flet as ft
import asyncio
import sys
import os
from typing import Optional, List, Dict, Any
from datetime import datetime

# Add current directory to sys.path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Import API client
from api_client import APIClient

# Import error handler
from error_handler import init_error_handler, handle_error, show_success, show_info

# Compatibility shims
icons = ft.Icons
colors = ft.Colors
ft.colors = ft.Colors

# Constants
SPACING_SMALL = 8
SPACING_MEDIUM = 16
SPACING_LARGE = 24

class SavedMessagesView(ft.View):
    def __init__(self, page: ft.Page, api_client: APIClient, current_user: str, on_back=None):
        super().__init__("/saved")
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_back = on_back
        
        # Theme colors
        self.primary_color = "#1F8EF1"
        self.bg_color = "#FDFBFB"
        self.card_color = "#FFFFFF"
        self.text_color = "#000000"
        self.text_secondary = "#8e8e93"
        
        # State
        self.messages = []
        self.loading = False
        
        self.build_ui()
    
    def build_ui(self):
        """Build the saved messages interface"""
        # AppBar
        self.page.appbar = ft.AppBar(
            title=ft.Text("Saved Messages", weight=ft.FontWeight.BOLD, color=ft.colors.BLACK),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=ft.colors.BLACK,
                on_click=lambda e: self.go_back()
            )
        )
        
        # Messages list
        self.messages_list = ft.ListView(
            expand=True,
            spacing=1,
            padding=ft.padding.symmetric(vertical=8)
        )
        
        # Loading indicator
        self.loading_indicator = ft.ProgressRing(
            visible=False,
            width=20,
            height=20,
            color=self.primary_color
        )
        
        # File picker for uploads
        self.file_picker = ft.FilePicker(on_result=lambda e: self.page.run_task(self.handle_file_upload, e))
        self.page.overlay.append(self.file_picker)
        
        # Message input
        self.message_input = ft.TextField(
            hint_text="💭 Message yourself...",
            border=ft.InputBorder.NONE,
            filled=True,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5,
            keyboard_type=ft.KeyboardType.TEXT,
            autofocus=False,
            read_only=False,
            disabled=False,
            on_change=lambda e: self._handle_input_change(),
            on_submit=lambda e: self.page.run_task(self.send_message),
            on_focus=lambda e: self._on_input_focus(e, True),
            on_blur=lambda e: self._on_input_focus(e, False),
            animate_opacity=ft.Animation(duration=200),
            animate_scale=ft.Animation(duration=200),
        )
        
        # Share menu button
        self.share_btn = ft.IconButton(
            icon=ft.Icons.ADD_CIRCLE_OUTLINE,
            tooltip="Share photo, file, document, or location",
            on_click=lambda e: self.show_share_menu(),
            style=ft.ButtonStyle(
                overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.BLUE),
                animation_duration=200
            )
        )
        
        # Main content
        main_content = ft.Container(
            content=ft.Column([
                # Header with gradient background
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Column([
                                ft.Text(
                                    "📝 Saved Messages",
                                    size=22,
                                    weight=ft.FontWeight.W_700,
                                    color=ft.Colors.WHITE,
                                    animate_opacity=ft.Animation(duration=200)
                                ),
                                ft.Text(
                                    "Your personal space",
                                    size=12,
                                    color=ft.Colors.WHITE70,
                                    weight=ft.FontWeight.W_400,
                                    animate_opacity=ft.Animation(duration=200)
                                ),
                            ], spacing=2),
                            ft.Container(expand=True),
                            ft.Container(
                                content=ft.Icon(
                                    ft.Icons.BOOKMARK_ROUNDED,
                                    color=ft.Colors.WHITE,
                                    size=24
                                ),
                                width=40,
                                height=40,
                                bgcolor=ft.Colors.with_opacity(0.2, ft.Colors.WHITE),
                                border_radius=20,
                            ),
                        ], spacing=15),
                        # Action buttons
                        ft.Row([
                            ft.Container(
                                content=ft.IconButton(
                                    icon=ft.Icons.PHOTO_CAMERA_OUTLINED,
                                    tooltip="Take Photo",
                                    icon_size=18,
                                    icon_color=ft.Colors.WHITE,
                                    style=ft.ButtonStyle(
                                        overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.WHITE),
                                        animation_duration=150,
                                        elevation=0,
                                        padding=0
                                    ),
                                    animate_scale=ft.Animation(duration=100)
                                ),
                                width=40,
                                height=40,
                                bgcolor=ft.LinearGradient(
                                    begin=ft.alignment.top_left,
                                    end=ft.alignment.bottom_right,
                                    colors=[ft.Colors.RED_500, ft.Colors.RED_600]
                                ),
                                border_radius=20,
                                shadow=ft.BoxShadow(
                                    spread_radius=1,
                                    blur_radius=6,
                                    color=ft.Colors.with_opacity(0.25, ft.Colors.RED_600),
                                    offset=ft.Offset(0, 2)
                                ),
                                animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT)
                            ),
                            ft.Container(
                                content=ft.IconButton(
                                    icon=ft.Icons.ATTACH_FILE_OUTLINED,
                                    tooltip="Upload File",
                                    icon_size=18,
                                    icon_color=ft.Colors.WHITE,
                                    style=ft.ButtonStyle(
                                        overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.WHITE),
                                        animation_duration=150,
                                        shadow_color=ft.Colors.BLUE,
                                        elevation=0,
                                        padding=0
                                    ),
                                    animate_scale=ft.Animation(duration=100)
                                ),
                                width=40,
                                height=40,
                                bgcolor=ft.LinearGradient(
                                    begin=ft.alignment.top_left,
                                    end=ft.alignment.bottom_right,
                                    colors=[ft.Colors.BLUE_600, ft.Colors.PURPLE_600]
                                ),
                                border_radius=20,
                                shadow=ft.BoxShadow(
                                    spread_radius=1,
                                    blur_radius=8,
                                    color=ft.Colors.with_opacity(0.3, ft.Colors.BLUE_600),
                                    offset=ft.Offset(0, 3)
                                ),
                                animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT)
                            ),
                            ft.Container(
                                content=ft.Row([
                                    self.loading_indicator,
                                    ft.Text(
                                        "Send",
                                        size=14,
                                        weight=ft.FontWeight.W_600,
                                        color=ft.Colors.WHITE
                                    )
                                ], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
                                width=50,
                                height=50,
                                bgcolor=ft.LinearGradient(
                                    begin=ft.alignment.top_left,
                                    end=ft.alignment.bottom_right,
                                    colors=[ft.Colors.BLUE_600, ft.Colors.PURPLE_600]
                                ),
                                border_radius=25,
                                shadow=ft.BoxShadow(
                                    spread_radius=1,
                                    blur_radius=8,
                                    color=ft.Colors.with_opacity(0.3, ft.Colors.BLUE_600),
                                    offset=ft.Offset(0, 3)
                                ),
                                animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT)
                            )
                        ], spacing=12),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20),
                    alignment=ft.alignment.center,
                    expand=True,
                    padding=ft.padding.all(30)
                ),
                # Messages list
                ft.Container(
                    content=self.messages_list,
                    bgcolor=self.card_color,
                    border_radius=ft.border_radius.all(15),
                    expand=True,
                    padding=ft.padding.all(16)
                ),
                # Message input area
                ft.Container(
                    content=ft.Row([
                        ft.Icon(
                            ft.Icons.EDIT_OUTLINED,
                            size=20,
                            color=self.text_secondary
                        ),
                        self.message_input,
                        ft.IconButton(
                            icon=ft.Icons.SEND_ROUNDED,
                            tooltip="Send message",
                            icon_color=self.primary_color,
                            style=ft.ButtonStyle(
                                overlay_color=ft.Colors.with_opacity(0.1, self.primary_color),
                                animation_duration=150,
                                elevation=0,
                                padding=0
                            ),
                            on_click=lambda e: self.page.run_task(self.send_message)
                        )
                    ], spacing=12),
                    padding=ft.padding.symmetric(horizontal=20, vertical=12),
                    bgcolor=self.card_color,
                    border_radius=ft.border_radius.all(25),
                    margin=ft.margin.only(top=20)
                )
            ], spacing=0),
            bgcolor=self.bg_color,
            expand=True
        )
        
        # Set initial content
        self.content = ft.Container(
            content=main_content,
            bgcolor=self.bg_color,
            expand=True
        )
        
        # Add to page
        self.page.add(self.content)
        self.page.update()
        
        # Load messages
        self.page.run_task(self.load_saved_messages)
    
    async def load_saved_messages(self):
        """Load all saved messages"""
        try:
            data = await self.api_client.get_saved_messages()
            self.messages_list.controls.clear()
            
            messages = data.get("messages", [])
            
            if not messages:
                # Show enhanced empty state
                empty_state = ft.Container(
                    content=ft.Column([
                        ft.Container(
                            content=ft.Icon(ft.Icons.BOOKMARK_BORDER_ROUNDED, size=80, color=ft.Colors.BLUE_GREY_300),
                            bgcolor=ft.Colors.with_opacity(0.1, ft.Colors.BLUE_GREY_100),
                            width=120,
                            height=120,
                            border_radius=60,
                            alignment=ft.alignment.center,
                            shadow=ft.BoxShadow(
                                spread_radius=1,
                                blur_radius=15,
                                color=ft.Colors.with_opacity(0.3, ft.Colors.BLUE_GREY_400),
                                offset=ft.Offset(0, 5)
                            )
                        ),
                        ft.Text(
                            "✨ No saved messages yet",
                            size=20,
                            weight=ft.FontWeight.W_600,
                            text_align=ft.TextAlign.CENTER,
                            color=ft.Colors.BLUE_GREY_600
                        ),
                        ft.Text(
                            "💭 Start a conversation with yourself!\nMessages you save will appear here",
                            size=14,
                            text_align=ft.TextAlign.CENTER,
                            color=ft.Colors.BLUE_GREY_400,
                            weight=ft.FontWeight.W_400
                        ),
                        ft.Container(
                            content=ft.ElevatedButton(
                                "Send your first message",
                                icon=ft.Icons.SEND_ROUNDED,
                                style=ft.ButtonStyle(
                                    bgcolor=ft.LinearGradient(
                                        begin=ft.alignment.top_left,
                                        end=ft.alignment.bottom_right,
                                        colors=[ft.Colors.BLUE_600, ft.Colors.PURPLE_600]
                                    ),
                                    color=ft.Colors.WHITE,
                                    elevation=3,
                                    shadow_color=ft.Colors.BLUE_600,
                                    padding=ft.padding.symmetric(horizontal=20, vertical=12),
                                    shape=ft.RoundedRectangleBorder(radius=25)
                                ),
                                on_click=lambda e: self.message_input.focus()
                            ),
                            margin=ft.margin.only(top=20)
                        )
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
                    alignment=ft.alignment.center,
                    expand=True,
                    padding=ft.padding.all(30)
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
            
            self.messages_list.controls.clear()
            
            # Determine error type and show appropriate message
            if "401" in error_str or "Unauthorized" in error_str:
                error_title = "Session Expired"
                error_msg = "Please log in again to access saved messages"
                error_icon = ft.Icons.LOCK
                error_color = ft.Colors.ORANGE_300
            elif "500" in error_str or "Server" in error_str:
                error_title = "Server Error"
                error_msg = "Backend server is not responding. Please try again later."
                error_icon = ft.Icons.CLOUD_OFF
                error_color = ft.Colors.RED_300
            else:
                error_title = "Failed to load messages"
                error_msg = error_str[:100]
                error_icon = ft.Icons.ERROR_OUTLINE
                error_color = ft.Colors.RED_300
            
            error_state = ft.Container(
                content=ft.Column([
                    ft.Container(
                        content=ft.Icon(error_icon, size=60, color=ft.Colors.WHITE),
                        width=100,
                        height=100,
                        bgcolor=error_color,
                        border_radius=50,
                        alignment=ft.alignment.center,
                        shadow=ft.BoxShadow(
                            spread_radius=1,
                            blur_radius=15,
                            color=ft.Colors.with_opacity(0.3, error_color),
                            offset=ft.Offset(0, 5)
                        )
                    ),
                    ft.Text(
                        error_title,
                        size=18,
                        weight=ft.FontWeight.W_600,
                        text_align=ft.TextAlign.CENTER,
                        color=error_color
                    ),
                    ft.Text(
                        error_msg,
                        size=14,
                        text_align=ft.TextAlign.CENTER,
                        color=ft.Colors.BLUE_GREY_500,
                        weight=ft.FontWeight.W_400,
                        max_lines=3
                    ),
                    ft.Container(height=15),
                    ft.Container(
                        content=ft.ElevatedButton(
                            "🔄 Try Again",
                            icon=ft.Icons.REFRESH_ROUNDED,
                            style=ft.ButtonStyle(
                                bgcolor=ft.LinearGradient(
                                    begin=ft.alignment.top_left,
                                    end=ft.alignment.bottom_right,
                                    colors=[error_color, ft.Colors.with_opacity(0.8, error_color)]
                                ),
                                color=ft.Colors.WHITE,
                                elevation=3,
                                shadow_color=error_color,
                                padding=ft.padding.symmetric(horizontal=25, vertical=12),
                                shape=ft.RoundedRectangleBorder(radius=25)
                            ),
                            on_click=lambda e: self.page.run_task(self.load_saved_messages),
                            animate_scale=ft.Animation(duration=200)
                        ),
                        animate=ft.Animation(duration=300, curve=ft.AnimationCurve.EASE_OUT)
                    )
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
                alignment=ft.alignment.center,
                expand=True,
                padding=ft.padding.all(30)
            )
            self.messages_list.controls.append(error_state)
            self.page.update()
    
    def create_message_card(self, message):
        """Create a saved message card with enhanced UI"""
        msg_text = message.get("text", "")
        sender_id = message.get("sender_id", "Unknown")
        created_at = message.get("created_at", "")
        message_id = message.get("_id", "")
        language = message.get("language") or "en"
        
        # Format timestamp with better date handling
        if isinstance(created_at, str):
            try:
                date_obj = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                timestamp = date_obj.strftime("%b %d, %Y")
            except:
                timestamp = created_at
        else:
            timestamp = str(created_at)
        
        # Language colors for better visual distinction
        lang_colors = {
            "en": (ft.Colors.BLUE_GREY_600, ft.Colors.BLUE_GREY_400),
            "es": (ft.Colors.RED_700, ft.Colors.RED_500),
            "fr": (ft.Colors.BLUE_700, ft.Colors.BLUE_500),
            "de": (ft.Colors.GREY_700, ft.Colors.GREY_500),
            "it": (ft.Colors.GREEN_700, ft.Colors.GREEN_500),
            "pt": (ft.Colors.PURPLE_700, ft.Colors.PURPLE_500),
            "ja": (ft.Colors.RED_700, ft.Colors.RED_500),
            "zh": (ft.Colors.RED_600, ft.Colors.RED_400),
            "ar": (ft.Colors.ORANGE_600, ft.Colors.ORANGE_400),
            "hi": (ft.Colors.ORANGE_700, ft.Colors.ORANGE_500),
        }
        lang_colors_tuple = lang_colors.get(language.lower(), (ft.Colors.BLUE_GREY_600, ft.Colors.BLUE_GREY_400))
        lang_color = lang_colors_tuple[0]
        
        # Enhanced message card with glassmorphism and better animations
        card = ft.Card(
            elevation=3,
            animate_scale=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT),
            animate_offset=ft.Animation(duration=300, curve=ft.AnimationCurve.EASE_OUT_BACK),
            content=ft.Container(
                content=ft.Column([
                    # Header with gradient background
                    ft.Container(
                        content=ft.Row([
                            ft.Column([
                                ft.Text(
                                    "SAVED",
                                    size=13,
                                    weight=ft.FontWeight.W_700,
                                    color=ft.Colors.WHITE,
                                    animate_opacity=ft.Animation(duration=200)
                                ),
                                ft.Text(
                                    timestamp,
                                    size=10,
                                    color=ft.Colors.WHITE70,
                                    opacity=0.9,
                                    animate_opacity=ft.Animation(duration=200)
                                ),
                            ], expand=True, spacing=2),
                            # Enhanced language badge with gradient
                            ft.Container(
                                content=ft.Text(
                                    language.upper(),
                                    size=8,
                                    weight=ft.FontWeight.W_800,
                                    color=ft.Colors.WHITE,
                                    animate_opacity=ft.Animation(duration=150)
                                ),
                                gradient=ft.LinearGradient(
                                    begin=ft.alignment.top_left,
                                    end=ft.alignment.bottom_right,
                                    colors=[lang_colors_tuple[0], lang_colors_tuple[1]]
                                ),
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                border_radius=10,
                                animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT),
                                shadow=ft.BoxShadow(
                                    spread_radius=1,
                                    blur_radius=4,
                                    color=ft.Colors.with_opacity(0.3, lang_color),
                                    offset=ft.Offset(0, 2)
                                )
                            ),
                            # Enhanced action buttons with better styling
                            ft.Row([
                                ft.Container(
                                    content=ft.IconButton(
                                        icon=ft.Icons.COPY_ALL,
                                        tooltip="Copy message",
                                        icon_size=16,
                                        style=ft.ButtonStyle(
                                            overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.BLUE),
                                            animation_duration=150,
                                            shadow_color=ft.Colors.BLUE,
                                            elevation=1,
                                            padding=8
                                        ),
                                        on_click=lambda e: self.copy_message(msg_text),
                                        animate_scale=ft.Animation(duration=100)
                                    ),
                                    bgcolor=ft.Colors.with_opacity(0.1, ft.Colors.BLUE_50),
                                    border_radius=20
                                ),
                                ft.Container(
                                    content=ft.IconButton(
                                        icon=ft.Icons.BOOKMARK_REMOVE,
                                        tooltip="Remove from saved",
                                        icon_size=16,
                                        style=ft.ButtonStyle(
                                            overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.RED),
                                            animation_duration=150,
                                            shadow_color=ft.Colors.RED,
                                            elevation=1,
                                            padding=8
                                        ),
                                        on_click=lambda e, mid=message_id: self.page.run_task(self.unsave_message, mid),
                                        animate_scale=ft.Animation(duration=100)
                                    ),
                                    bgcolor=ft.Colors.with_opacity(0.1, ft.Colors.RED_50),
                                    border_radius=20
                                )
                            ], spacing=8),
                        ], spacing=SPACING_SMALL),
                        padding=ft.padding.symmetric(horizontal=15, vertical=10),
                        border_radius=ft.border_radius.only(top_left=12, top_right=12),
                        gradient=ft.LinearGradient(
                            begin=ft.alignment.top_left,
                            end=ft.alignment.bottom_right,
                            colors=[ft.Colors.BLUE_600, ft.Colors.PURPLE_600]
                        )
                    ),
                    # Enhanced message content with better typography
                    ft.Container(
                        content=ft.Column([
                            ft.Text(
                                msg_text,
                                selectable=True,
                                size=14,
                                color=ft.Colors.BLACK87,
                                line_height=1.6,
                                weight=ft.FontWeight.W_400,
                                animate_opacity=ft.Animation(duration=200)
                            ),
                            # Add interaction hint
                            ft.Container(
                                content=ft.Row([
                                    ft.Icon(ft.Icons.TOUCH_APP, size=12, color=ft.Colors.BLUE_GREY_400),
                                    ft.Text(
                                        "Tap to select • Long press for options",
                                        size=10,
                                        color=ft.Colors.BLUE_GREY_400,
                                        italic=True
                                    )
                                ], spacing=4),
                                margin=ft.margin.only(top=8)
                            )
                        ], spacing=0),
                        padding=ft.padding.all(15),
                        on_click=lambda e: self._on_message_click(e, msg_text),
                        animate=ft.Animation(duration=200)
                    ),
                ], spacing=0),
                animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT),
                border_radius=12,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=8,
                    color=ft.Colors.with_opacity(0.15, ft.Colors.BLACK),
                    offset=ft.Offset(0, 4)
                )
            )
        )
        
        # Store original data for interactions
        card.data = {"message_id": message_id, "text": msg_text}
        return card
    
    def copy_message(self, text: str):
        """Copy message text to clipboard"""
        try:
            self.page.set_clipboard(text)
            # Show a brief feedback message with animation
            snack = ft.SnackBar(
                content=ft.Row([
                    ft.Icon(ft.Icons.CHECK, color=ft.Colors.WHITE, size=16),
                    ft.Text("Message copied to clipboard", color=ft.Colors.WHITE)
                ], spacing=5),
                bgcolor=ft.Colors.GREEN_600,
                duration=2000
            )
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
        except Exception as e:
            print(f"Error copying message: {e}")
    
    def _handle_input_change(self):
        """Handle input field changes for dynamic UI updates"""
        if self.message_input.value and self.message_input.value.strip():
            # Enable send button when there's text
            pass  # Could add dynamic button state changes here
    
    def _on_input_focus(self, e: ft.ControlEvent, focused: bool):
        """Handle input field focus effects"""
        if hasattr(e.control, 'border'):
            e.control.border = ft.InputBorder.UNDERLINE if focused else ft.InputBorder.NONE
            e.control.border_color = ft.Colors.BLUE if focused else ft.Colors.TRANSPARENT
            e.control.border_width = 2 if focused else 0
        self.page.update()
    
    def _on_send_hover(self, e: ft.ControlEvent):
        """Handle send button hover effects"""
        if hasattr(e.control, 'scale'):
            e.control.scale = 1.1
        if hasattr(e.control, 'icon_color'):
            e.control.icon_color = ft.Colors.BLUE_700
        self.page.update()
    
    def _on_share_btn_hover(self, e: ft.ControlEvent, btn_type: str):
        """Handle share button hover effects"""
        if hasattr(e.control, 'scale'):
            e.control.scale = 1.15
        
        # Color variations on hover
        colors = {
            "photo": ft.Colors.BLUE_800,
            "document": ft.Colors.RED_800,
            "file": ft.Colors.GREEN_800,
            "location": ft.Colors.ORANGE_800
        }
        
        if btn_type in colors and hasattr(e.control, 'icon_color'):
            e.control.icon_color = colors[btn_type]
        
        self.page.update()
    
    def _animate_card(self, e: ft.ControlEvent):
        """Animate card on click"""
        if hasattr(e.control, 'scale'):
            e.control.scale = 1.02
            self.page.update()
            # Reset scale after animation
            self.page.set_timeout(lambda: setattr(e.control, 'scale', 1.0), 200)
            self.page.update()
    
    def _on_card_hover(self, e: ft.ControlEvent, hovering: bool):
        """Handle card hover effects"""
        if hasattr(e.control, 'elevation'):
            e.control.elevation = 8 if hovering else 3
            if hasattr(e.control, 'scale'):
                e.control.scale = 1.02 if hovering else 1.0
            self.page.update()
    
    def _on_lang_badge_hover(self, e: ft.ControlEvent):
        """Handle language badge hover effects"""
        if hasattr(e.control, 'scale'):
            e.control.scale = 1.1
        self.page.update()
    
    def _on_message_click(self, e: ft.ControlEvent, text: str):
        """Handle message text click - show context menu"""
        # Create a simple context menu effect
        snack = ft.SnackBar(
            content=ft.Row([
                ft.Icon(ft.Icons.TOUCH_APP, color=ft.Colors.WHITE, size=16),
                ft.Text("Message selected - use buttons above", color=ft.Colors.WHITE)
            ], spacing=5),
            bgcolor=ft.Colors.BLUE_600,
            duration=1500
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    async def send_message(self):
        """Send a message to saved messages with feedback"""
        if not self.message_input.value or not self.message_input.value.strip():
            return
        
        try:
            # Show sending state
            message_text = self.message_input.value
            self.message_input.value = ""
            self._show_loading(True)
            
            # Get or create saved messages chat
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("_id")
            
            if not chat_id:
                self._show_error_snack("Could not find saved messages chat")
                self.message_input.value = message_text  # Restore input
                self._show_loading(False)
                return
            
            # Send the message
            print(f"Sending message to chat {chat_id}: {message_text}")
            result = await self.api_client.send_message(
                chat_id=chat_id,
                text=message_text
            )
            print(f"Message send result: {result}")
            
            # Show success feedback with animation
            snack = ft.SnackBar(
                content=ft.Row([
                    ft.Icon(ft.Icons.CHECK_CIRCLE, color=ft.Colors.WHITE, size=16),
                    ft.Text("✅ Message saved", color=ft.Colors.WHITE)
                ], spacing=5),
                bgcolor=ft.Colors.GREEN_600,
                duration=2000
            )
            self.page.overlay.append(snack)
            snack.open = True
            
            # Reload messages
            await self.load_saved_messages()
            
        except Exception as e:
            error_msg = str(e)
            print(f"Error sending message: {error_msg}")
            self._show_error_snack(f"Failed to save message: {error_msg[:50]}")
            self.message_input.value = message_text  # Restore input on error
        finally:
            self._show_loading(False)
    
    def _show_error_snack(self, message: str):
        """Show error snackbar"""
        snack = ft.SnackBar(
            ft.Text(message, color=ft.Colors.WHITE),
            bgcolor=ft.Colors.ERROR
        )
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
    
    async def unsave_message(self, message_id: str):
        """Remove a message from saved with feedback"""
        try:
            await self.api_client.unsave_message(message_id)
            snack = ft.SnackBar(
                ft.Text("✅ Message removed", color=ft.Colors.WHITE)
            )
            self.page.overlay.append(snack)
            snack.open = True
            await self.load_saved_messages()
        except Exception as e:
            error_msg = str(e)
            print(f"Error unsaving message: {error_msg}")
            self._show_error_snack(f"Failed to remove: {error_msg[:50]}")
    
    def show_share_menu(self):
        """Show share menu with photo, document, file, location options"""
        # Menu is shown via individual buttons below
        pass
    
    def pick_photo(self):
        """Open file picker for photo"""
        try:
            print("Opening photo file picker...")
            self.file_picker.pick_files(
                allowed_extensions=["jpg", "jpeg", "png", "gif", "webp"],
                allow_multiple=False,
                dialog_title="Select Photo"
            )
        except Exception as e:
            print(f"Error opening photo picker: {e}")
            self._show_error_snack("Could not open photo picker")
    
    def pick_document(self):
        """Open file picker for document"""
        try:
            print("Opening document file picker...")
            self.file_picker.pick_files(
                allowed_extensions=["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"],
                allow_multiple=False,
                dialog_title="Select Document"
            )
        except Exception as e:
            print(f"Error opening document picker: {e}")
            self._show_error_snack("Could not open document picker")
    
    def pick_file(self):
        """Open file picker for any file"""
        try:
            print("Opening general file picker...")
            self.file_picker.pick_files(allow_multiple=False)
        except Exception as e:
            print(f"Error opening file picker: {e}")
            self._show_error_snack("Could not open file picker")
    
    def share_location(self):
        """Share location (coming soon)"""
        # Future: Integrate GPS location sharing
        print("Location sharing - feature coming soon")
    
    async def handle_file_upload(self, e: ft.FilePickerResultEvent):
        """Handle file upload from picker"""
        if not e.files:
            return
        
        try:
            file = e.files[0]
            print(f"Selected file: {file.name}, Size: {file.size} bytes")
            
            # Show loading state
            self._show_loading(True)
            
            # Get saved chat
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("_id")
            
            if not chat_id:
                self._show_error_snack("Could not find saved messages chat")
                self._show_loading(False)
                return
            
            # Initialize file upload
            import os
            file_path = file.path if hasattr(file, 'path') else file.name
            
            # Get file info
            file_size = file.size if hasattr(file, 'size') else os.path.getsize(file_path) if os.path.exists(file_path) else 0
            
            # Determine MIME type
            mime_type = "application/octet-stream"
            if file.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp')):
                mime_type = "image/jpeg" if file.name.lower().endswith(('.jpg', '.jpeg')) else "image/png" if file.name.lower().endswith('.png') else "image/gif"
            elif file.name.lower().endswith(('.mp4', '.avi', '.mov', '.mkv')):
                mime_type = "video/mp4"
            elif file.name.lower().endswith(('.pdf', '.doc', '.docx')):
                mime_type = "application/pdf" if file.name.lower().endswith('.pdf') else "application/msword"
            
            # Initialize upload
            upload_init = await self.api_client.init_upload(
                filename=file.name,
                size=file_size,
                mime=mime_type,
                chat_id=chat_id
            )
            
            if upload_init.get("upload_id"):
                upload_id = upload_init["upload_id"]
                print(f"Upload initialized: {upload_id}")
                
                # Read file and upload in chunks
                chunk_size = 4 * 1024 * 1024  # 4MB chunks
                with open(file_path, 'rb') as f:
                    chunk_index = 0
                    while True:
                        chunk_data = f.read(chunk_size)
                        if not chunk_data:
                            break
                        
                        # Upload chunk
                        await self.api_client.upload_chunk(
                            upload_id=upload_id,
                            chunk_index=chunk_index,
                            chunk_data=chunk_data
                        )
                        
                        chunk_index += 1
                        print(f"Uploaded chunk {chunk_index}")
                
                # Complete upload
                complete_result = await self.api_client.complete_upload(upload_id)
                if complete_result.get("file_id"):
                    # Send message with file
                    await self.api_client.send_message(
                        chat_id=chat_id,
                        text=f"📎 {file.name}",
                        file_id=complete_result["file_id"]
                    )
                    
                    # Show success message
                    snack = ft.SnackBar(
                        content=ft.Row([
                            ft.Icon(ft.Icons.CHECK_CIRCLE, color=ft.colors.WHITE, size=16),
                            ft.Text(f"✅ {file.name} uploaded successfully", color=ft.colors.WHITE)
                        ], spacing=5),
                        bgcolor=ft.colors.GREEN_600,
                        duration=3000
                    )
                    self.page.overlay.append(snack)
                    snack.open = True
                    self.page.update()
                    
                    # Reload messages
                    await self.load_saved_messages()
                else:
                    self._show_error_snack("Failed to complete file upload")
            else:
                self._show_error_snack("Failed to initialize file upload")
                
        except Exception as e:
            print(f"Error uploading file: {e}")
            self._show_error_snack(f"Upload failed: {str(e)}")
        finally:
            self._show_loading(False)
    
    def _show_loading(self, show: bool = True):
        """Show/hide loading indicator"""
        self.loading_indicator.visible = show
        self.message_input.disabled = show
        self.page.update()
    
    def _animate_card(self, e: ft.ControlEvent):
        """Animate card on click"""
        if hasattr(e.control, 'scale'):
            e.control.scale = 1.02
            self.page.update()
            # Reset scale after animation
            self.page.set_timeout(lambda: setattr(e.control, 'scale', 1.0), 200)
            self.page.update()
    
    def _on_card_hover(self, e: ft.ControlEvent, hovering: bool):
        """Handle card hover effects"""
        if hasattr(e.control, 'elevation'):
            e.control.elevation = 8 if hovering else 3
            if hasattr(e.control, 'scale'):
                e.control.scale = 1.02 if hovering else 1.0
            self.page.update()
    
    def _on_lang_badge_hover(self, e: ft.ControlEvent):
        """Handle language badge hover effects"""
        if hasattr(e.control, 'scale'):
            e.control.scale = 1.1
        self.page.update()
    
    def _on_message_click(self, e: ft.ControlEvent, text: str):
        """Handle message text click - show context menu"""
        # Create a simple context menu effect
        snack = ft.SnackBar(
            content=ft.Row([
                ft.Icon(ft.Icons.TOUCH_APP, color=ft.colors.WHITE, size=16),
                ft.Text("Message selected - use buttons above", color=ft.colors.WHITE)
            ], spacing=5),
            bgcolor=ft.colors.BLUE_600,
            duration=1500
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