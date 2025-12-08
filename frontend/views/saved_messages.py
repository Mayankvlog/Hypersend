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
except ImportError:
    # Fallback for different import contexts
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from api_client import APIClient
    from theme import ZaplyTheme, LIGHT_COLORS, DARK_COLORS, FONT_SIZES, SPACING, RADIUS


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
        
        self.build_ui()
    
    def build_ui(self):
        """Build the minimal clean saved messages interface"""
        colors_palette = self.theme.colors
        
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
                    icon=ft.Icons.DARK_MODE if not self.dark_mode else ft.Icons.LIGHT_MODE,
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
            focused_border_color=colors_palette["accent"]
        )
        
        # Send button
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND_ROUNDED,
            icon_color=colors_palette["accent"],
            on_click=lambda e: self.page.run_task(self.send_message),
            tooltip="Send"
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
                # Input area - Simple bottom bar
                ft.Container(
                    content=ft.Row([
                        ft.IconButton(
                            icon=ft.Icons.ATTACH_FILE,
                            icon_color=colors_palette["text_secondary"],
                            tooltip="Attach file"
                        ),
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
        
        # Load messages
        self.page.run_task(self.load_saved_messages)
    
    def toggle_theme(self):
        """Toggle between light and dark mode"""
        self.dark_mode = not self.dark_mode
        self.theme = ZaplyTheme(dark_mode=self.dark_mode)
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        
        # Rebuild UI with new theme
        self.build_ui()
        self.page.update()
    
    async def load_saved_messages(self):
        """Load all saved messages"""
        colors_palette = self.theme.colors
        
        try:
            data = await self.api_client.get_saved_messages()
            self.messages_list.controls.clear()
            
            messages = data.get("messages", [])
            
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
                        on_click=lambda e: self.copy_message(msg_text)
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
            chat_id = saved_chat.get("_id")
            
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
            self.message_input.value = message_text
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