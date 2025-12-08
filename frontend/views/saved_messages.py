import flet as ft
from theme import SPACING_SMALL, SPACING_MEDIUM, TEXT_BLACK


class SavedMessagesView(ft.Container):
    """View to display all saved messages with typing capability"""
    
    def __init__(self, page, api_client, current_user, on_back):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_back = on_back
        
        # Messages list
        self.messages_list = ft.ListView(
            spacing=SPACING_SMALL,
            padding=SPACING_MEDIUM,
            expand=True
        )
        
# Enhanced message input field with modern design
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
            text_style=ft.TextStyle(
                size=14,
                color=ft.Colors.BLACK87,
                height=1.5,
                weight=ft.FontWeight.W_400
            ),
            hint_style=ft.TextStyle(
                color=ft.Colors.BLUE_GREY_400,
                size=14,
                weight=ft.FontWeight.W_300
            ),
            content_padding=ft.padding.symmetric(horizontal=15, vertical=12),
            bgcolor=ft.Colors.GREY_50,
            border_radius=25
        )
        
        # Loading indicator
        self.loading_indicator = ft.ProgressRing(
            visible=False,
            width=20,
            height=20,
            color=ft.Colors.BLUE
        )
        
        # File picker for uploads
        self.file_picker = ft.FilePicker(on_result=lambda e: self.page.run_task(self.handle_file_upload, e))
        page.overlay.append(self.file_picker)
        
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
        
        # Layout
        self.content = ft.Column(
            [
                # Enhanced header with gradient
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Container(
                                content=ft.IconButton(
                                    icon=ft.Icons.ARROW_BACK_ROUNDED,
                                    icon_color=ft.Colors.WHITE,
                                    tooltip="Back",
                                    style=ft.ButtonStyle(
                                        overlay_color=ft.Colors.with_opacity(0.2, ft.Colors.WHITE),
                                        animation_duration=150,
                                        elevation=0
                                    ),
                                    on_click=lambda e: self.on_back()
                                ),
                                width=40,
                                height=40,
                                bgcolor=ft.Colors.with_opacity(0.2, ft.Colors.WHITE),
                                border_radius=20
                            ),
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
                                alignment=ft.alignment.center
                            )
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                    ),
                    padding=ft.padding.symmetric(horizontal=20, vertical=15),
                    gradient=ft.LinearGradient(
                        begin=ft.alignment.top_left,
                        end=ft.alignment.bottom_right,
                        colors=[ft.Colors.BLUE_600, ft.Colors.PURPLE_600]
                    ),
                    shadow=ft.BoxShadow(
                        spread_radius=0,
                        blur_radius=10,
                        color=ft.Colors.with_opacity(0.2, ft.Colors.BLUE_600),
                        offset=ft.Offset(0, 3)
                    )
                ),
                # Messages
                self.messages_list,
                # Message input at bottom
                ft.Divider(height=1),
                ft.Container(
                    content=ft.Column([
                        # Enhanced share button row with modern design
                        ft.Container(
                            content=ft.Row([
                                ft.Container(
                                    content=ft.IconButton(
                                        icon=ft.Icons.PHOTO_CAMERA_OUTLINED,
                                        tooltip="Upload Photo",
                                        icon_size=18,
                                        icon_color=ft.Colors.WHITE,
                                        style=ft.ButtonStyle(
                                            overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.WHITE),
                                            animation_duration=150,
                                            elevation=0,
                                            padding=0
                                        ),
                                        on_click=lambda e: self.pick_photo(),
                                        animate_scale=ft.Animation(duration=100)
                                    ),
                                    width=40,
                                    height=40,
                                    bgcolor=ft.LinearGradient(
                                        begin=ft.alignment.top_left,
                                        end=ft.alignment.bottom_right,
                                        colors=[ft.Colors.BLUE_500, ft.Colors.BLUE_600]
                                    ),
                                    border_radius=20,
                                    shadow=ft.BoxShadow(
                                        spread_radius=1,
                                        blur_radius=6,
                                        color=ft.Colors.with_opacity(0.25, ft.Colors.BLUE_600),
                                        offset=ft.Offset(0, 2)
                                    ),
                                    animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT)
                                ),
                                ft.Container(
                                    content=ft.IconButton(
                                        icon=ft.Icons.DESCRIPTION_OUTLINED,
                                        tooltip="Share Document",
                                        icon_size=18,
                                        icon_color=ft.Colors.WHITE,
                                        style=ft.ButtonStyle(
                                            overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.WHITE),
                                            animation_duration=150,
                                            elevation=0,
                                            padding=0
                                        ),
                                        on_click=lambda e: self.pick_document(),
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
                                            elevation=0,
                                            padding=0
                                        ),
                                        on_click=lambda e: self.pick_file(),
                                        animate_scale=ft.Animation(duration=100)
                                    ),
                                    width=40,
                                    height=40,
                                    bgcolor=ft.LinearGradient(
                                        begin=ft.alignment.top_left,
                                        end=ft.alignment.bottom_right,
                                        colors=[ft.Colors.GREEN_500, ft.Colors.GREEN_600]
                                    ),
                                    border_radius=20,
                                    shadow=ft.BoxShadow(
                                        spread_radius=1,
                                        blur_radius=6,
                                        color=ft.Colors.with_opacity(0.25, ft.Colors.GREEN_600),
                                        offset=ft.Offset(0, 2)
                                    ),
                                    animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT)
                                ),
                                ft.Container(
                                    content=ft.IconButton(
                                        icon=ft.Icons.LOCATION_ON_OUTLINED,
                                        tooltip="Share Location",
                                        icon_size=18,
                                        icon_color=ft.Colors.WHITE,
                                        style=ft.ButtonStyle(
                                            overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.WHITE),
                                            animation_duration=150,
                                            elevation=0,
                                            padding=0
                                        ),
                                        on_click=lambda e: self.share_location(),
                                        animate_scale=ft.Animation(duration=100)
                                    ),
                                    width=40,
                                    height=40,
                                    bgcolor=ft.LinearGradient(
                                        begin=ft.alignment.top_left,
                                        end=ft.alignment.bottom_right,
                                        colors=[ft.Colors.ORANGE_500, ft.Colors.ORANGE_600]
                                    ),
                                    border_radius=20,
                                    shadow=ft.BoxShadow(
                                        spread_radius=1,
                                        blur_radius=6,
                                        color=ft.Colors.with_opacity(0.25, ft.Colors.ORANGE_600),
                                        offset=ft.Offset(0, 2)
                                    ),
                                    animate=ft.Animation(duration=200, curve=ft.AnimationCurve.EASE_OUT)
                                ),
                                ft.Container(expand=True)
                            ], spacing=12, alignment=ft.MainAxisAlignment.CENTER),
                            padding=ft.padding.symmetric(horizontal=10, vertical=8),
                            bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.BLUE_GREY_50),
                            border_radius=25
                        ),
# Enhanced message input row with modern design
                        ft.Container(
                            content=ft.Row(
                                [
                                    self.message_input,
                                    ft.Container(
                                        content=ft.Row([
                                            ft.IconButton(
                                                icon=ft.Icons.SEND_ROUNDED,
                                                icon_color=ft.Colors.WHITE,
                                                tooltip="Send message",
                                                on_click=lambda e: self.page.run_task(self.send_message),
                                                style=ft.ButtonStyle(
                                                    overlay_color=ft.Colors.with_opacity(0.3, ft.Colors.WHITE),
                                                    animation_duration=200,
                                                    shadow_color=ft.Colors.BLUE,
                                                    elevation=0,
                                                    padding=0
                                                ),
                                                animate_scale=ft.Animation(duration=150, curve=ft.AnimationCurve.EASE_OUT),
                                                width=40,
                                                height=40
                                            ),
                                            self.loading_indicator
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
                                ],
                                spacing=12,
                                alignment=ft.MainAxisAlignment.END
                            ),
                            padding=ft.padding.all(5),
                            bgcolor=ft.Colors.WHITE,
                            border_radius=30,
                            border=ft.border.all(1, ft.Colors.BLUE_GREY_100),
                            shadow=ft.BoxShadow(
                                spread_radius=0,
                                blur_radius=10,
                                color=ft.Colors.with_opacity(0.1, ft.Colors.BLACK),
                                offset=ft.Offset(0, 2)
                            )
                        )
                    ], spacing=5),
                    padding=SPACING_MEDIUM,
                    bgcolor=ft.Colors.WHITE
                )
            ],
            spacing=0
        )
        
        self.expand = True
        # Load saved messages after page is ready
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
                                spread_radius=0,
                                blur_radius=20,
                                color=ft.Colors.with_opacity(0.1, ft.Colors.BLUE_GREY_400),
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
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20),
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
            if "T" in created_at:
                date_part = created_at.split("T")[0]
                time_part = created_at.split("T")[1].split(".")[0] if "." in created_at.split("T")[1] else created_at.split("T")[1][:5]
                timestamp = f"{date_part} {time_part}"
            else:
                timestamp = created_at
        else:
            timestamp = str(created_at)
        
        # Format sender ID (show just the email name if it's an email)
        sender_display = sender_id.split("@")[0] if "@" in sender_id else sender_id
        
        # Enhanced language badge colors with gradients
        lang_colors = {
            "en": (ft.Colors.BLUE_600, ft.Colors.BLUE_400),
            "es": (ft.Colors.RED_600, ft.Colors.RED_400),
            "fr": (ft.Colors.BLUE_700, ft.Colors.BLUE_500),
            "de": (ft.Colors.BLACK87, ft.Colors.GREY_700),
            "it": (ft.Colors.GREEN_600, ft.Colors.GREEN_400),
            "pt": (ft.Colors.GREEN_700, ft.Colors.GREEN_500),
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
                                    sender_display.upper(),
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
            await self.api_client.send_message(
                chat_id=chat_id,
                text=message_text
            )
            
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
        self.file_picker.pick_files(
            allowed_extensions=["jpg", "jpeg", "png", "gif", "webp"],
            allow_multiple=False,
            dialog_title="Select Photo"
        )
    
    def pick_document(self):
        """Open file picker for document"""
        self.file_picker.pick_files(
            allowed_extensions=["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"],
            allow_multiple=False,
            dialog_title="Select Document"
        )
    
    def pick_file(self):
        """Open file picker for any file"""
        self.file_picker.pick_files(allow_multiple=False)
    
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
            # Future: Upload file to server
            print(f"Selected file: {file.name}")
            # For now, just add a note about the file to saved messages
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("_id")
            
            if chat_id:
                # Send a text message about the file
                await self.api_client.send_message(
                    chat_id=chat_id,
                    text=f"📎 File: {file.name}"
                )
                await self.load_saved_messages()
                self.page.update()
        except Exception as e:
            print(f"Error uploading file: {e}")
