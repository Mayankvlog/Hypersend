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
        
        # Message input field (like Telegram Saved Messages)
        self.message_input = ft.TextField(
            hint_text="Message yourself...",
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
        )
        
        # File picker for uploads
        self.file_picker = ft.FilePicker(on_result=lambda e: self.handle_file_upload(e))
        page.overlay.append(self.file_picker)
        
        # Share menu button
        self.share_btn = ft.IconButton(
            icon=ft.Icons.ADD_CIRCLE_OUTLINE,
            tooltip="Share photo, file, document, or location",
            on_click=lambda e: self.show_share_menu()
        )
        
        # Layout
        self.content = ft.Column(
            [
                # Header
                ft.Container(
                    content=ft.Row(
                        [
                            ft.IconButton(
                                icon=ft.Icons.ARROW_BACK,
                                icon_color=TEXT_BLACK,
                                on_click=lambda e: self.on_back()
                            ),
                            ft.Text(
                                "Saved Messages",
                                size=20,
                                weight=ft.FontWeight.BOLD,
                                color=TEXT_BLACK,
                            ),
                            ft.Container(expand=True)
                        ],
                        alignment=ft.MainAxisAlignment.START
                    ),
                    padding=SPACING_MEDIUM,
                    bgcolor=ft.Colors.WHITE,
                ),
                # Messages
                self.messages_list,
                # Message input at bottom
                ft.Divider(height=1),
                ft.Container(
                    content=ft.Column([
                        # Share button row (photo, document, file, location)
                        ft.Row([
                            ft.IconButton(
                                icon=ft.Icons.PHOTO,
                                tooltip="Upload Photo",
                                icon_size=20,
                                on_click=lambda e: self.pick_photo()
                            ),
                            ft.IconButton(
                                icon=ft.Icons.DESCRIPTION,
                                tooltip="Share Document",
                                icon_size=20,
                                on_click=lambda e: self.pick_document()
                            ),
                            ft.IconButton(
                                icon=ft.Icons.ATTACH_FILE,
                                tooltip="Upload File",
                                icon_size=20,
                                on_click=lambda e: self.pick_file()
                            ),
                            ft.IconButton(
                                icon=ft.Icons.LOCATION_ON,
                                tooltip="Share Location",
                                icon_size=20,
                                on_click=lambda e: self.share_location()
                            ),
                            ft.Container(expand=True)
                        ], spacing=5, height=40),
                        # Message input row
                        ft.Row(
                            [
                                self.message_input,
                                ft.IconButton(
                                    icon=ft.Icons.SEND,
                                    icon_color=ft.Colors.BLUE,
                                    tooltip="Send message",
                                    on_click=lambda e: self.page.run_task(self.send_message)
                                )
                            ],
                            spacing=SPACING_SMALL
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
                # Show empty state
                self.messages_list.controls.append(
                    ft.Column([
                        ft.Icon(ft.Icons.BOOKMARK_BORDER, size=64, color=ft.Colors.BLUE_GREY_300),
                        ft.Text(
                            "No saved messages yet",
                            size=18,
                            weight=ft.FontWeight.W_500,
                            text_align=ft.TextAlign.CENTER,
                            color=ft.Colors.BLUE_GREY_400
                        ),
                        ft.Text(
                            "Messages you save will appear here",
                            size=12,
                            text_align=ft.TextAlign.CENTER,
                            color=ft.Colors.BLUE_GREY_300,
                            opacity=0.7
                        ),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20),
                    alignment=ft.alignment.center,
                    expand=True
                )
            else:
                for msg in messages:
                    msg_card = self.create_message_card(msg)
                    self.messages_list.controls.append(msg_card)
            
            self.page.update()
        except Exception as e:
            print(f"Error loading saved messages: {e}")
            self.messages_list.controls.clear()
            self.messages_list.controls.append(
                ft.Column([
                    ft.Icon(ft.Icons.ERROR_OUTLINE, size=64, color=ft.Colors.RED_300),
                    ft.Text(
                        "Failed to load messages",
                        size=16,
                        weight=ft.FontWeight.W_500,
                        text_align=ft.TextAlign.CENTER,
                        color=ft.Colors.RED_400
                    ),
                    ft.Text(
                        str(e)[:100],
                        size=12,
                        text_align=ft.TextAlign.CENTER,
                        color=ft.Colors.RED_200,
                        opacity=0.7
                    ),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
                alignment=ft.alignment.center,
                expand=True
            )
            self.page.update()
    
    def create_message_card(self, message):
        """Create a saved message card"""
        msg_text = message.get("text", "")
        sender_id = message.get("sender_id", "Unknown")
        created_at = message.get("created_at", "")
        message_id = message.get("_id", "")
        language = message.get("language") or "en"
        
        # Format timestamp
        if isinstance(created_at, str):
            timestamp = created_at.split("T")[0] if "T" in created_at else created_at
        else:
            timestamp = str(created_at)
        
        return ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Column([
                            ft.Text(f"From: {sender_id}", size=12, opacity=0.7),
                            ft.Text(
                                f"{timestamp}  •  Lang: {language}",
                                size=10,
                                opacity=0.5,
                            ),
                        ], expand=True),
                        ft.IconButton(
                            icon=ft.Icons.BOOKMARK_REMOVE,
                            tooltip="Remove from saved",
                            on_click=lambda e, mid=message_id: self.page.run_task(self.unsave_message, mid)
                        )
                    ]),
                    ft.Divider(height=1),
                    ft.Text(msg_text, selectable=True, max_lines=5)
                ], spacing=SPACING_SMALL),
                padding=SPACING_MEDIUM
            )
        )
    
    async def send_message(self):
        """Send a message to saved messages"""
        if not self.message_input.value or not self.message_input.value.strip():
            return
        
        try:
            # Get or create saved messages chat
            saved_chat = await self.api_client.get_saved_chat()
            chat_id = saved_chat.get("_id")
            
            if not chat_id:
                print("Error: Could not get saved chat ID")
                return
            
            # Send the message
            await self.api_client.send_message(
                chat_id=chat_id,
                text=self.message_input.value
            )
            
            # Clear input and reload messages
            self.message_input.value = ""
            await self.load_saved_messages()
            self.page.update()
            
        except Exception as e:
            print(f"Error sending message: {e}")
    
    async def unsave_message(self, message_id: str):
        """Remove a message from saved"""
        try:
            await self.api_client.unsave_message(message_id)
            await self.load_saved_messages()
        except Exception as e:
            print(f"Error unsaving message: {e}")
    
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
