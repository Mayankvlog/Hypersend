import flet as ft
from theme import PRIMARY_COLOR, SPACING_SMALL, SPACING_MEDIUM


class MessageView(ft.Container):
    """View to display messages in a chat with save functionality"""
    
    def __init__(self, page, api_client, chat, current_user, on_back):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.chat = chat
        self.current_user = current_user
        self.on_back = on_back
        
        # Messages list
        self.messages_list = ft.ListView(
            spacing=SPACING_SMALL,
            padding=SPACING_MEDIUM,
            expand=True,
            auto_scroll=True
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
                                on_click=lambda e: self.on_back()
                            ),
                            ft.Text(chat.get("name", "Chat"), size=20, weight=ft.FontWeight.BOLD),
                            ft.Container(expand=True)
                        ],
                        alignment=ft.MainAxisAlignment.START
                    ),
                    padding=SPACING_MEDIUM,
                    bgcolor=PRIMARY_COLOR
                ),
                # Messages
                self.messages_list,
            ],
            spacing=0
        )
        
        self.expand = True
        # Load messages after page is ready
        self.page.run_task(self.load_messages)
    
    async def load_messages(self):
        """Load messages from chat"""
        try:
            data = await self.api_client.get_messages(self.chat["_id"])
            self.messages_list.controls.clear()
            
            messages = data.get("messages", [])
            
            if not messages:
                empty_text = ft.Text("No messages yet", 
                           text_align=ft.TextAlign.CENTER,
                           opacity=0.6)
                self.messages_list.controls.append(empty_text)
            else:
                for msg in messages:
                    msg_card = self.create_message_card(msg)
                    self.messages_list.controls.append(msg_card)
            
            self.page.update()
        except Exception as e:
            print(f"Error loading messages: {e}")
            self.messages_list.controls.clear()
            error_text = ft.Text(f"Error loading messages: {str(e)}", 
                       text_align=ft.TextAlign.CENTER,
                       color="red")
            self.messages_list.controls.append(error_text)
            self.page.update()
    
    def create_message_card(self, message):
        """Create a message card with save option"""
        msg_text = message.get("text", "")
        sender_id = message.get("sender_id", "Unknown")
        created_at = message.get("created_at", "")
        message_id = message.get("_id", "")
        is_saved = self.current_user in message.get("saved_by", [])
        language = message.get("language") or "en"
        
        # Format timestamp
        if isinstance(created_at, str):
            timestamp = created_at.split("T")[0] if "T" in created_at else created_at
        else:
            timestamp = str(created_at)
        
        # Save button
        save_button = ft.IconButton(
            icon=ft.Icons.BOOKMARK if is_saved else ft.Icons.BOOKMARK_BORDER,
            tooltip="Save message" if not is_saved else "Remove from saved",
            on_click=lambda e, mid=message_id, saved=is_saved: self.page.run_task(
                self.toggle_save_message, mid, saved
            )
        )
        
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
                        save_button
                    ]),
                    ft.Divider(height=1),
                    ft.Text(msg_text, selectable=True, max_lines=10)
                ], spacing=SPACING_SMALL),
                padding=SPACING_MEDIUM
            )
        )
    
    async def toggle_save_message(self, message_id: str, is_saved: bool):
        """Toggle save status of a message"""
        try:
            if is_saved:
                await self.api_client.unsave_message(message_id)
            else:
                await self.api_client.save_message(message_id)
            await self.load_messages()
        except Exception as e:
            print(f"Error toggling save: {e}")
