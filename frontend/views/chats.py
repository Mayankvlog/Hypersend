import flet as ft
from frontend.theme import PRIMARY_COLOR, SPACING_SMALL, SPACING_MEDIUM


class ChatsView(ft.Container):
    def __init__(self, page, api_client, current_user, on_logout):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_logout = on_logout
        
        # Chat list
        self.chat_list = ft.ListView(
            spacing=SPACING_SMALL,
            padding=SPACING_MEDIUM,
            expand=True
        )
        
        # Layout
        self.content = ft.Column(
            [
                # Header
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Text("HyperSend", size=20, weight=ft.FontWeight.BOLD),
                            ft.IconButton(
                                icon=ft.icons.LOGOUT,
                                on_click=lambda e: self.page.run_task(self.handle_logout, e)
                            )
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                    ),
                    padding=SPACING_MEDIUM,
                    bgcolor=PRIMARY_COLOR
                ),
                # Chats
                self.chat_list,
                # New chat button
                ft.FloatingActionButton(
                    icon=ft.icons.ADD,
                    on_click=self.new_chat
                )
            ],
            spacing=0
        )
        
        self.expand = True
        # Load chats after page is ready
        self.page.run_task(self.load_chats)
    
    async def load_chats(self):
        """Load user's chats"""
        try:
            data = await self.api_client.list_chats()
            self.chat_list.controls.clear()
            
            # Add Saved Messages card at the top
            saved_card = ft.Card(
                content=ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.icons.BOOKMARK, color=PRIMARY_COLOR),
                        ft.Column([
                            ft.Text("Saved Messages", weight=ft.FontWeight.BOLD),
                            ft.Text("Your personal notes and bookmarks", size=12, opacity=0.7)
                        ], expand=True)
                    ], spacing=SPACING_MEDIUM),
                    padding=SPACING_MEDIUM
                ),
                on_click=lambda e: self.page.run_task(self.open_saved_messages)
            )
            self.chat_list.controls.append(saved_card)
            
            for chat in data.get("chats", []):
                chat_card = self.create_chat_card(chat)
                self.chat_list.controls.append(chat_card)
            
            if not data.get("chats"):
                self.chat_list.controls.append(
                    ft.Text("No chats yet. Start a new conversation!", 
                           text_align=ft.TextAlign.CENTER,
                           opacity=0.6)
                )
            
            self.page.update()
        except Exception as e:
            print(f"Error loading chats: {e}")
    
    def create_chat_card(self, chat):
        """Create a chat list item"""
        chat_name = chat.get("name", "Private Chat")
        last_msg = chat.get("last_message", {}).get("text", "No messages")
        
        return ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text(chat_name, weight=ft.FontWeight.BOLD),
                    ft.Text(last_msg, size=12, opacity=0.7, max_lines=1)
                ]),
                padding=SPACING_MEDIUM
            ),
            on_click=lambda e, c=chat: self.open_chat(c)
        )
    
    def open_chat(self, chat):
        """Open chat detail view"""
        from frontend.views.file_upload import FileUploadView
        
        # Show file upload dialog
        upload_view = FileUploadView(
            page=self.page,
            api_client=self.api_client,
            chat_id=chat['_id'],
            on_complete=lambda file_id: self.on_upload_complete(chat['_id'], file_id)
        )
        
        # Show in dialog
        dialog = ft.AlertDialog(
            title=ft.Text(f"Upload to {chat.get('name', 'Private Chat')}"),
            content=upload_view,
            actions=[
                ft.TextButton("Close", on_click=lambda e: self.close_dialog())
            ],
            modal=True
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def on_upload_complete(self, chat_id: str, file_id: str):
        """Handle upload completion"""
        print(f"File {file_id} uploaded to chat {chat_id}")
        self.close_dialog()
        # Reload chats to show new message
        self.page.run_task(self.load_chats)
    
    def close_dialog(self):
        """Close current dialog"""
        if self.page.dialog:
            self.page.dialog.open = False
            self.page.update()

    async def open_saved_messages(self, e=None):
        """Open or create the Saved Messages chat and show upload UI to add content to it"""
        try:
            data = await self.api_client.get_saved_chat()
            chat = data.get("chat")
            if not chat:
                return
            self.open_chat(chat)
        except Exception as ex:
            print(f"Failed to open Saved Messages: {ex}")
    
    def new_chat(self, e):
        """Start new chat"""
        # TODO: Implement user search and chat creation
        print("New chat")
    
    async def handle_logout(self, e):
        """Logout"""
        await self.api_client.logout()
        self.on_logout()
