import flet as ft
from flet import icons
import httpx
import asyncio
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
from frontend.update_manager import check_app_updates

# API Configuration
API_URL = os.getenv("API_BASE_URL", os.getenv("API_URL", "http://localhost:8000"))

class HyperSendApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "HyperSend"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 0
        self.page.window_width = 400
        self.page.window_height = 850
        
        # State
        self.token: Optional[str] = None
        self.current_user: Optional[dict] = None
        self.current_chat: Optional[dict] = None
        self.chats: list = []
        self.messages: list = []
        
        # HTTP client
        self.client = httpx.AsyncClient(base_url=API_URL, timeout=60.0)
        
        # Theme colors
        self.primary_color = "#0088cc"
        self.bg_dark = "#FDFBFB"
        self.bg_light = "#F6F5F5F6"
        self.text_primary = "#ffffff"
        self.text_secondary = "#8e8e93"
        
        # Setup custom theme
        self.page.theme = ft.Theme(
            color_scheme_seed=self.primary_color,
            use_material3=True
        )
        
        # TODO: Re-enable update check after fixing asyncio compatibility
        # Check for updates on startup
        # asyncio.create_task(check_app_updates(self.page))
        
        # Show login screen
        self.show_login()
    
    def show_login(self):
        """Show login/register screen"""
        email_field = ft.TextField(
            label="Email",
            autofocus=True,
            keyboard_type=ft.KeyboardType.EMAIL,
            prefix_icon=icons.EMAIL,
            filled=True
        )
        
        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            prefix_icon=icons.LOCK,
            filled=True
        )
        
        username_field = ft.TextField(
            label="Username",
            prefix_icon=icons.PERSON,
            filled=True,
            visible=False
        )
        
        error_text = ft.Text(
            "",
            color=ft.colors.RED,
            size=12,
            visible=False
        )
        
        async def login_clicked(e):
            if not email_field.value or not password_field.value:
                error_text.value = "Please fill all fields"
                error_text.visible = True
                self.page.update()
                return
            
            try:
                response = await self.client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": email_field.value,
                        "password": password_field.value
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.token = data["access_token"]
                    # Fetch user info after login
                    self.client.headers["Authorization"] = f"Bearer {self.token}"
                    user_response = await self.client.get("/api/v1/users/me")
                    if user_response.status_code == 200:
                        self.current_user = user_response.json()
                    self.show_chat_list()
                else:
                    error_text.value = response.json().get("detail", "Login failed")
                    error_text.visible = True
            except Exception as ex:
                error_text.value = f"Error: {str(ex)}"
                error_text.visible = True
            
            self.page.update()
        
        async def register_clicked(e):
            if not email_field.value or not password_field.value or not username_field.value:
                error_text.value = "Please fill all fields"
                error_text.visible = True
                self.page.update()
                return
            
            try:
                response = await self.client.post(
                    "/api/v1/auth/register",
                    json={
                        "email": email_field.value,
                        "name": username_field.value,
                        "password": password_field.value
                    }
                )
                
                if response.status_code == 201:
                    data = response.json()
                    # Registration successful, now login
                    login_response = await self.client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": email_field.value,
                            "password": password_field.value
                        }
                    )
                    if login_response.status_code == 200:
                        login_data = login_response.json()
                        self.token = login_data["access_token"]
                        self.current_user = data
                        self.client.headers["Authorization"] = f"Bearer {self.token}"
                        self.show_chat_list()
                    else:
                        error_text.value = "Registration successful but login failed"
                        error_text.visible = True
                else:
                    error_text.value = response.json().get("detail", "Registration failed")
                    error_text.visible = True
            except Exception as ex:
                error_text.value = f"Error: {str(ex)}"
                error_text.visible = True
            
            self.page.update()
        
        def toggle_mode(e):
            if username_field.visible:
                # Switch to login
                username_field.visible = False
                login_btn.text = "Login"
                register_btn.text = "Need an account? Register"
                login_btn.on_click = login_clicked
            else:
                # Switch to register
                username_field.visible = True
                login_btn.text = "Register"
                register_btn.text = "Have an account? Login"
                login_btn.on_click = register_clicked
            
            error_text.visible = False
            self.page.update()
        
        login_btn = ft.ElevatedButton(
            "Login",
            on_click=login_clicked,
            style=ft.ButtonStyle(
                color=ft.colors.WHITE,
                bgcolor=self.primary_color,
                padding=15
            ),
            width=300
        )
        
        register_btn = ft.TextButton(
            "Need an account? Register",
            on_click=toggle_mode
        )
        
        self.page.controls = [
            ft.Container(
                content=ft.Column(
                    [
                        email_field,
                        username_field,
                        password_field,
                        error_text,
                        login_btn,
                        register_btn
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=15
                ),
                padding=ft.padding.only(left=30, right=30, top=150, bottom=30),
                alignment=ft.alignment.top_center,
                expand=True
            )
        ]
        self.page.update()
    
    def show_chat_list(self):
        """Show list of chats"""
        async def load_chats():
            try:
                response = await self.client.get("/api/v1/chats/")
                if response.status_code == 200:
                    payload = response.json()
                    self.chats = payload.get("chats", [])
                    update_chat_list()
            except Exception as ex:
                print(f"Error loading chats: {ex}")
        
        def update_chat_list():
            chat_items = []
            for chat in self.chats:
                # Determine chat name and avatar based on backend schema
                chat_name = chat.get("name") or ("Group Chat" if chat.get("type") == "group" else "Private Chat")
                avatar = (
                    ft.Icon(icons.GROUP, size=40)
                    if chat.get("type") == "group"
                    else ft.CircleAvatar(
                        content=ft.Text(
                            (chat_name or "?")[0].upper(),
                            size=20,
                            weight=ft.FontWeight.BOLD
                        ),
                        bgcolor=self.primary_color
                    )
                )
                
                last_message_text = (chat.get("last_message") or {}).get("text", "No messages yet")
                
                chat_item = ft.Container(
                    content=ft.Row(
                        [
                            avatar,
                            ft.Column(
                                [
                                    ft.Text(
                                        chat_name,
                                        size=16,
                                        weight=ft.FontWeight.W_500,
                                        color=self.text_primary
                                    ),
                                    ft.Text(
                                        last_message_text[:50] + "..." if len(last_message_text) > 50 else last_message_text,
                                        size=13,
                                        color=self.text_secondary
                                    )
                                ],
                                spacing=5,
                                expand=True
                            )
                        ],
                        spacing=15
                    ),
                    padding=15,
                    on_click=lambda e, c=chat: self.show_chat(c),
                    ink=True
                )
                chat_items.append(chat_item)
                chat_items.append(ft.Divider(height=1, color=self.bg_light))
            
            chat_list_view.controls = chat_items if chat_items else [
                ft.Container(
                    content=ft.Text(
                        "No chats yet. Start a new conversation!",
                        color=self.text_secondary,
                        text_align=ft.TextAlign.CENTER
                    ),
                    padding=30,
                    alignment=ft.alignment.center
                )
            ]
            self.page.update()
        
        chat_list_view = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            expand=True
        )
        
        # AppBar
        appbar = ft.AppBar(
            title=ft.Text("HyperSend", weight=ft.FontWeight.BOLD),
            center_title=False,
            bgcolor=self.bg_light,
            actions=[
                ft.IconButton(
                    icon=icons.SEARCH,
                    on_click=lambda e: print("Search")
                ),
                ft.IconButton(
                    icon=icons.ADD,
                    on_click=lambda e: self.show_new_chat_dialog()
                )
            ]
        )
        
        self.page.appbar = appbar
        self.page.controls = [
            ft.Container(
                content=chat_list_view,
                bgcolor=self.bg_dark,
                expand=True
            )
        ]
        
        # Load chats
        asyncio.create_task(load_chats())
        self.page.update()
    
    def show_chat(self, chat: dict):
        """Show chat messages"""
        self.current_chat = chat
        
        async def load_messages():
            try:
                response = await self.client.get(f"/api/v1/chats/{chat['_id']}/messages")
                if response.status_code == 200:
                    payload = response.json()
                    self.messages = payload.get("messages", [])
                    update_messages()
            except Exception as ex:
                print(f"Error loading messages: {ex}")
        
        def update_messages():
            message_items = []
            for msg in self.messages:
                is_mine = msg.get("sender_id") == self.current_user.get("id", self.current_user.get("_id"))
                
                # Message bubble
                if msg.get("type") == "text":
                    content = ft.Text(
                        msg.get("text", ""),
                        color=self.text_primary,
                        selectable=True
                    )
                else:
                    # File message (simplified)
                    filename = msg.get("file_id", "File")
                    content = ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Icon(icons.INSERT_DRIVE_FILE, size=40),
                                    ft.Column(
                                        [
                                            ft.Text(
                                                str(filename),
                                                weight=ft.FontWeight.W_500
                                            )
                                        ],
                                        spacing=2
                                    )
                                ],
                                spacing=10
                            ),
                            ft.ElevatedButton(
                                "Download",
                                icon=icons.DOWNLOAD,
                                on_click=lambda e, fid=msg.get("file_id"): self.download_file(fid)
                            )
                        ],
                        spacing=10
                    )
                
                message_bubble = ft.Container(
                    content=ft.Column(
                        [
                            content,
                            ft.Text(
                                datetime.fromisoformat(msg.get("created_at", msg.get("timestamp", "")).replace("Z", "+00:00")).strftime("%H:%M"),
                                size=10,
                                color=self.text_secondary
                            )
                        ],
                        spacing=5
                    ),
                    bgcolor=self.primary_color if is_mine else self.bg_light,
                    padding=10,
                    border_radius=10,
                    margin=ft.margin.only(
                        left=50 if is_mine else 0,
                        right=0 if is_mine else 50,
                        top=5,
                        bottom=5
                    )
                )
                
                message_items.append(message_bubble)
            
            messages_view.controls = message_items
            self.page.update()
        
        messages_view = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            expand=True,
            spacing=5
        )
        
        message_input = ft.TextField(
            hint_text="Type a message...",
            border=ft.InputBorder.NONE,
            filled=True,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5
        )
        
        async def send_message(e):
            if not message_input.value:
                return
            
            try:
                response = await self.client.post(
                    f"/api/v1/chats/{chat['_id']}/messages",
                    json={
                        "text": message_input.value
                    }
                )
                
                if response.status_code == 200:
                    message_input.value = ""
                    await load_messages()
            except Exception as ex:
                print(f"Error sending message: {ex}")
            
            self.page.update()
        
        async def pick_file(e):
            file_picker.pick_files(allow_multiple=False)
        
        async def upload_file(e: ft.FilePickerResultEvent):
            if not e.files:
                return
            
            file = e.files[0]
            await self.upload_file_chunked(file.path, chat["_id"])
        
        file_picker = ft.FilePicker(on_result=upload_file)
        self.page.overlay.append(file_picker)
        
        # AppBar for chat
        chat_name = chat.get("other_user", {}).get("username", "Chat") if not chat.get("is_group") else chat.get("group_name", "Group")
        
        self.page.appbar = ft.AppBar(
            leading=ft.IconButton(
                icon=icons.ARROW_BACK,
                on_click=lambda e: self.show_chat_list()
            ),
            title=ft.Text(chat_name, weight=ft.FontWeight.BOLD),
            center_title=False,
            bgcolor=self.bg_light
        )
        
        self.page.controls = [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Container(
                            content=messages_view,
                            expand=True,
                            padding=10
                        ),
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.IconButton(
                                        icon=icons.ATTACH_FILE,
                                        on_click=pick_file
                                    ),
                                    message_input,
                                    ft.IconButton(
                                        icon=icons.SEND,
                                        on_click=send_message,
                                        bgcolor=self.primary_color,
                                        icon_color=ft.colors.WHITE
                                    )
                                ],
                                spacing=10
                            ),
                            padding=10,
                            bgcolor=self.bg_light
                        )
                    ],
                    spacing=0
                ),
                bgcolor=self.bg_dark,
                expand=True
            )
        ]
        
        # Load messages
        asyncio.create_task(load_messages())
        self.page.update()
    
    async def upload_file_chunked(self, file_path: str, chat_id: str):
        """Upload file in chunks"""
        try:
            path = Path(file_path)
            file_size = path.stat().st_size
            
            # Start upload
            response = await self.client.post(
                "/api/v1/files/init",
                json={
                    "filename": path.name,
                    "size": file_size,
                    "mime": "application/octet-stream",
                    "chat_id": chat_id
                }
            )
            
            if response.status_code != 200:
                print("Failed to start upload")
                return
            
            upload_info = response.json()
            upload_id = upload_info["upload_id"]
            chunk_size = upload_info["chunk_size"]
            total_chunks = upload_info["total_chunks"]
            
            # Upload chunks
            with open(file_path, 'rb') as f:
                for chunk_index in range(total_chunks):
                    chunk_data = f.read(chunk_size)
                    if not chunk_data:
                        break
                    
                    response = await self.client.put(
                        f"/api/v1/files/{upload_id}/chunk",
                        params={"chunk_index": chunk_index},
                        content=chunk_data
                    )
                    
                    if response.status_code != 200:
                        print(f"Failed to upload chunk {chunk_index}")
                        return
            
            # Complete upload
            response = await self.client.post(
                f"/api/v1/files/{upload_id}/complete"
            )
            
            if response.status_code != 200:
                print("Failed to complete upload")
                return
                
            complete_info = response.json()
            file_id = complete_info["file_id"]
            
            # Send message with file
            await self.client.post(
                f"/api/v1/chats/{chat_id}/messages",
                json={
                    "file_id": file_id
                }
            )
            
            print("File uploaded successfully")
            
        except Exception as ex:
            print(f"Upload error: {ex}")
    
    async def download_file(self, file_id: str):
        """Download file"""
        try:
            response = await self.client.get(f"/api/v1/files/{file_id}/download")
            if response.status_code == 200:
                # Get filename from headers
                filename = response.headers.get("Content-Disposition", "download").split("filename=")[-1].strip('"')
                
                # Save file
                save_path = Path.home() / "Downloads" / filename
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                
                print(f"File downloaded to {save_path}")
        except Exception as ex:
            print(f"Download error: {ex}")
    
    def show_new_chat_dialog(self):
        """Show dialog to create new chat"""
        # Simplified - in production, show user search
        pass


async def main(page: ft.Page):
    app = HyperSendApp(page)


if __name__ == "__main__":
    ft.app(target=main)
