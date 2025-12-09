"""
Zaply - Telegram Style Messaging App
Built with Python Flet + Hypersend FastAPI Backend
"""

import flet as ft
import httpx
import asyncio
import os
import json
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

# Load environment
from dotenv import load_dotenv
load_dotenv()

API_URL = os.getenv("API_BASE_URL", "http://139.59.82.105:8000")
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# Import theme
from theme import ZaplyTheme, LIGHT_COLORS, DARK_COLORS, FONT_SIZES, SPACING, RADIUS

def debug_log(msg: str):
    if DEBUG:
        print(f"[ZAPLY] {msg}")

class ZaplyApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Zaply"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.window.width = 400
        self.page.window.height = 850
        self.page.padding = 0
        
        # Theme
        self.theme = ZaplyTheme(dark_mode=False)
        self.dark_mode = False
        self.colors = self.theme.colors
        
        # State
        self.token = None
        self.current_user = None
        self.chats = []
        self.messages = []
        self.current_chat = None
        
        # HTTP Client
        self.client = httpx.AsyncClient(base_url=API_URL, timeout=30.0)
        
        debug_log(f"App initialized. API URL: {API_URL}")
        
    async def initialize(self):
        """Initialize app"""
        debug_log("Initializing app...")
        # Load saved token if exists
        token_file = Path.home() / ".zaply_token"
        if token_file.exists():
            try:
                with open(token_file, 'r') as f:
                    data = json.load(f)
                    self.token = data.get("access_token")
                    if self.token:
                        debug_log("Token restored from file")
                        self.show_chat_list()
                        return
            except:
                pass
        
        # No token, show login
        self.show_login()
    
    def show_login(self):
        """Show login screen"""
        self.page.clean()
        
        # Title
        title = ft.Text(
            "Zaply",
            size=28,
            weight=ft.FontWeight.BOLD,
            color=self.colors["accent"]
        )
        
        # Email input
        email_field = ft.TextField(
            label="Email",
            border_radius=8,
            keyboard_type=ft.KeyboardType.EMAIL,
            autofocus=True,
            filled=True,
            bgcolor=self.colors["bg_secondary"],
            focused_border_color=self.colors["accent"],
            content_padding=16
        )
        
        # Password input
        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            border_radius=8,
            filled=True,
            bgcolor=self.colors["bg_secondary"],
            focused_border_color=self.colors["accent"],
            content_padding=16
        )
        
        # Error message
        error_text = ft.Text(
            "",
            color=self.colors["error"],
            visible=False,
            size=12
        )
        
        # Login button
        login_btn = ft.ElevatedButton(
            "Login",
            width=300,
            height=48,
            style=ft.ButtonStyle(
                bgcolor=self.colors["accent"],
                color=ft.Colors.WHITE,
                shape=ft.RoundedRectangleBorder(radius=8)
            )
        )
        
        async def handle_login(e):
            if not email_field.value or not password_field.value:
                error_text.value = "Email and password required"
                error_text.visible = True
                self.page.update()
                return
            
            try:
                login_btn.disabled = True
                login_btn.text = "Logging in..."
                self.page.update()
                
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
                    self.current_user = data.get("user", {})
                    
                    # Save token
                    token_file = Path.home() / ".zaply_token"
                    with open(token_file, 'w') as f:
                        json.dump({"access_token": self.token}, f)
                    
                    debug_log(f"Login successful. Token: {self.token[:20]}...")
                    self.show_chat_list()
                else:
                    error_text.value = "Login failed"
                    error_text.visible = True
                    login_btn.disabled = False
                    login_btn.text = "Login"
                    
            except Exception as ex:
                error_text.value = f"Error: {str(ex)[:50]}"
                error_text.visible = True
                login_btn.disabled = False
                login_btn.text = "Login"
            
            self.page.update()
        
        login_btn.on_click = handle_login
        
        # Register link
        register_link = ft.TextButton(
            "Don't have account? Register",
            on_click=self.show_register
        )
        
        # Main column
        main = ft.Column(
            controls=[
                title,
                ft.Container(height=30),
                email_field,
                ft.Container(height=10),
                password_field,
                ft.Container(height=10),
                error_text,
                ft.Container(height=20),
                login_btn,
                ft.Container(height=20),
                register_link
            ],
            spacing=0,
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True
        )
        
        # Container
        container = ft.Container(
            content=main,
            padding=30,
            alignment=ft.alignment.center,
            expand=True,
            bgcolor=self.colors["bg_primary"]
        )
        
        self.page.add(container)
    
    def show_register(self, e=None):
        """Show register screen"""
        self.page.clean()
        
        # Title
        title = ft.Text(
            "Create Account",
            size=28,
            weight=ft.FontWeight.BOLD,
            color=self.colors["accent"]
        )
        
        # Name input
        name_field = ft.TextField(
            label="Name",
            border_radius=8,
            keyboard_type=ft.KeyboardType.NAME,
            filled=True,
            bgcolor=self.colors["bg_secondary"],
            focused_border_color=self.colors["accent"],
            content_padding=16
        )
        
        # Email input
        email_field = ft.TextField(
            label="Email",
            border_radius=8,
            keyboard_type=ft.KeyboardType.EMAIL,
            filled=True,
            bgcolor=self.colors["bg_secondary"],
            focused_border_color=self.colors["accent"],
            content_padding=16
        )
        
        # Password input
        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            border_radius=8,
            filled=True,
            bgcolor=self.colors["bg_secondary"],
            focused_border_color=self.colors["accent"],
            content_padding=16
        )
        
        # Error message
        error_text = ft.Text(
            "",
            color=self.colors["error"],
            visible=False,
            size=12
        )
        
        # Register button
        register_btn = ft.ElevatedButton(
            "Register",
            width=300,
            height=48,
            style=ft.ButtonStyle(
                bgcolor=self.colors["accent"],
                color=ft.Colors.WHITE,
                shape=ft.RoundedRectangleBorder(radius=8)
            )
        )
        
        async def handle_register(e):
            if not all([name_field.value, email_field.value, password_field.value]):
                error_text.value = "All fields required"
                error_text.visible = True
                self.page.update()
                return
            
            try:
                register_btn.disabled = True
                register_btn.text = "Registering..."
                self.page.update()
                
                response = await self.client.post(
                    "/api/v1/auth/register",
                    json={
                        "name": name_field.value,
                        "email": email_field.value,
                        "password": password_field.value
                    }
                )
                
                if response.status_code == 201:
                    self.show_login()
                else:
                    error_text.value = "Registration failed"
                    error_text.visible = True
                    register_btn.disabled = False
                    register_btn.text = "Register"
                    
            except Exception as ex:
                error_text.value = f"Error: {str(ex)[:50]}"
                error_text.visible = True
                register_btn.disabled = False
                register_btn.text = "Register"
            
            self.page.update()
        
        register_btn.on_click = handle_register
        
        # Back link
        back_link = ft.TextButton(
            "Already have account? Login",
            on_click=lambda e: self.show_login()
        )
        
        # Main column
        main = ft.Column(
            controls=[
                title,
                ft.Container(height=30),
                name_field,
                ft.Container(height=10),
                email_field,
                ft.Container(height=10),
                password_field,
                ft.Container(height=10),
                error_text,
                ft.Container(height=20),
                register_btn,
                ft.Container(height=20),
                back_link
            ],
            spacing=0,
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True
        )
        
        # Container
        container = ft.Container(
            content=main,
            padding=30,
            alignment=ft.alignment.center,
            expand=True,
            bgcolor=self.colors["bg_primary"]
        )
        
        self.page.add(container)
    
    def show_chat_list(self):
        """Show chat list screen"""
        self.page.clean()
        
        # AppBar
        appbar = ft.AppBar(
            title=ft.Text("Zaply", weight=ft.FontWeight.BOLD, color=self.colors["text_primary"]),
            bgcolor=self.colors["bg_primary"],
            elevation=0.5,
            actions=[
                ft.IconButton(
                    ft.Icons.LOGOUT,
                    tooltip="Logout",
                    on_click=self.logout
                )
            ]
        )
        
        self.page.appbar = appbar
        
        # Chat list view
        chat_list_view = ft.ListView(
            expand=True,
            spacing=4,
            padding=8
        )
        
        async def load_chats():
            try:
                if not self.token:
                    return
                
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await self.client.get("/api/v1/chats/", headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    self.chats = data.get("chats", [])
                    
                    # Render chat items
                    chat_list_view.controls.clear()
                    for chat in self.chats:
                        chat_name = chat.get("name", "Chat")
                        last_message = chat.get("last_message", {}).get("text", "No messages")
                        
                        chat_item = ft.Container(
                            content=ft.Row([
                                ft.Container(
                                    content=ft.Text(
                                        chat_name[0].upper(),
                                        size=20,
                                        weight=ft.FontWeight.BOLD,
                                        color=ft.Colors.WHITE
                                    ),
                                    width=50,
                                    height=50,
                                    border_radius=25,
                                    bgcolor=self.colors["accent"],
                                    alignment=ft.alignment.center
                                ),
                                ft.Column([
                                    ft.Text(chat_name, weight=ft.FontWeight.BOLD),
                                    ft.Text(last_message, size=12, color=self.colors["text_secondary"])
                                ], spacing=2, expand=True)
                            ], spacing=12),
                            padding=10,
                            border_radius=10,
                            on_click=lambda e, c=chat: self.open_chat(c)
                        )
                        chat_list_view.controls.append(chat_item)
                    
                    self.page.update()
                    
            except Exception as ex:
                debug_log(f"Error loading chats: {ex}")
        
        # Load chats
        self.page.add(chat_list_view)
        self.page.run_task(load_chats)
    
    def open_chat(self, chat: Dict[str, Any]):
        """Open chat detail screen"""
        self.current_chat = chat
        self.page.clean()
        
        # AppBar with chat name
        appbar = ft.AppBar(
            leading=ft.IconButton(
                ft.Icons.ARROW_BACK,
                on_click=lambda e: self.show_chat_list()
            ),
            title=ft.Text(chat.get("name", "Chat"), weight=ft.FontWeight.BOLD),
            bgcolor=self.colors["bg_primary"],
            elevation=0.5
        )
        
        self.page.appbar = appbar
        
        # Messages view
        messages_view = ft.ListView(
            expand=True,
            spacing=8,
            padding=8,
            reverse=True,
            auto_scroll=True
        )
        
        # Input area
        message_input = ft.TextField(
            hint_text="Message...",
            multiline=True,
            min_lines=1,
            max_lines=5,
            filled=True,
            bgcolor=self.colors["bg_secondary"],
            border_radius=20,
            content_padding=10,
            expand=True
        )
        
        send_btn = ft.IconButton(
            ft.Icons.SEND,
            icon_color=self.colors["accent"],
            on_click=lambda e: self.page.run_task(send_message)
        )
        
        async def send_message():
            if not message_input.value.strip():
                return
            
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await self.client.post(
                    f"/api/v1/chats/{self.current_chat['_id']}/messages",
                    json={"text": message_input.value},
                    headers=headers
                )
                
                if response.status_code == 201:
                    message_input.value = ""
                    await load_messages()
                    
            except Exception as ex:
                debug_log(f"Error sending message: {ex}")
            
            self.page.update()
        
        async def load_messages():
            try:
                if not self.token:
                    return
                
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await self.client.get(
                    f"/api/v1/chats/{self.current_chat['_id']}/messages",
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.messages = data.get("messages", [])
                    
                    # Render messages
                    messages_view.controls.clear()
                    for msg in reversed(self.messages):
                        is_mine = msg.get("sender_id") == self.current_user.get("_id")
                        
                        msg_bubble = ft.Container(
                            content=ft.Text(msg.get("text", "")),
                            padding=12,
                            border_radius=12,
                            bgcolor=self.colors["message_sent"] if is_mine else self.colors["message_received"],
                            margin=ft.margin.only(
                                left=50 if is_mine else 0,
                                right=0 if is_mine else 50
                            )
                        )
                        messages_view.controls.append(msg_bubble)
                    
                    self.page.update()
                    
            except Exception as ex:
                debug_log(f"Error loading messages: {ex}")
        
        # Input row
        input_row = ft.Row([
            message_input,
            send_btn
        ], spacing=8)
        
        # Main content
        main = ft.Column([
            messages_view,
            input_row
        ], spacing=8, expand=True)
        
        container = ft.Container(
            content=main,
            padding=8,
            expand=True,
            bgcolor=self.colors["bg_primary"]
        )
        
        self.page.add(container)
        self.page.run_task(load_messages)
    
    def logout(self, e=None):
        """Logout user"""
        self.token = None
        token_file = Path.home() / ".zaply_token"
        if token_file.exists():
            token_file.unlink()
        self.show_login()

async def main(page: ft.Page):
    app = ZaplyApp(page)
    await app.initialize()

if __name__ == "__main__":
    ft.app(target=main)
