import flet as ft
import os
from typing import Optional
from datetime import datetime

class ProfileView(ft.View):
    def __init__(self, page: ft.Page, current_user: dict, on_back=None, api_client=None):
        super().__init__("/profile")
        self.page = page
        self.current_user = current_user
        self.on_back = on_back
        self.api_client = api_client
        
        # Theme colors
        self.primary_color = "#1F8EF1"
        self.bg_color = "#FDFBFB"
        self.card_color = "#FFFFFF"
        self.text_color = "#000000"
        self.text_secondary = "#8e8e93"
        
        # Stats state
        self.messages_count = 0
        self.files_count = 0
        self.storage_used = 0
        
        self.build_ui()
    
    def build_ui(self):
        """Build the profile interface"""
        # Profile header with avatar
        profile_header = ft.Container(
            content=ft.Column(
                [
                    # Avatar
                    ft.Container(
                        content=ft.CircleAvatar(
                            content=ft.Text(
                                self.get_initial(),
                                size=40,
                                weight=ft.FontWeight.BOLD,
                                color=ft.Colors.WHITE
                            ),
                            bgcolor=self.primary_color,
                            radius=60
                        ),
                        margin=ft.margin.only(bottom=20)
                    ),
                    
                    # Name and username
                    ft.Text(
                        self.current_user.get("name", "User"),
                        size=24,
                        weight=ft.FontWeight.BOLD,
                        color=self.text_color,
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Text(
                        f"@{self.current_user.get('username', 'user')}",
                        size=16,
                        color=self.text_secondary,
                        text_align=ft.TextAlign.CENTER
                    ),
                    
                    # Email
                    ft.Text(
                        self.current_user.get("email", ""),
                        size=14,
                        color=self.text_secondary,
                        text_align=ft.TextAlign.CENTER
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8
            ),
            padding=ft.padding.all(30),
            bgcolor=self.card_color,
            border_radius=ft.border_radius.all(15),
            margin=ft.margin.only(bottom=20)
        )
        
        # Stats section with live counters
        self.messages_text = ft.Text(
            str(self.messages_count),
            size=20,
            weight=ft.FontWeight.BOLD,
            color=self.primary_color,
            text_align=ft.TextAlign.CENTER
        )
        
        self.files_text = ft.Text(
            str(self.files_count),
            size=20,
            weight=ft.FontWeight.BOLD,
            color=self.primary_color,
            text_align=ft.TextAlign.CENTER
        )
        
        self.storage_text = ft.Text(
            f"{self.storage_used} MB",
            size=20,
            weight=ft.FontWeight.BOLD,
            color=self.primary_color,
            text_align=ft.TextAlign.CENTER
        )
        
        stats_section = ft.Container(
            content=ft.Row(
                [
                    # Messages sent
                    ft.Container(
                        content=ft.Column(
                            [
                                self.messages_text,
                                ft.Text(
                                    "Messages",
                                    size=12,
                                    color=self.text_secondary,
                                    text_align=ft.TextAlign.CENTER
                                )
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=4
                        ),
                        expand=True
                    ),
                    
                    # Files shared
                    ft.Container(
                        content=ft.Column(
                            [
                                self.files_text,
                                ft.Text(
                                    "Files",
                                    size=12,
                                    color=self.text_secondary,
                                    text_align=ft.TextAlign.CENTER
                                )
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=4
                        ),
                        expand=True
                    ),
                    
                    # Storage used
                    ft.Container(
                        content=ft.Column(
                            [
                                self.storage_text,
                                ft.Text(
                                    "Storage",
                                    size=12,
                                    color=self.text_secondary,
                                    text_align=ft.TextAlign.CENTER
                                )
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=4
                        ),
                        expand=True
                    )
                ],
                alignment=ft.MainAxisAlignment.SPACE_AROUND
            ),
            padding=ft.padding.symmetric(vertical=20, horizontal=15),
            bgcolor=self.card_color,
            border_radius=ft.border_radius.all(15),
            margin=ft.margin.only(bottom=20)
        )
        
        # Account info section
        account_info = ft.Container(
            content=ft.Column(
                [
                    self.info_item("Account ID", self.current_user.get("id", "N/A")),
                    self.info_item("Joined", self.get_join_date()),
                    self.info_item("Status", "🟢 Active"),
                    self.info_item("Account Type", "Premium"),
                ],
                spacing=0
            ),
            padding=ft.padding.all(20),
            bgcolor=self.card_color,
            border_radius=ft.border_radius.all(15),
            margin=ft.margin.only(bottom=20)
        )
        
        # Action buttons
        actions_section = ft.Container(
            content=ft.Column(
                [
                    # Edit Profile button
                    ft.ElevatedButton(
                        "Edit Profile",
                        icon=ft.Icons.EDIT,
                        style=ft.ButtonStyle(
                            color=ft.Colors.WHITE,
                            bgcolor=self.primary_color,
                            padding=ft.padding.symmetric(vertical=15, horizontal=20)
                        ),
                        on_click=self.edit_profile,
                        width=400
                    ),
                    
                    ft.Container(height=10),
                    
                    # Share Profile button
                    ft.OutlinedButton(
                        "Share Profile",
                        icon=ft.Icons.SHARE,
                        style=ft.ButtonStyle(
                            color=self.primary_color,
                            side=ft.BorderSide(1, self.primary_color),
                            padding=ft.padding.symmetric(vertical=15, horizontal=20)
                        ),
                        on_click=self.share_profile,
                        width=400
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER
            ),
            margin=ft.margin.only(bottom=20)
        )
        
        # Main content
        main_content = ft.Column(
            [
                profile_header,
                stats_section,
                account_info,
                actions_section
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=0,
            expand=True
        )
        
        # Back button at the top of content for visibility
        back_button_row = ft.Container(
            content=ft.Row([
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    icon_color=ft.Colors.BLACK,
                    icon_size=28,
                    tooltip="Back",
                    on_click=lambda e: self.go_back()
                ),
                ft.Text("Profile", size=20, weight=ft.FontWeight.BOLD, color=self.text_color),
                ft.Container(expand=True),
                ft.IconButton(
                    icon=ft.Icons.MORE_VERT,
                    icon_color=ft.Colors.BLACK,
                    on_click=self.show_more_options
                )
            ], alignment=ft.MainAxisAlignment.START),
            padding=ft.padding.symmetric(horizontal=10, vertical=5),
            bgcolor=self.bg_color
        )
        
        # Set up the view with header included
        self.controls = [
            ft.Container(
                content=ft.Column([
                    back_button_row,
                    main_content
                ], spacing=0),
                padding=ft.padding.only(top=10, left=20, right=20, bottom=20),
                bgcolor=self.bg_color,
                expand=True
            )
        ]
        
        # Also set view's appbar for proper Flet behavior
        self.appbar = ft.AppBar(
            title=ft.Text("Profile", weight=ft.FontWeight.BOLD, color=ft.Colors.BLACK),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=ft.Colors.BLACK,
                on_click=lambda e: self.go_back()
            ),
            actions=[
                ft.IconButton(
                    icon=ft.Icons.MORE_VERT,
                    icon_color=ft.Colors.BLACK,
                    on_click=self.show_more_options
                )
            ]
        )
    
    def info_item(self, label: str, value: str):
        """Create an info item row"""
        return ft.Container(
            content=ft.Row(
                [
                    ft.Text(
                        label,
                        size=14,
                        color=self.text_secondary,
                        expand=True
                    ),
                    ft.Text(
                        value,
                        size=14,
                        color=self.text_color,
                        weight=ft.FontWeight.W_500
                    )
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN
            ),
            padding=ft.padding.symmetric(vertical=12)
        )
    
    def get_initial(self):
        """Get user initial for avatar"""
        name = self.current_user.get("name", "")
        username = self.current_user.get("username", "")
        email = self.current_user.get("email", "")
        
        if name:
            return name[0].upper()
        elif username:
            return username[0].upper()
        elif email:
            return email[0].upper()
        else:
            return "U"
    
    def get_join_date(self):
        """Get formatted join date"""
        created_at = self.current_user.get("created_at")
        if created_at:
            try:
                # Parse ISO date and format
                date_obj = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                return date_obj.strftime("%B %Y")
            except:
                return "Unknown"
        return "Unknown"
    
    def edit_profile(self, e):
        """Handle edit profile action"""
        # Show edit profile dialog
        name_field = ft.TextField(
            label="Name",
            value=self.current_user.get("name", ""),
            filled=True
        )
        
        username_field = ft.TextField(
            label="Username",
            value=self.current_user.get("username", ""),
            filled=True
        )
        
        bio_field = ft.TextField(
            label="Bio",
            value=self.current_user.get("bio", ""),
            multiline=True,
            max_lines=3,
            filled=True
        )
        
        def save_changes(e):
            # Create async save function
            async def do_save():
                try:
                    # Show loading indicator
                    save_btn = dialog.actions[1]  # Save button is second action
                    save_btn.content = ft.ProgressRing(width=20, height=20, stroke_width=2)
                    self.page.update()
                    
                    # Save to backend
                    result = await self.api_client.update_profile(
                        name=name_field.value,
                        username=username_field.value,
                        bio=bio_field.value
                    )
                    
                    # Update local user data
                    self.current_user["name"] = name_field.value
                    self.current_user["username"] = username_field.value
                    self.current_user["bio"] = bio_field.value
                    
                    # Close dialog and rebuild UI
                    dialog.open = False
                    self.build_ui()  # Rebuild UI with updated data
                    self.page.update()
                    
                    # Show success message
                    snack = ft.SnackBar(
                        content=ft.Text("Profile updated successfully!"),
                        bgcolor=ft.Colors.GREEN
                    )
                    self.page.overlay.append(snack)
                    snack.open = True
                    self.page.update()
                    
                except Exception as save_e:
                    print(f"[PROFILE] Error saving profile: {save_e}")
                    # Restore button and show error
                    save_btn = dialog.actions[1]  # Save button is second action
                    save_btn.content = ft.Text("Save")
                    self.page.update()
                    
                    # Show error message
                    error_snack = ft.SnackBar(
                        content=ft.Text(f"Failed to save profile: {str(save_e)}"),
                        bgcolor=ft.Colors.RED
                    )
                    self.page.overlay.append(error_snack)
                    error_snack.open = True
                    self.page.update()
            
            # Run async save
            self.page.run_task(do_save)
        
        dialog = ft.AlertDialog(
            title=ft.Text("Edit Profile"),
            content=ft.Column(
                [name_field, username_field, bio_field],
                spacing=15,
                tight=True
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: setattr(dialog, 'open', False)),
                ft.ElevatedButton("Save", on_click=save_changes)
            ],
            actions_alignment=ft.MainAxisAlignment.END
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def share_profile(self, e):
        """Handle share profile action"""
        profile_text = f"👤 {self.current_user.get('name', 'User')} (@{self.current_user.get('username', 'user')})"
        
        # Show share dialog
        dialog = ft.AlertDialog(
            title=ft.Text("Share Profile"),
            content=ft.Column(
                [
                    ft.Text("Share this profile:"),
                    ft.Container(
                        content=ft.Text(
                            profile_text,
                            size=14,
                            selectable=True
                        ),
                        padding=ft.padding.all(10),
                        bgcolor=ft.Colors.GREY_100,
                        border_radius=ft.border_radius.all(8)
                    )
                ],
                spacing=10
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: setattr(dialog, 'open', False))
            ]
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def show_more_options(self, e):
        """Show more options menu"""
        menu = ft.PopupMenuButton(
            items=[
                ft.PopupMenuItem(
                    text="📊 View Statistics",
                    on_click=lambda e: print("Statistics coming soon")
                ),
                ft.PopupMenuItem(
                    text="🔗 Copy Profile Link",
                    on_click=lambda e: print("Copy link coming soon")
                ),
                ft.PopupMenuItem(
                    text="📱 Export Data",
                    on_click=lambda e: print("Export data coming soon")
                ),
                ft.PopupMenuItem(
                    text="⚙️ Account Settings",
                    on_click=lambda e: self.page.go("/settings")
                ),
            ]
        )
        self.page.open(menu)
    
    async def load_stats(self):
        """Load user statistics from API"""
        try:
            if not self.api_client:
                print("[PROFILE] API client nahi hai")
                return
            
            print("[PROFILE] User statistics load kar rahe hain...")
            
            # Pehle current user data lo
            try:
                user_data = await self.api_client.get_current_user()
                quota_used = user_data.get("quota_used", 0)
                # Bytes ko MB mein convert karo
                storage_mb = quota_used / (1024 * 1024)
                self.storage_used = int(storage_mb)
                print(f"[PROFILE] Storage use kiya gaya: {self.storage_used} MB")
            except Exception as e:
                print(f"[PROFILE] User data lene mein error: {e}")
                self.storage_used = 0
            
            # Chats lo aur messages count karo
            try:
                chats_data = await self.api_client.list_chats()
                chats = chats_data.get("chats", [])
                
                # Total messages aur files count karo
                total_messages = 0
                total_files = 0
                
                for chat in chats:
                    chat_id = chat.get("_id") or chat.get("id")
                    if chat_id:
                        try:
                            # Is chat ki messages lo
                            messages_data = await self.api_client.get_messages(chat_id, limit=1000)
                            messages = messages_data.get("messages", [])
                            total_messages += len(messages)
                            
                            # File messages count karo
                            for msg in messages:
                                if msg.get("file_id"):
                                    total_files += 1
                        except Exception as msg_e:
                            print(f"[PROFILE] Chat {chat_id} ki messages lene mein error: {msg_e}")
                            continue
                
                self.messages_count = total_messages
                self.files_count = total_files
                print(f"[PROFILE] Total Messages: {self.messages_count}, Files: {self.files_count}")
                
            except Exception as e:
                print(f"[PROFILE] Chats lene mein error: {e}")
                self.messages_count = 0
                self.files_count = 0
            
            # UI update karo
            if hasattr(self, 'messages_text'):
                self.messages_text.value = str(self.messages_count)
            if hasattr(self, 'files_text'):
                self.files_text.value = str(self.files_count)
            if hasattr(self, 'storage_text'):
                self.storage_text.value = f"{self.storage_used} MB"
            
            self.page.update()
            print("[PROFILE] Stats load ho gaye aur UI update ho gaya")
            
        except Exception as e:
            print(f"[PROFILE] Stats load karne mein serious error: {e}")
            # Error par default values set karo
            self.messages_count = 0
            self.files_count = 0
            self.storage_used = 0
            
            if hasattr(self, 'messages_text'):
                self.messages_text.value = "0"
            if hasattr(self, 'files_text'):
                self.files_text.value = "0"
            if hasattr(self, 'storage_text'):
                self.storage_text.value = "0 MB"
            
            self.page.update()
    
    def on_view_mount(self):
        """Called when view is mounted"""
        self.page.run_task(self.load_stats)
    
    def go_back(self):
        """Go back to previous screen"""
        if self.on_back:
            self.on_back()
        else:
            self.page.go("/")

