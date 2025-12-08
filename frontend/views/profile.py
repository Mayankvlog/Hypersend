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
                                color=ft.colors.WHITE
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
        
        # Stats section
        stats_section = ft.Container(
            content=ft.Row(
                [
                    # Messages sent
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text(
                                    "0",
                                    size=20,
                                    weight=ft.FontWeight.BOLD,
                                    color=self.primary_color,
                                    text_align=ft.TextAlign.CENTER
                                ),
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
                                ft.Text(
                                    "0",
                                    size=20,
                                    weight=ft.FontWeight.BOLD,
                                    color=self.primary_color,
                                    text_align=ft.TextAlign.CENTER
                                ),
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
                                ft.Text(
                                    "0 MB",
                                    size=20,
                                    weight=ft.FontWeight.BOLD,
                                    color=self.primary_color,
                                    text_align=ft.TextAlign.CENTER
                                ),
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
                        icon=ft.icons.EDIT,
                        style=ft.ButtonStyle(
                            color=ft.colors.WHITE,
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
                        icon=ft.icons.SHARE,
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
        
        # Set up the view
        self.controls = [
            ft.Container(
                content=main_content,
                padding=ft.padding.all(20),
                bgcolor=self.bg_color,
                expand=True
            )
        ]
        
        # Set app bar
        self.page.appbar = ft.AppBar(
            title=ft.Text("Profile", weight=ft.FontWeight.BOLD, color=ft.colors.BLACK),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.icons.ARROW_BACK,
                icon_color=ft.colors.BLACK,
                on_click=lambda e: self.go_back()
            ),
            actions=[
                ft.IconButton(
                    icon=ft.icons.MORE_VERT,
                    icon_color=ft.colors.BLACK,
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
            # Here you would normally save to backend
            self.current_user["name"] = name_field.value
            self.current_user["username"] = username_field.value
            self.current_user["bio"] = bio_field.value
            
            dialog.open = False
            self.build_ui()  # Rebuild UI with updated data
            self.page.update()
        
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
                        bgcolor=ft.colors.GREY_100,
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
    
    def go_back(self):
        """Go back to previous screen"""
        if self.on_back:
            self.on_back()
        else:
            self.page.go("/")