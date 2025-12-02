"""
Settings View - User account settings and preferences
"""
import flet as ft
from frontend.theme import PRIMARY_COLOR, SPACING_MEDIUM, SPACING_LARGE, BORDER_RADIUS
from frontend.views.permissions import PermissionsView, PermissionsSettingsCard


class SettingsView(ft.Container):
    """User settings and preferences view"""
    
    def __init__(self, page, api_client, current_user, on_logout, on_back):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_logout = on_logout
        self.on_back = on_back
        self.permissions_data = {}
        
        # Header
        self.header = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    on_click=lambda e: on_back()
                ),
                ft.Text("Settings", size=20, weight="bold", expand=True),
                ft.Container(width=48)
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
        )
        
        # Settings content
        self.settings_column = ft.Column(
            spacing=SPACING_MEDIUM,
            scroll=ft.ScrollMode.AUTO
        )
        
        # Build UI
        self.build_ui()
        
        # Load permissions
        self.page.run_task(self.load_permissions)
        
        # Main layout
        self.content = ft.Column(
            [
                self.header,
                ft.Divider(),
                self.settings_column,
                ft.Container(height=SPACING_LARGE),
                ft.ElevatedButton(
                    "Logout",
                    on_click=lambda e: self.page.run_task(self.handle_logout),
                    width=300,
                    height=45,
                    bgcolor=ft.Colors.RED_400,
                    color=ft.Colors.WHITE
                ),
            ],
            spacing=SPACING_MEDIUM,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        self.padding = SPACING_LARGE
        self.expand = True
    
    def build_ui(self):
        """Build settings UI"""
        # User Info Section
        self.settings_column.controls.append(
            ft.Text("Account", size=14, weight="bold", color=PRIMARY_COLOR)
        )
        
        # Current user email
        self.settings_column.controls.append(
            ft.Card(
                content=ft.Container(
                    content=ft.Column(
                        [
                            ft.Text("Email", size=12, color=ft.Colors.GREY_700),
                            ft.Text(
                                self.current_user.get("email", "N/A"),
                                size=14,
                                weight="bold"
                            )
                        ],
                        spacing=4
                    ),
                    padding=SPACING_MEDIUM
                )
            )
        )
        
        # Permissions Section
        self.settings_column.controls.append(
            ft.Container(height=SPACING_MEDIUM)
        )
        
        self.settings_column.controls.append(
            ft.Text("Permissions", size=14, weight="bold", color=PRIMARY_COLOR)
        )
        
        # Permissions card (will be populated after loading)
        self.permissions_card_container = ft.Container()
        self.settings_column.controls.append(self.permissions_card_container)
        
        # App Info Section
        self.settings_column.controls.append(
            ft.Container(height=SPACING_MEDIUM)
        )
        
        self.settings_column.controls.append(
            ft.Text("About", size=14, weight="bold", color=PRIMARY_COLOR)
        )
        
        self.settings_column.controls.append(
            ft.Card(
                content=ft.Container(
                    content=ft.Column(
                        [
                            ft.Row([
                                ft.Text("App Version", size=12, color=ft.Colors.GREY_700, expand=True),
                                ft.Text("1.0.0", size=12, weight="bold")
                            ]),
                            ft.Divider(),
                            ft.Row([
                                ft.Text("App Name", size=12, color=ft.Colors.GREY_700, expand=True),
                                ft.Text("Zaply", size=12, weight="bold")
                            ])
                        ],
                        spacing=8
                    ),
                    padding=SPACING_MEDIUM
                )
            )
        )
    
    async def load_permissions(self):
        """Load user's current permissions"""
        try:
            self.permissions_data = await self.api_client.get_permissions()
            
            # Update permissions card
            def open_permissions_view():
                """Open full permissions view"""
                perm_view = PermissionsView(self.page, self.api_client, self.on_back)
                self.page.clean()
                self.page.add(perm_view)
                self.page.update()
            
            permissions_card = PermissionsSettingsCard(
                self.permissions_data,
                on_edit=open_permissions_view
            )
            
            self.permissions_card_container.content = permissions_card
            self.page.update()
        except Exception as e:
            print(f"Error loading permissions: {e}")
    
    async def handle_logout(self, e):
        """Handle logout"""
        try:
            await self.api_client.logout()
            self.on_logout()
        except Exception as error:
            print(f"Logout error: {error}")
            self.on_logout()  # Logout anyway
