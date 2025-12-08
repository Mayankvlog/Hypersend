"""
Permissions Management View - Similar to Telegram permissions system
Handles user-controlled access to location, camera, microphone, contacts, phone, storage
"""
import flet as ft
from theme import SPACING_MEDIUM, SPACING_LARGE


class PermissionsView(ft.Container):
    """Manages app permissions with allow/deny controls"""
    
    def __init__(self, page, api_client, on_back):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.on_back = on_back
        self.permissions = {}
        self.loading = False
        
        # Permission definitions
        self.permission_definitions = {
            'location': {
                'name': 'Location',
                'icon': 'LOCATION_ON',
                'description': 'Allow access to your location for sharing',
                'color': '#FF5252'
            },
            'camera': {
                'name': 'Camera',
                'icon': 'CAMERA_ALT',
                'description': 'Allow access to camera for video calls',
                'color': '#42A5F5'
            },
            'microphone': {
                'name': 'Microphone',
                'icon': 'MIC',
                'description': 'Allow access to microphone for voice calls',
                'color': '#AB47BC'
            },
            'contacts': {
                'name': 'Contacts',
                'icon': 'CONTACTS',
                'description': 'Allow access to your contacts',
                'color': '#29B6F6'
            },
            'phone': {
                'name': 'Phone State',
                'icon': 'PHONE',
                'description': 'Allow reading phone state',
                'color': '#66BB6A'
            },
            'storage': {
                'name': 'Storage',
                'icon': 'FOLDER',
                'description': 'Allow access to files and media',
                'color': '#FFA726'
            }
        }
        
        # Build permission cards
        self.permission_cards = []
        self.build_ui()
    
    def build_ui(self):
        """Build the permissions UI"""
        # Header
        header = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    on_click=lambda e: self.on_back()
                ),
                ft.Text("App Permissions", size=20, weight="bold", expand=True),
                ft.Container(width=48)  # Balance for back button
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
        )
        
        # Permission cards container
        self.cards_column = ft.Column(spacing=SPACING_MEDIUM)
        
        # Build permission card for each permission
        for perm_key, perm_data in self.permission_definitions.items():
            card = self.build_permission_card(perm_key, perm_data)
            self.permission_cards.append(card)
            self.cards_column.controls.append(card)
        
        # Main content
        content = ft.Column(
            [
                header,
                ft.Divider(),
                ft.Text(
                    "Control app access to your device features",
                    size=14,
                    color=ft.Colors.GREY_700,
                    weight="w400"
                ),
                ft.Container(height=SPACING_MEDIUM),
                self.cards_column,
                ft.Container(height=SPACING_LARGE),
                ft.ElevatedButton(
                    "Save Preferences",
                    on_click=lambda e: self.page.run_task(self.save_permissions),
                    width=300,
                    height=45
                ),
            ],
            spacing=SPACING_MEDIUM,
            scroll=ft.ScrollMode.AUTO
        )
        
        self.content = ft.Container(
            content=content,
            padding=SPACING_LARGE,
            expand=True
        )
    
    def build_permission_card(self, perm_key, perm_data):
        """Build individual permission card"""
        
        # Permission state storage
        if perm_key not in self.permissions:
            self.permissions[perm_key] = False
        
        # Toggle button and status
        status_indicator = ft.Icon(
            name=ft.Icons.CLOSE,
            color=ft.Colors.RED_400,
            size=20
        )
        
        def toggle_permission(e):
            """Toggle permission on/off"""
            self.permissions[perm_key] = not self.permissions[perm_key]
            status_indicator.name = ft.Icons.CHECK_CIRCLE if self.permissions[perm_key] else ft.Icons.CLOSE
            status_indicator.color = ft.Colors.GREEN_400 if self.permissions[perm_key] else ft.Colors.RED_400
            status_text.value = "Allowed" if self.permissions[perm_key] else "Denied"
            status_text.color = ft.Colors.GREEN_400 if self.permissions[perm_key] else ft.Colors.RED_400
            self.page.update()
        
        # Status text
        status_text = ft.Text(
            "Denied",
            size=12,
            color=ft.Colors.RED_400,
            weight="w500"
        )
        
        # Card content
        card = ft.Card(
            content=ft.Container(
                content=ft.Row(
                    [
                        # Icon
                        ft.Icon(
                            name=perm_data['icon'],
                            color=perm_data['color'],
                            size=32
                        ),
                        # Permission details
                        ft.Column(
                            [
                                ft.Text(perm_data['name'], size=16, weight="bold"),
                                ft.Text(
                                    perm_data['description'],
                                    size=12,
                                    color=ft.Colors.GREY_700,
                                    width=200,
                                    max_lines=2,
                                    overflow=ft.TextOverflow.ELLIPSIS
                                ),
                            ],
                            spacing=4,
                            expand=True
                        ),
                        # Status and toggle
                        ft.Column(
                            [
                                status_indicator,
                                status_text,
                            ],
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=4
                        ),
                        # Toggle switch
                        ft.IconButton(
                            icon=ft.Icons.TOGGLE_OFF,
                            icon_size=36,
                            icon_color=ft.Colors.GREY_400,
                            on_click=toggle_permission
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=SPACING_MEDIUM
                ),
                padding=SPACING_MEDIUM
            )
        )
        
        return card
    
    async def save_permissions(self, e):
        """Save permissions to backend"""
        try:
            self.loading = True
            self.page.update()
            
            # Prepare payload
            permissions_payload = {
                'location': self.permissions.get('location', False),
                'camera': self.permissions.get('camera', False),
                'microphone': self.permissions.get('microphone', False),
                'contacts': self.permissions.get('contacts', False),
                'phone': self.permissions.get('phone', False),
                'storage': self.permissions.get('storage', False),
            }
            
            # Send to backend
            await self.api_client.update_permissions(permissions_payload)
            
            # Show success message
            self.page.snack_bar = ft.SnackBar(
                ft.Text("Permissions saved successfully"),
                duration=2000
            )
            self.page.snack_bar.open = True
            self.page.update()
            
        except Exception as error:
            print(f"Error saving permissions: {error}")
            self.page.snack_bar = ft.SnackBar(
                ft.Text(f"Error: {str(error)}"),
                duration=2000
            )
            self.page.snack_bar.open = True
            self.page.update()
        finally:
            self.loading = False


class PermissionsSettingsCard(ft.Card):
    """Compact permissions card for settings/profile view"""
    
    def __init__(self, permissions_data, on_edit):
        super().__init__()
        self.permissions_data = permissions_data or {}
        self.on_edit = on_edit
        
        # Count allowed permissions
        allowed_count = sum(1 for v in self.permissions_data.values() if v)
        total_count = 6
        
        self.content = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Text("App Permissions", size=14, weight="bold", expand=True),
                            ft.IconButton(
                                icon=ft.Icons.EDIT,
                                icon_size=20,
                                on_click=lambda e: on_edit()
                            )
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                    ),
                    ft.Divider(height=1),
                    ft.Text(
                        f"{allowed_count} of {total_count} permissions allowed",
                        size=12,
                        color=ft.Colors.GREY_700
                    ),
                    ft.Container(height=8),
                    # Show status of each permission
                    ft.Column(
                        [
                            self.build_permission_status(name, allowed)
                            for name, allowed in self.permissions_data.items()
                        ],
                        spacing=6
                    )
                ],
                spacing=SPACING_MEDIUM
            ),
            padding=SPACING_MEDIUM
        )
    
    def build_permission_status(self, name, allowed):
        """Build permission status row"""
        permission_names = {
            'location': 'Location',
            'camera': 'Camera',
            'microphone': 'Microphone',
            'contacts': 'Contacts',
            'phone': 'Phone',
            'storage': 'Storage'
        }
        
        return ft.Row(
            [
                ft.Text(permission_names.get(name, name), size=12, expand=True),
                ft.Icon(
                    name=ft.Icons.CHECK_CIRCLE if allowed else ft.Icons.CLOSE,
                    color=ft.Colors.GREEN_400 if allowed else ft.Colors.RED_400,
                    size=16
                )
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
        )


