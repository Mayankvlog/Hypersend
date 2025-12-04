import flet as ft
import asyncio
import os
import sys

from frontend.permissions_manager import REQUIRED_PERMISSIONS, check_permission, request_android_permissions

def SettingsView(
    page: ft.Page,
    api_client,
    current_user: dict,
    on_logout: callable,
    on_back: callable
):
    """
    Flet view for application settings, including permission management.
    """
    
    # Placeholder for the actual content of SettingsView
    # This will be replaced with actual UI logic
    
    # --- Permission UI ---
    def get_permission_status_icon(perm_name: str):
        if sys.platform != "android":
            return ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN_500)
        
        if check_permission(perm_name):
            return ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN_500)
        else:
            return ft.Icon(ft.icons.CANCEL, color=ft.colors.RED_500)

    async def _request_permissions_on_click(e):
        e.control.disabled = True
        e.control.text = "Requesting..."
        page.update()
        # Request permissions
        await asyncio.sleep(0.1) # Give UI time to update
        request_android_permissions() # This will trigger system dialog
        await asyncio.sleep(1) # Give user time to react to dialog
        e.control.disabled = False
        e.control.text = "Request Permissions Again"
        # Update UI to reflect new status
        for perm_row in permissions_list.controls:
            perm_name = perm_row.data
            perm_row.controls[1] = get_permission_status_icon(perm_name)
        page.update()

    permissions_list = ft.Column(
        controls=[
            ft.Row(
                controls=[
                    ft.Text(perm.split(".")[-1], expand=True),
                    get_permission_status_icon(perm),
                ],
                data=perm # Store permission name for later update
            ) for perm in REQUIRED_PERMISSIONS
        ],
        spacing=10
    )

    permission_section = ft.Column(
        controls=[
            ft.Text("Permissions", size=18, weight=ft.FontWeight.BOLD),
            ft.Text(
                "Manage app permissions. Permissions not granted here can be "
                "managed in your device's system settings.",
                size=12,
                color=ft.colors.BLACK54
            ),
            ft.Container(height=10),
            permissions_list,
            ft.Container(height=10),
            ft.ElevatedButton(
                text="Request Permissions Again",
                on_click=_request_permissions_on_click,
                visible=sys.platform == "android"
            ),
            ft.TextButton(
                text="Open App Settings (Android)",
                on_click=lambda e: print("Open Android App Settings (Not Implemented)"), # TODO: Implement jnius call to open app settings
                visible=sys.platform == "android"
            )
        ]
    )

    # --- Other Settings (Placeholders) ---
    account_section = ft.Column(
        controls=[
            ft.Text("Account", size=18, weight=ft.FontWeight.BOLD),
            ft.Text(f"Logged in as: {current_user.get('email', 'N/A')}"),
            ft.ElevatedButton("Logout", on_click=lambda e: on_logout()),
        ]
    )

    about_section = ft.Column(
        controls=[
            ft.Text("About", size=18, weight=ft.FontWeight.BOLD),
            ft.Text("Zaply App Version 1.0.0"),
            ft.Text("Made with ❤️ by Mayan"),
        ]
    )


    # Main Layout
    view_controls = ft.Column(
        controls=[
            permission_section,
            ft.Divider(),
            account_section,
            ft.Divider(),
            about_section,
        ],
        scroll=ft.ScrollMode.AUTO,
        expand=True,
        spacing=20,
        padding=20
    )

    return ft.View(
        "/settings",
        [
            ft.AppBar(
                leading=ft.IconButton(
                    icon=ft.icons.ARROW_BACK,
                    on_click=lambda e: on_back()
                ),
                title=ft.Text("Settings"),
                center_title=False,
                bgcolor=ft.colors.SURFACE_VARIANT
            ),
            view_controls
        ]
    )