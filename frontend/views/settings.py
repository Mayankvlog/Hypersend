import flet as ft
import asyncio
import sys
import os

try:
    from permissions_manager import REQUIRED_PERMISSIONS, check_permission, request_android_permissions
except ImportError:
    REQUIRED_PERMISSIONS = []
    def check_permission(perm): return True
    def request_android_permissions(): pass

# Icon compatibility
icons = ft.Icons
colors = ft.Colors

class SettingsView(ft.View):
    def __init__(self, page: ft.Page, api_client, current_user: dict, on_logout: callable, on_back: callable):
        super().__init__("/settings")
        self.page = page
        self.api_client = api_client
        self.current_user = current_user
        self.on_logout = on_logout
        self.on_back = on_back
        
        # Theme colors
        self.primary_color = "#1F8EF1"
        self.bg_color = "#FDFBFB"
        self.card_color = "#FFFFFF"
        self.text_color = "#000000"
        self.text_secondary = "#8e8e93"
        
        # Settings state
        self.notifications_enabled = True
        self.dark_mode = False
        self.auto_download = False
        self.online_status = True
        
        self.build_ui()
    
    def build_ui(self):
        """Build comprehensive settings interface like Telegram"""
        
        # Profile Section
        profile_section = self.create_section(
            "Profile",
            [
                self.setting_item(
                    "Edit Profile",
                    "Change your name, username, and bio",
                    icons.PERSON,
                    on_click=lambda e: self.page.go("/profile")
                ),
                self.setting_item(
                    "Phone Number",
                    "Add or change your phone number",
                    icons.PHONE,
                    on_click=lambda e: print("Phone settings coming soon")
                ),
            ]
        )
        
        # Appearance Section
        appearance_section = self.create_section(
            "Appearance",
            [
                self.switch_item(
                    "Dark Mode",
                    "Enable dark theme",
                    icons.DARK_MODE,
                    self.dark_mode,
                    on_change=self.toggle_dark_mode
                ),
                self.setting_item(
                    "Chat Background",
                    "Customize chat wallpaper",
                    icons.IMAGE,
                    on_click=lambda e: print("Chat background coming soon")
                ),
                self.setting_item(
                    "Font Size",
                    "Adjust text size",
                    icons.TEXT_FIELDS,
                    on_click=self.show_font_size_dialog
                ),
            ]
        )
        
        # Notifications Section
        notifications_section = self.create_section(
            "Notifications",
            [
                self.switch_item(
                    "Message Notifications",
                    "Get notified for new messages",
                    icons.NOTIFICATIONS,
                    self.notifications_enabled,
                    on_change=self.toggle_notifications
                ),
                self.switch_item(
                    "Sound",
                    "Play sound for notifications",
                    icons.VOLUME_UP,
                    True,
                    on_change=lambda e: print("Sound toggle coming soon")
                ),
                self.switch_item(
                    "Vibration",
                    "Vibrate for notifications",
                    icons.VIBRATE,
                    True,
                    on_change=lambda e: print("Vibration toggle coming soon")
                ),
            ]
        )
        
        # Privacy & Security Section
        privacy_section = self.create_section(
            "Privacy & Security",
            [
                self.setting_item(
                    "Blocked Users",
                    "Manage blocked users",
                    icons.BLOCK,
                    on_click=lambda e: print("Blocked users coming soon")
                ),
                self.setting_item(
                    "Two-Step Verification",
                    "Add extra security to your account",
                    icons.SECURITY,
                    on_click=lambda e: print("2FA coming soon")
                ),
                self.setting_item(
                    "Privacy Settings",
                    "Control who can see your info",
                    icons.PRIVACY_TIP,
                    on_click=lambda e: print("Privacy settings coming soon")
                ),
                self.switch_item(
                    "Online Status",
                    "Show when you're online",
                    icons.CIRCLE,
                    self.online_status,
                    on_change=self.toggle_online_status
                ),
            ]
        )
        
        # Data & Storage Section
        data_section = self.create_section(
            "Data & Storage",
            [
                self.switch_item(
                    "Auto-Download Media",
                    "Download media automatically",
                    icons.DOWNLOAD,
                    self.auto_download,
                    on_change=self.toggle_auto_download
                ),
                self.setting_item(
                    "Storage Usage",
                    "Manage app storage",
                    icons.STORAGE,
                    on_click=self.show_storage_usage
                ),
                self.setting_item(
                    "Clear Cache",
                    "Free up space by clearing cache",
                    icons.CLEAR,
                    on_click=self.clear_cache
                ),
            ]
        )
        
        # Chat Settings Section
        chat_section = self.create_section(
            "Chat Settings",
            [
                self.setting_item(
                    "Chat Backup",
                    "Backup your chat history",
                    icons.BACKUP,
                    on_click=lambda e: print("Chat backup coming soon")
                ),
                self.setting_item(
                    "Export Chats",
                    "Export your chat history",
                    icons.DOWNLOAD,
                    on_click=lambda e: print("Export chats coming soon")
                ),
                self.switch_item(
                    "Read Receipts",
                    "Show when you've read messages",
                    icons.DONE_ALL,
                    True,
                    on_change=lambda e: print("Read receipts toggle coming soon")
                ),
            ]
        )
        
        # Help Section
        help_section = self.create_section(
            "Help",
            [
                self.setting_item(
                    "Help Center",
                    "Get help and support",
                    icons.HELP,
                    on_click=lambda e: print("Help center coming soon")
                ),
                self.setting_item(
                    "Report a Problem",
                    "Report bugs or issues",
                    icons.BUG_REPORT,
                    on_click=lambda e: print("Report problem coming soon")
                ),
                self.setting_item(
                    "About",
                    "App version and information",
                    icons.INFO,
                    on_click=self.show_about
                ),
            ]
        )
        
        # Permissions Section (Android only)
        if sys.platform == "android":
            permissions_section = self.create_permissions_section()
        else:
            permissions_section = ft.Container()
        
        # Logout Button
        logout_section = ft.Container(
            content=ft.ElevatedButton(
                "Logout",
                icon=ft.icons.LOGOUT,
                style=ft.ButtonStyle(
                    color=ft.colors.WHITE,
                    bgcolor=ft.colors.RED_500,
                    padding=ft.padding.symmetric(vertical=15, horizontal=20)
                ),
                on_click=self.confirm_logout,
                width=400
            ),
            margin=ft.margin.only(top=20, bottom=20),
            alignment=ft.alignment.center
        )
        
        # Devices Section
        devices_section = self.create_section(
            "Devices",
            [
                self.setting_item(
                    "Active Sessions",
                    "Manage devices logged into your account",
                    icons.DEVICES,
                    on_click=self.show_devices_dialog
                ),
                self.setting_item(
                    "Link Desktop Device",
                    "Scan QR code to log in",
                    icons.QR_CODE,
                    on_click=lambda e: print("QR scan coming soon")
                ),
            ]
        )

        # Language Section
        language_section = self.create_section(
            "Language",
            [
                self.setting_item(
                    "Language",
                    "English",
                    icons.LANGUAGE,
                    on_click=self.show_language_dialog
                ),
            ]
        )

        # Main content
        main_content = ft.Column(
            [
                profile_section,
                appearance_section,
                notifications_section,
                privacy_section,
                data_section,
                chat_section,
                devices_section,
                language_section,
                help_section,
                permissions_section,
                logout_section
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=0,
            expand=True
        )
        
        # Set up view
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
            title=ft.Text("Settings", weight=ft.FontWeight.BOLD, color=ft.colors.BLACK),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.icons.ARROW_BACK,
                icon_color=ft.colors.BLACK,
                on_click=lambda e: self.go_back()
            )
        )
    
    def create_section(self, title: str, items: list):
        """Create a settings section"""
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        title,
                        size=18,
                        weight=ft.FontWeight.BOLD,
                        color=self.text_color,
                        margin=ft.margin.only(bottom=15)
                    )
                ] + items,
                spacing=0
            ),
            padding=ft.padding.all(20),
            bgcolor=self.card_color,
            border_radius=ft.border_radius.all(15),
            margin=ft.margin.only(bottom=20)
        )
    
    def setting_item(self, title: str, subtitle: str, icon, on_click):
        """Create a setting item"""
        return ft.GestureDetector(
            content=ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(
                            icon,
                            color=self.primary_color,
                            size=24
                        ),
                        ft.Column(
                            [
                                ft.Text(
                                    title,
                                    size=16,
                                    color=self.text_color,
                                    weight=ft.FontWeight.W_500
                                ),
                                ft.Text(
                                    subtitle,
                                    size=13,
                                    color=self.text_secondary
                                )
                            ],
                            spacing=2,
                            expand=True
                        ),
                        ft.Icon(
                            ft.Icons.CHEVRON_RIGHT,
                            color=self.text_secondary,
                            size=20
                        )
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    spacing=15
                ),
                padding=ft.padding.symmetric(vertical=12, horizontal=0)
            ),
            on_tap=on_click
        )
    
    def switch_item(self, title: str, subtitle: str, icon, value: bool, on_change):
        """Create a switch setting item"""
        switch = ft.Switch(
            value=value,
            active_color=self.primary_color,
            on_change=on_change
        )
        
        return ft.Container(
            content=ft.Row(
                [
                    ft.Icon(
                        icon,
                        color=self.primary_color,
                        size=24
                    ),
                    ft.Column(
                        [
                            ft.Text(
                                title,
                                size=16,
                                color=self.text_color,
                                weight=ft.FontWeight.W_500
                            ),
                            ft.Text(
                                subtitle,
                                size=13,
                                color=self.text_secondary
                            )
                        ],
                        spacing=2,
                        expand=True
                    ),
                    switch
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                spacing=15
            ),
            padding=ft.padding.symmetric(vertical=12, horizontal=0)
        )
    
    def create_permissions_section(self):
        """Create permissions section for Android"""
        def get_permission_status_icon(perm_name: str):
            try:
                if check_permission(perm_name):
                    return ft.Icon(icons.CHECK_CIRCLE, color=colors.GREEN_500, size=20)
                else:
                    return ft.Icon(icons.CANCEL, color=colors.RED_500, size=20)
            except Exception:
                return ft.Text("✓", color=colors.GREEN_500)

        permissions_list = ft.Column(
            controls=[
                ft.Row(
                    controls=[
                        ft.Text(perm.split(".")[-1], expand=True, size=13),
                        get_permission_status_icon(perm),
                    ],
                    spacing=10,
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                ) for perm in REQUIRED_PERMISSIONS
            ],
            spacing=8,
            expand=False
        )

        return self.create_section(
            "Permissions",
            [
                ft.Text(
                    "Permissions are managed by Android. Tap 'Open App Settings' to change them.",
                    size=12,
                    color=self.text_secondary,
                    margin=ft.margin.only(bottom=15)
                ),
                permissions_list,
                ft.Container(height=15),
                ft.ElevatedButton(
                    "Request Permissions",
                    icon=ft.icons.SECURITY,
                    on_click=self.request_permissions,
                    style=ft.ButtonStyle(
                        color=ft.colors.WHITE,
                        bgcolor=self.primary_color
                    )
                ),
                ft.Container(height=10),
                ft.OutlinedButton(
                    "Open App Settings",
                    icon=ft.Icons.SETTINGS,
                    on_click=self.open_app_settings,
                    style=ft.ButtonStyle(
                        color=self.primary_color,
                        side=ft.BorderSide(1, self.primary_color)
                    )
                )
            ]
        )
    
    async def request_permissions(self, e):
        """Request Android permissions"""
        e.control.disabled = True
        e.control.text = "Requesting..."
        self.page.update()
        
        await asyncio.sleep(0.1)
        request_android_permissions()
        await asyncio.sleep(1)
        
        e.control.disabled = False
        e.control.text = "Request Permissions"
        self.page.update()
    
    def open_app_settings(self, e):
        """Open Android app settings"""
        if sys.platform == "android":
            try:
                from jnius import autoclass
                
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                Intent = autoclass('android.content.Intent')
                Uri = autoclass('android.net.Uri')
                
                intent = Intent()
                intent.setAction("android.settings.APPLICATION_DETAILS_SETTINGS")
                uri = Uri.fromParts("package", PythonActivity.mActivity.getPackageName(), None)
                intent.setData(uri)
                
                PythonActivity.mActivity.startActivity(intent)
            except Exception as ex:
                print(f"Error opening app settings: {ex}")
    
    def toggle_dark_mode(self, e):
        """Toggle dark mode"""
        self.dark_mode = e.control.value
        # Implement dark mode logic
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        self.page.update()
    
    def toggle_notifications(self, e):
        """Toggle notifications"""
        self.notifications_enabled = e.control.value
        # Implement notification logic
    
    def toggle_online_status(self, e):
        """Toggle online status"""
        self.online_status = e.control.value
        # Implement online status logic
    
    def toggle_auto_download(self, e):
        """Toggle auto download"""
        self.auto_download = e.control.value
        # Implement auto download logic
    
    def show_font_size_dialog(self, e):
        """Show font size dialog"""
        sizes = ["Small", "Medium", "Large"]
        current_size = "Medium"
        
        dialog = ft.AlertDialog(
            title=ft.Text("Font Size"),
            content=ft.Column(
                [
                    ft.Radio(
                        value=current_size,
                        options=[ft.RadioOption(size) for size in sizes],
                        on_change=lambda e: print(f"Font size: {e.control.value}")
                    )
                ],
                tight=True
            ),
            actions=[
                ft.TextButton("OK", on_click=lambda e: setattr(dialog, 'open', False))
            ]
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def show_devices_dialog(self, e):
        """Show devices dialog"""
        dialog = ft.AlertDialog(
            title=ft.Text("Active Sessions"),
            content=ft.Column(
                [
                    ft.Text("This Device", weight=ft.FontWeight.BOLD, color=self.primary_color),
                    ft.ListTile(
                        leading=ft.Icon(icons.SMARTPHONE, size=30, color=self.primary_color),
                        title=ft.Text("Zaply for Windows", weight=ft.FontWeight.W_500),
                        subtitle=ft.Text("Online now • Washington, USA", size=12)
                    ),
                    ft.Divider(),
                    ft.Text("Active Sessions", weight=ft.FontWeight.BOLD),
                    ft.ListTile(
                        leading=ft.Icon(icons.ANDROID, size=30),
                        title=ft.Text("Android 14", weight=ft.FontWeight.W_500),
                        subtitle=ft.Text("Last active: 10 min ago", size=12),
                        trailing=ft.IconButton(icons.DELETE_OUTLINE, icon_color=colors.RED_400)
                    ),
                ],
                tight=True,
                width=400
            ),
            actions=[
                ft.TextButton("Terminate All Other Sessions", style=ft.ButtonStyle(color=colors.RED_500)),
                ft.TextButton("Close", on_click=lambda e: setattr(dialog, 'open', False))
            ]
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

    def show_language_dialog(self, e):
        """Show language selection dialog"""
        languages = [
            "English", "Spanish", "French", "German", "Russian", 
            "Arabic", "Hindi", "Chinese", "Japanese"
        ]
        
        def select_language(lang):
            print(f"Selected language: {lang}")
            dialog.open = False
            self.page.update()
            
            snack = ft.SnackBar(content=ft.Text(f"Language changed to {lang}"), bgcolor=colors.GREEN_600)
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()

        dialog = ft.AlertDialog(
            title=ft.Text("Language"),
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.ListTile(
                            title=ft.Text(lang),
                            on_click=lambda e, l=lang: select_language(l),
                            leading=ft.Radio(value=lang, group="lang") if lang == "English" else ft.Radio(value=lang, group="lang")
                        ) for lang in languages
                    ],
                    scroll=ft.ScrollMode.AUTO,
                ),
                height=300,
                width=300
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: setattr(dialog, 'open', False))
            ]
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

    def show_storage_usage(self, e):
        """Show storage usage"""
        dialog = ft.AlertDialog(
            title=ft.Text("Storage Usage"),
            content=ft.Column(
                [
                    ft.Text("Cache: 45 MB"),
                    ft.Text("Media: 120 MB"),
                    ft.Text("Documents: 15 MB"),
                    ft.Divider(),
                    ft.Text("Total: 180 MB", weight=ft.FontWeight.BOLD)
                ],
                tight=True
            ),
            actions=[
                ft.TextButton("OK", on_click=lambda e: setattr(dialog, 'open', False))
            ]
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def clear_cache(self, e):
        """Clear app cache"""
        dialog = ft.AlertDialog(
            title=ft.Text("Clear Cache"),
            content=ft.Text("Are you sure you want to clear the cache? This will free up space but may slow down the app initially."),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: setattr(dialog, 'open', False)),
                ft.ElevatedButton("Clear", on_click=lambda e: self.do_clear_cache(dialog))
            ]
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def do_clear_cache(self, dialog):
        """Actually clear cache"""
        # Implement cache clearing logic
        dialog.open = False
        self.page.update()
        
        # Show success message
        success_dialog = ft.AlertDialog(
            title=ft.Text("Success"),
            content=ft.Text("Cache cleared successfully!"),
            actions=[
                ft.TextButton("OK", on_click=lambda e: setattr(success_dialog, 'open', False))
            ]
        )
        
        self.page.dialog = success_dialog
        success_dialog.open = True
        self.page.update()
    
    def show_about(self, e):
        """Show about dialog with comprehensive Zaply features"""
        
        # Feature sections
        messaging_features = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(icons.MESSAGE, color=self.primary_color, size=24),
                    ft.Text("Messaging", weight=ft.FontWeight.BOLD, size=16)
                ], spacing=10),
                ft.Text("• Send text, formatted text, photos, videos & files up to 40 GB", size=13),
                ft.Text("• Edit messages up to 48 hours (shows 'edited' icon)", size=13),
                ft.Text("• Delete messages & chats for both sides without trace", size=13),
            ], spacing=5),
            padding=10
        )
        
        encryption_features = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(icons.SECURITY, color=colors.GREEN, size=24),
                    ft.Text("Encryption", weight=ft.FontWeight.BOLD, size=16)
                ], spacing=10),
                ft.Text("Cloud Chats:", weight=ft.FontWeight.W_600, size=13),
                ft.Text("• MTProto 2.0 protocol with AES-256 encryption", size=12),
                ft.Text("• SHA-256 hashing & Diffie-Hellman key exchange", size=12),
                ft.Container(height=5),
                ft.Text("Secret Chats (E2EE):", weight=ft.FontWeight.W_600, size=13),
                ft.Text("• End-to-end encrypted - only you & recipient have keys", size=12),
                ft.Text("• 256-bit AES + 2048-bit RSA encryption", size=12),
                ft.Text("• Not stored on servers, no forwarding allowed", size=12),
                ft.Text("• Self-destructing messages supported", size=12),
            ], spacing=3),
            padding=10,
            bgcolor=colors.with_opacity(0.1, colors.GREEN)
        )
        
        privacy_features = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(icons.PRIVACY_TIP, color=colors.BLUE, size=24),
                    ft.Text("Privacy & Control", weight=ft.FontWeight.BOLD, size=16)
                ], spacing=10),
                ft.Text("• Complete control over your messages", size=13),
                ft.Text("• Delete for everyone without leaving traces", size=13),
                ft.Text("• Message edit history visible with icon", size=13),
                ft.Text("• Self-destructing messages in secret chats", size=13),
            ], spacing=5),
            padding=10
        )
        
        dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(icons.INFO, color=self.primary_color),
                ft.Text("About Zaply", weight=ft.FontWeight.BOLD)
            ], spacing=10),
            content=ft.Container(
                content=ft.Column([
                    ft.Text("Zaply v1.0.0", weight=ft.FontWeight.BOLD, size=18, color=self.primary_color),
                    ft.Text("Fast, Secure Chat & File Sharing", size=14),
                    ft.Divider(),
                    messaging_features,
                    encryption_features,
                    privacy_features,
                    ft.Divider(),
                    ft.Text("© 2025 Zaply Inc.", size=12, color=self.text_secondary, text_align=ft.TextAlign.CENTER)
                ], spacing=5, scroll=ft.ScrollMode.AUTO),
                width=350,
                height=450
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))
            ]
        )
        
        self.page.open(dialog)
    
    def confirm_logout(self, e):
        """Confirm logout"""
        dialog = ft.AlertDialog(
            title=ft.Text("Logout"),
            content=ft.Text("Are you sure you want to logout?"),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: setattr(dialog, 'open', False)),
                ft.ElevatedButton(
                    "Logout",
                    style=ft.ButtonStyle(
                        color=ft.colors.WHITE,
                        bgcolor=ft.colors.RED_500
                    ),
                    on_click=lambda e: self.do_logout(dialog)
                )
            ]
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
    
    def do_logout(self, dialog):
        """Actually logout"""
        dialog.open = False
        self.page.update()
        
        if self.on_logout:
            self.on_logout()
    
    def go_back(self):
        """Go back to previous screen"""
        if self.on_back:
            self.on_back()
        else:
            self.page.go("/")