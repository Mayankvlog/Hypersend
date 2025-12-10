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
                    on_click=self.show_chat_background_picker
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
                    on_change=self.toggle_sound
                ),
                self.switch_item(
                    "Vibration",
                    "Vibrate for notifications",
                    icons.VIBRATION,
                    True,
                    on_change=self.toggle_vibration
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
                    on_click=self.show_blocked_users
                ),
                self.setting_item(
                    "Two-Step Verification",
                    "Add extra security to your account",
                    icons.SECURITY,
                    on_click=self.show_2fa_settings
                ),
                self.setting_item(
                    "Privacy Settings",
                    "Control who can see your info",
                    icons.PRIVACY_TIP,
                    on_click=self.show_privacy_settings
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
                    on_click=self.backup_chats
                ),
                self.setting_item(
                    "Export Chats",
                    "Export your chat history",
                    icons.DOWNLOAD,
                    on_click=self.export_chats
                ),
                self.switch_item(
                    "Read Receipts",
                    "Show when you've read messages",
                    icons.DONE_ALL,
                    True,
                    on_change=self.toggle_read_receipts
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
                    on_click=self.show_help_center
                ),
                self.setting_item(
                    "Report a Problem",
                    "Report bugs or issues",
                    icons.BUG_REPORT,
                    on_click=self.report_problem
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
                icon=ft.Icons.LOGOUT,
                style=ft.ButtonStyle(
                    color=ft.Colors.WHITE,
                    bgcolor=ft.Colors.RED_500,
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
                    on_click=self.scan_qr_code
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
        
        # Back button header for visibility
        back_header = ft.Container(
            content=ft.Row([
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    icon_color=ft.Colors.BLACK,
                    icon_size=28,
                    tooltip="Back",
                    on_click=lambda e: self.go_back()
                ),
                ft.Text("Settings", size=20, weight=ft.FontWeight.BOLD, color=self.text_color),
            ], alignment=ft.MainAxisAlignment.START),
            padding=ft.padding.symmetric(horizontal=10, vertical=5),
            bgcolor=self.bg_color
        )
        
        # Set up view with header included
        self.controls = [
            ft.Container(
                content=ft.Column([
                    back_header,
                    main_content
                ], spacing=0),
                padding=ft.padding.only(top=10, left=20, right=20, bottom=20),
                bgcolor=self.bg_color,
                expand=True
            )
        ]
        
        # Also set view's appbar for proper Flet behavior
        self.appbar = ft.AppBar(
            title=ft.Text("Settings", weight=ft.FontWeight.BOLD, color=ft.Colors.BLACK),
            bgcolor=self.bg_color,
            leading=ft.IconButton(
                icon=ft.Icons.ARROW_BACK,
                icon_color=ft.Colors.BLACK,
                on_click=lambda e: self.go_back()
            )
        )
    
    def create_section(self, title: str, items: list):
        """Create a settings section"""
        return ft.Container(
            content=ft.Column(
                [
                    ft.Container(
                        content=ft.Text(
                            title,
                            size=18,
                            weight=ft.FontWeight.BOLD,
                            color=self.text_color
                        ),
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
                ft.Container(
                    content=ft.Text(
                        "Permissions are managed by Android. Tap 'Open App Settings' to change them.",
                        size=12,
                        color=self.text_secondary
                    ),
                    margin=ft.margin.only(bottom=15)
                ),
                permissions_list,
                ft.Container(height=15),
                ft.ElevatedButton(
                    "Request Permissions",
                    icon=ft.Icons.SECURITY,
                    on_click=self.request_permissions,
                    style=ft.ButtonStyle(
                        color=ft.Colors.WHITE,
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
        try:
            self.dark_mode = e.control.value
            self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
            self.page.update()
            print(f"[SETTINGS] Dark mode {'on' if self.dark_mode else 'off'} kiya")
        except Exception as ex:
            print(f"[SETTINGS] Dark mode toggle mein error: {ex}")
    
    def toggle_notifications(self, e):
        """Toggle notifications"""
        try:
            self.notifications_enabled = e.control.value
            self.page.update()
            print(f"[SETTINGS] Notifications {'on' if self.notifications_enabled else 'off'} kiye")
        except Exception as ex:
            print(f"[SETTINGS] Notifications toggle mein error: {ex}")
    
    def toggle_sound(self, e):
        """Toggle sound"""
        try:
            sound_enabled = e.control.value
            self.page.update()
            print(f"[SETTINGS] Sound {'on' if sound_enabled else 'off'} kiya")
            # TODO: Actual sound implementation
        except Exception as ex:
            print(f"[SETTINGS] Sound toggle mein error: {ex}")
    
    def toggle_vibration(self, e):
        """Toggle vibration"""
        try:
            vibration_enabled = e.control.value
            self.page.update()
            print(f"[SETTINGS] Vibration {'on' if vibration_enabled else 'off'} kiya")
            # TODO: Actual vibration implementation
        except Exception as ex:
            print(f"[SETTINGS] Vibration toggle mein error: {ex}")
    
    def toggle_online_status(self, e):
        """Toggle online status"""
        try:
            self.online_status = e.control.value
            self.page.update()
            print(f"[SETTINGS] Online status {'visible' if self.online_status else 'hidden'} kiya")
        except Exception as ex:
            print(f"[SETTINGS] Online status toggle mein error: {ex}")
    
    def show_phone_settings(self):
        """Show phone number settings dialog"""
        # Get current phone from user data
        current_phone = self.current_user.get("phone", "") if self.current_user else ""
        
        # Country codes
        country_codes = [
            ("+91", "🇮🇳 India"),
            ("+1", "🇺🇸 USA"),
            ("+44", "🇬🇧 UK"),
            ("+86", "🇨🇳 China"),
            ("+81", "🇯🇵 Japan"),
            ("+49", "🇩🇪 Germany"),
            ("+33", "🇫🇷 France"),
            ("+7", "🇷🇺 Russia"),
            ("+971", "🇦🇪 UAE"),
            ("+65", "🇸🇬 Singapore"),
        ]
        
        # Country dropdown
        country_dropdown = ft.Dropdown(
            label="Country Code",
            value="+91",
            options=[ft.dropdown.Option(key=code, text=f"{label} ({code})") for code, label in country_codes],
            width=150,
        )
        
        # Phone number input
        phone_input = ft.TextField(
            label="Phone Number",
            hint_text="Enter phone number",
            keyboard_type=ft.KeyboardType.PHONE,
            prefix_icon=icons.PHONE,
            value=current_phone.replace("+91", "").strip() if current_phone else "",
            expand=True,
            max_length=15,
        )
        
        # Verification code input (hidden initially)
        verification_input = ft.TextField(
            label="Verification Code",
            hint_text="Enter 6-digit code",
            keyboard_type=ft.KeyboardType.NUMBER,
            prefix_icon=icons.LOCK,
            max_length=6,
            visible=False,
        )
        
        # Status text
        status_text = ft.Text("", size=12, color=ft.Colors.GREY)
        
        # Verification step indicator
        step_indicator = ft.Row([
            ft.Container(
                content=ft.Text("1", color=ft.Colors.WHITE, size=12),
                bgcolor=self.primary_color,
                width=24,
                height=24,
                border_radius=12,
                alignment=ft.alignment.center
            ),
            ft.Container(width=30, height=2, bgcolor=ft.Colors.GREY_300),
            ft.Container(
                content=ft.Text("2", color=ft.Colors.WHITE, size=12),
                bgcolor=ft.Colors.GREY_400,
                width=24,
                height=24,
                border_radius=12,
                alignment=ft.alignment.center
            ),
        ], alignment=ft.MainAxisAlignment.CENTER)
        
        def send_verification(e):
            phone = phone_input.value.strip()
            if not phone or len(phone) < 10:
                status_text.value = "Please enter a valid phone number"
                status_text.color = ft.Colors.RED
                self.page.update()
                return
            
            full_phone = f"{country_dropdown.value}{phone}"
            status_text.value = f"Verification code sent to {full_phone}"
            status_text.color = ft.Colors.GREEN
            verification_input.visible = True
            
            # Update step indicator
            step_indicator.controls[2].bgcolor = self.primary_color
            
            self.page.update()
        
        def verify_code(e):
            code = verification_input.value.strip()
            if not code or len(code) != 6:
                status_text.value = "Please enter 6-digit code"
                status_text.color = ft.Colors.RED
                self.page.update()
                return
            
            # Simulate verification success
            full_phone = f"{country_dropdown.value}{phone_input.value.strip()}"
            status_text.value = f"✅ Phone verified: {full_phone}"
            status_text.color = ft.Colors.GREEN
            
            # Update user data (would call API in production)
            if self.current_user:
                self.current_user["phone"] = full_phone
            
            # Show success snackbar
            snack = ft.SnackBar(
                content=ft.Text(f"Phone number updated to {full_phone}"),
                bgcolor=ft.Colors.GREEN
            )
            self.page.overlay.append(snack)
            snack.open = True
            
            # Close dialog after delay
            self.page.close(phone_dialog)
            self.page.update()
        
        phone_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(icons.PHONE, color=self.primary_color),
                ft.Text("Phone Number", weight=ft.FontWeight.BOLD)
            ], spacing=10),
            content=ft.Container(
                content=ft.Column([
                    step_indicator,
                    ft.Container(height=15),
                    ft.Text("Enter your phone number", size=14, color=self.text_secondary),
                    ft.Row([country_dropdown, phone_input], spacing=10),
                    verification_input,
                    status_text,
                    ft.Container(height=10),
                    ft.Text("We'll send a verification code via SMS", size=12, color=ft.Colors.GREY),
                ], spacing=10, tight=True),
                width=350,
                padding=10
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(phone_dialog)),
                ft.ElevatedButton(
                    "Send Code",
                    on_click=send_verification,
                    bgcolor=self.primary_color,
                    color=ft.Colors.WHITE
                ),
                ft.ElevatedButton(
                    "Verify",
                    on_click=verify_code,
                    bgcolor=ft.Colors.GREEN,
                    color=ft.Colors.WHITE,
                    visible=True
                ),
            ]
        )
        
        self.page.open(phone_dialog)
    
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
        
        def on_size_change(e):
            selected = e.control.value
            # Save preference (would store in settings)
            snack = ft.SnackBar(content=ft.Text(f"Font size set to {selected}"), duration=1500)
            self.page.overlay.append(snack)
            snack.open = True
            self.page.close(font_dialog)
            self.page.update()
        
        font_dialog = ft.AlertDialog(
            title=ft.Text("Font Size"),
            content=ft.Container(
                content=ft.RadioGroup(
                    value=current_size,
                    content=ft.Column([
                        ft.Radio(value="Small", label="Small"),
                        ft.Radio(value="Medium", label="Medium"),
                        ft.Radio(value="Large", label="Large"),
                    ]),
                    on_change=on_size_change
                ),
                width=200
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(font_dialog))
            ]
        )
        
        self.page.open(font_dialog)
    
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
            "Arabic", "Hindi", "Chinese", "Japanese", "Portuguese",
            "Italian", "Korean", "Indonesian", "Turkish", "Vietnamese",
            "Thai", "Dutch", "Polish", "Ukrainian"
        ]
        
        def select_language(lang):
            print(f"Selected language: {lang}")
            self.page.close(dialog)
            
            snack = ft.SnackBar(content=ft.Text(f"Language changed to {lang}"), bgcolor=colors.GREEN_600)
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()

        dialog = ft.AlertDialog(
            title=ft.Text("Language"),
            content=ft.Container(
                content=ft.RadioGroup(
                    content=ft.Column(
                        [
                            ft.ListTile(
                                title=ft.Text(lang),
                                on_click=lambda e, l=lang: select_language(l),
                                leading=ft.Radio(value=lang)
                            ) for lang in languages
                        ],
                        scroll=ft.ScrollMode.AUTO,
                    ),
                    value="English",
                    on_change=lambda e: select_language(e.control.value)
                ),
                height=400,
                width=300
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog))
            ]
        )
        self.page.open(dialog)

    def show_storage_usage(self, e):
        """Show storage usage"""
        dialog = ft.AlertDialog(
            title=ft.Text("Storage Usage"),
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Row([
                            ft.Text("Cache"),
                            ft.Container(expand=True),
                            ft.Text("45 MB", weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE)
                        ]),
                        ft.ProgressBar(value=0.25, color=ft.Colors.BLUE, bgcolor=ft.Colors.BLUE_50),
                        
                        ft.Row([
                            ft.Text("Media"),
                            ft.Container(expand=True),
                            ft.Text("120 MB", weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN)
                        ]),
                        ft.ProgressBar(value=0.6, color=ft.Colors.GREEN, bgcolor=ft.Colors.GREEN_50),
                        
                        ft.Row([
                            ft.Text("Documents"),
                            ft.Container(expand=True),
                            ft.Text("15 MB", weight=ft.FontWeight.BOLD, color=ft.Colors.ORANGE)
                        ]),
                        ft.ProgressBar(value=0.1, color=ft.Colors.ORANGE, bgcolor=ft.Colors.ORANGE_50),
                        
                        ft.Divider(),
                        ft.Row([
                            ft.Text("Total Used", size=16, weight=ft.FontWeight.BOLD),
                            ft.Container(expand=True),
                            ft.Text("180 MB", size=16, weight=ft.FontWeight.BOLD)
                        ]),
                        ft.Text("Free Space: 25.4 GB", size=12, color=ft.Colors.GREY)
                    ],
                    tight=True,
                    spacing=12,
                ),
                width=350,
                padding=10
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))
            ]
        )
        self.page.open(dialog)
    
    def clear_cache(self, e):
        """Clear app cache"""
        def perform_clear(e):
            self.page.close(dialog)
            
            # Simulate clearing
            snack = ft.SnackBar(content=ft.Text("🧹 Clearing cache..."), duration=1000)
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()
            
            import threading
            def finish_clear():
                success_snack = ft.SnackBar(
                    content=ft.Text("✅ Cache cleared! Released 45 MB."),
                    bgcolor=ft.Colors.GREEN
                )
                self.page.overlay.append(success_snack)
                success_snack.open = True
                self.page.update()
                
            threading.Timer(1.0, finish_clear).start()

        dialog = ft.AlertDialog(
            title=ft.Text("Clear Cache"),
            content=ft.Column([
                ft.Icon(ft.Icons.DELETE_SWEEP, size=64, color=ft.Colors.RED),
                ft.Text(
                    "Are you sure you want to clear the cache?\nThis will free up space but may slow down the app initially.",
                    text_align=ft.TextAlign.CENTER
                )
            ], tight=True, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton(
                    "Clear (45 MB)", 
                    on_click=perform_clear,
                    bgcolor=ft.Colors.RED,
                    color=ft.Colors.WHITE
                )
            ]
        )
        self.page.open(dialog)
        

    
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

    def toggle_sound(self, e):
        """Toggle sound for notifications"""
        enabled = e.control.value
        print(f"Sound enabled: {enabled}")
        
    def toggle_vibration(self, e):
        """Toggle vibration for notifications"""
        enabled = e.control.value
        print(f"Vibration enabled: {enabled}")

    def toggle_read_receipts(self, e):
        """Toggle read receipts"""
        enabled = e.control.value
        print(f"Read receipts enabled: {enabled}")
        
    def show_chat_background_picker(self, e):
        """Show chat background picker"""
        # Solid colors for now
        colors = [
            "#FDFBFB", "#E3F2FD", "#F3E5F5", "#E8F5E9", 
            "#FFFDE7", "#FBE9E7", "#ECEFF1", "#212121"
        ]
        
        def pick_color(color):
            self.page.bgcolor = color
            for view in self.page.views:
                view.bgcolor = color
            self.page.update()
            
            snack = ft.SnackBar(content=ft.Text("Background updated!"))
            self.page.overlay.append(snack)
            snack.open = True
            self.page.close(dialog)
            self.page.update()
            
        dialog = ft.AlertDialog(
            title=ft.Text("Chat Background"),
            content=ft.Container(
                content=ft.Row([
                    ft.Container(
                        width=50, height=50, bgcolor=c, 
                        border_radius=25,
                        on_click=lambda e, c=c: pick_color(c),
                        border=ft.border.all(1, ft.Colors.GREY_300)
                    ) for c in colors
                ], wrap=True, spacing=10, run_spacing=10),
                width=300,
                height=150
            ),
            actions=[ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog))]
        )
        self.page.open(dialog)

    def show_blocked_users(self, e):
        """Show blocked users"""
        blocked_users = [] # fetch from API ideally
        
        main_content = ft.Column()
        if not blocked_users:
            main_content.controls.append(
                ft.Container(
                    content=ft.Column([
                        ft.Icon(icons.BLOCK, size=64, color=ft.Colors.GREY_400),
                        ft.Text("No blocked users", color=ft.Colors.GREY_500)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    alignment=ft.alignment.center,
                    padding=20
                )
            )
            
        dialog = ft.AlertDialog(
            title=ft.Text("Blocked Users"),
            content=ft.Container(content=main_content, width=300, height=200),
            actions=[ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))]
        )
        self.page.open(dialog)

    def show_2fa_settings(self, e):
        """Show 2FA settings"""
        def enable_2fa(e):
            snack = ft.SnackBar(content=ft.Text("Two-Step Verification Enabled! (Simulation)"))
            self.page.overlay.append(snack)
            snack.open = True
            self.page.close(dialog)
            self.page.update()
            
        dialog = ft.AlertDialog(
            title=ft.Text("Two-Step Verification"),
            content=ft.Column([
                ft.Icon(icons.SECURITY, size=64, color=self.primary_color),
                ft.Text("Require a PIN when registering your phone number again on Zaply.", text_align=ft.TextAlign.CENTER),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20, tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton("Enable", on_click=enable_2fa, bgcolor=self.primary_color, color=ft.Colors.WHITE)
            ]
        )
        self.page.open(dialog)
        
    def show_privacy_settings(self, e):
        """Show privacy settings"""
        dialog = ft.AlertDialog(
            title=ft.Text("Privacy Settings"),
            content=ft.Column([
                self.switch_item("Last Seen & Online", "Everybody", icons.VISIBILITY, True, lambda e: None),
                self.switch_item("Profile Photo", "Everybody", icons.ACCOUNT_CIRCLE, True, lambda e: None),
                self.switch_item("Forwarded Messages", "Everybody", icons.FORWARD, True, lambda e: None),
                self.switch_item("Calls", "Everybody", icons.CALL, True, lambda e: None),
            ], tight=True, spacing=0),
            actions=[ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))]
        )
        self.page.open(dialog)
        
    def backup_chats(self, e):
        """Backup chats"""
        def perform_backup(e):
            btn.content = ft.ProgressRing(width=20, height=20, stroke_width=2, color=ft.Colors.WHITE)
            btn.disabled = True
            self.page.update()
            
            # Simulate backup with timer
            def finish_backup():
                snack = ft.SnackBar(content=ft.Text("Backup created successfully!"))
                self.page.overlay.append(snack)
                snack.open = True
                self.page.close(dialog)
                self.page.update()
            
            # Use small delay to simulate work
            import threading
            threading.Timer(1.5, finish_backup).start()
            
        btn = ft.ElevatedButton("Back Up Now", on_click=perform_backup, bgcolor=self.primary_color, color=ft.Colors.WHITE)
        
        dialog = ft.AlertDialog(
            title=ft.Text("Chat Backup"),
            content=ft.Column([
                ft.Text("Last Backup: Never"),
                ft.Text("Back up your messages and media to Zaply Cloud.", size=12, color=ft.Colors.GREY),
            ], tight=True, spacing=10),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                btn
            ]
        )
        self.page.open(dialog)
        
    def export_chats(self, e):
        """Export chats"""
        snack = ft.SnackBar(content=ft.Text("Chats exported to Downloads folder (Simulation)"))
        self.page.overlay.append(snack)
        snack.open = True
        self.page.update()
        
    def scan_qr_code(self, e):
        """Scan QR Code"""
        dialog = ft.AlertDialog(
            title=ft.Text("Link Device"),
            content=ft.Column([
                ft.Container(
                    content=ft.Icon(icons.QR_CODE_SCANNER, size=150, color=ft.Colors.BLACK),
                    alignment=ft.alignment.center,
                    height=200, width=200,
                    border=ft.border.all(2, self.primary_color),
                    border_radius=10
                ),
                ft.Text("Point your camera at the QR code", text_align=ft.TextAlign.CENTER),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True, spacing=20),
            actions=[ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))]
        )
        self.page.open(dialog)
        
    def show_help_center(self, e):
        """Show help center"""
        dialog = ft.AlertDialog(
            title=ft.Text("Help Center"),
            content=ft.Column([
                ft.ListTile(leading=ft.Icon(icons.QUESTION_ANSWER), title=ft.Text("Ask a Question")),
                ft.ListTile(leading=ft.Icon(icons.CHAT), title=ft.Text("Zaply FAQ")),
                ft.ListTile(leading=ft.Icon(icons.POLICY), title=ft.Text("Privacy Policy")),
            ], tight=True, spacing=0),
            actions=[ft.TextButton("Close", on_click=lambda e: self.page.close(dialog))]
        )
        self.page.open(dialog)
        
    def report_problem(self, e):
        """Report a problem"""
        dialog = ft.AlertDialog(
            title=ft.Text("Report a Problem"),
            content=ft.TextField(
                label="Describe your issue",
                multiline=True,
                min_lines=3,
                max_lines=5
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.page.close(dialog)),
                ft.ElevatedButton("Submit", on_click=lambda e: self.page.close(dialog))
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
                        color=ft.Colors.WHITE,
                        bgcolor=ft.Colors.RED_500
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

